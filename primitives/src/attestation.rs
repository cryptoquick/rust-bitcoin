// SPDX-License-Identifier: CC0-1.0

//! An attestation.
//!
//! This module contains the [`Attestation`] struct and related methods to operate on it

use core::fmt;
use core::ops::Index;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hex::DisplayHex;
use internals::compact_size;
use internals::wrap_debug::WrapDebug;

use crate::prelude::Vec;

/// The Attestation is the data used to unlock bitcoin since the [QuBit upgrade].
///
/// Can be logically seen as an array of bytestrings, i.e. `Vec<Vec<u8>>`, and it is serialized on the wire
/// in that format. You can convert between this type and `Vec<Vec<u8>>` by using [`Attestation::from_slice`]
/// and [`Attestation::to_vec`].
///
/// For serialization and deserialization performance it is stored internally as a single `Vec`,
/// saving some allocations.
///
/// [SegWit upgrade]: <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Attestation {
    /// Contains the attestation `Vec<Vec<u8>>` serialization.
    ///
    /// Does not include the initial varint indicating the number of elements. Each element however,
    /// does include a varint indicating the element length. The number of elements is stored in
    /// `attestation_elements`.
    ///
    /// Concatenated onto the end of `content` is the index area. This is a `4 * attestation_elements`
    /// bytes area which stores the index of the start of each attestation item.
    content: Vec<u8>,

    /// The number of elements in the attestation.
    ///
    /// Stored separately (instead of as a compact size encoding in the initial part of content) so
    /// that methods like [`Attestation::push`] don't have to shift the entire array.
    attestation_elements: usize,

    /// This is the valid index pointing to the beginning of the index area.
    ///
    /// Said another way, this is the total length of all attestation elements serialized (without the
    /// element count but with their sizes serialized as compact size).
    indices_start: usize,
}

impl Attestation {
    /// Constructs a new empty [`Attestation`].
    #[inline]
    pub const fn new() -> Self {
        Attestation { content: Vec::new(), attestation_elements: 0, indices_start: 0 }
    }

    /// Constructs a new [`Attestation`] from inner parts.
    ///
    /// This function leaks implementation details of the `Attestation`, as such it is unstable and
    /// should not be relied upon (it is primarily provided for use in `rust-bitcoin`).
    ///
    /// UNSTABLE: This function may change, break, or disappear in any release.
    #[inline]
    #[doc(hidden)]
    #[allow(non_snake_case)] // Because of `__unstable`.
    pub fn from_parts__unstable(
        content: Vec<u8>,
        attestation_elements: usize,
        indices_start: usize,
    ) -> Self {
        Attestation { content, attestation_elements, indices_start }
    }

    /// Constructs a new [`Attestation`] object from a slice of bytes slices where each slice is an attestation item.
    pub fn from_slice<T: AsRef<[u8]>>(slice: &[T]) -> Self {
        let attestation_elements = slice.len();
        let index_size = attestation_elements * 4;
        let content_size = slice
            .iter()
            .map(|elem| elem.as_ref().len() + compact_size::encoded_size(elem.as_ref().len()))
            .sum();

        let mut content = alloc::vec![0u8; content_size + index_size];
        let mut cursor = 0usize;
        for (i, elem) in slice.iter().enumerate() {
            encode_cursor(&mut content, content_size, i, cursor);
            let encoded = compact_size::encode(elem.as_ref().len());
            let encoded_size = encoded.as_slice().len();
            content[cursor..cursor + encoded_size].copy_from_slice(encoded.as_slice());
            cursor += encoded_size;
            content[cursor..cursor + elem.as_ref().len()].copy_from_slice(elem.as_ref());
            cursor += elem.as_ref().len();
        }

        Attestation { attestation_elements, content, indices_start: content_size }
    }

    /// Convenience method to create an array of byte-arrays from this attestation.
    #[inline]
    pub fn to_vec(&self) -> Vec<Vec<u8>> {
        self.iter().map(<[u8]>::to_vec).collect()
    }

    /// Returns `true` if the attestation contains no element.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.attestation_elements == 0
    }

    /// Returns a struct implementing [`Iterator`].
    #[must_use = "iterators are lazy and do nothing unless consumed"]
    #[inline]
    pub fn iter(&self) -> Iter {
        Iter { inner: self.content.as_slice(), indices_start: self.indices_start, current_index: 0 }
    }

    /// Returns the number of elements this attestation holds.
    #[inline]
    pub fn len(&self) -> usize {
        self.attestation_elements
    }

    /// Returns the number of bytes this attestation contributes to a transactions total size.
    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        size += compact_size::encoded_size(self.attestation_elements);
        size += self
            .iter()
            .map(|attestation_element| {
                let len = attestation_element.len();
                compact_size::encoded_size(len) + len
            })
            .sum::<usize>();

        size
    }

    /// Clear the attestation.
    #[inline]
    pub fn clear(&mut self) {
        self.content.clear();
        self.attestation_elements = 0;
        self.indices_start = 0;
    }

    /// Push a new element on the attestation, requires an allocation.
    #[inline]
    pub fn push<T: AsRef<[u8]>>(&mut self, new_element: T) {
        self.push_slice(new_element.as_ref());
    }

    /// Push a new element slice onto the attestation stack.
    fn push_slice(&mut self, new_element: &[u8]) {
        self.attestation_elements += 1;
        let previous_content_end = self.indices_start;
        let encoded = compact_size::encode(new_element.len());
        let encoded_size = encoded.as_slice().len();
        let current_content_len = self.content.len();
        let new_item_total_len = encoded_size + new_element.len();
        self.content.resize(current_content_len + new_item_total_len + 4, 0);

        self.content[previous_content_end..].rotate_right(new_item_total_len);
        self.indices_start += new_item_total_len;
        encode_cursor(
            &mut self.content,
            self.indices_start,
            self.attestation_elements - 1,
            previous_content_end,
        );

        let end_compact_size = previous_content_end + encoded_size;
        self.content[previous_content_end..end_compact_size].copy_from_slice(encoded.as_slice());
        self.content[end_compact_size..end_compact_size + new_element.len()]
            .copy_from_slice(new_element);
    }

    /// Returns the last element in the attestation, if any.
    #[inline]
    pub fn last(&self) -> Option<&[u8]> {
        self.get_back(0)
    }

    /// Retrieves an element from the end of the attestation by its reverse index.
    ///
    /// `index` is 0-based from the end, where 0 is the last element, 1 is the second-to-last, etc.
    ///
    /// Returns `None` if the requested index is beyond the attestation's elements.
    ///
    /// # Examples
    /// ```
    /// use bitcoin_primitives::attestation::Attestation;
    ///
    /// let mut attestation = Attestation::new();
    /// attestation.push(b"A");
    /// attestation.push(b"B");
    /// attestation.push(b"C");
    /// attestation.push(b"D");
    ///
    /// assert_eq!(attestation.get_back(0), Some(b"D".as_slice()));
    /// assert_eq!(attestation.get_back(1), Some(b"C".as_slice()));
    /// assert_eq!(attestation.get_back(2), Some(b"B".as_slice()));
    /// assert_eq!(attestation.get_back(3), Some(b"A".as_slice()));
    /// assert_eq!(attestation.get_back(4), None);
    /// ```
    pub fn get_back(&self, index: usize) -> Option<&[u8]> {
        if self.attestation_elements <= index {
            None
        } else {
            self.get(self.attestation_elements - 1 - index)
        }
    }

    /// Returns a specific element from the attestation by its index, if any.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        let pos = decode_cursor(&self.content, self.indices_start, index)?;

        let mut slice = &self.content[pos..]; // Start of element.
        let element_len = compact_size::decode_unchecked(&mut slice);
        // Compact size should always fit into a u32 because of `MAX_SIZE` in Core.
        // ref: https://github.com/rust-bitcoin/rust-bitcoin/issues/3264
        let end = element_len as usize;
        Some(&slice[..end])
    }
}

/// Correctness Requirements: value must always fit within u32
// This is duplicated in `bitcoin::blockdata::witness`, if you change it please do so over there also.
#[inline]
fn encode_cursor(bytes: &mut [u8], start_of_indices: usize, index: usize, value: usize) {
    let start = start_of_indices + index * 4;
    let end = start + 4;
    bytes[start..end]
        .copy_from_slice(&u32::to_ne_bytes(value.try_into().expect("larger than u32")));
}

// This is duplicated in `bitcoin::blockdata::witness`, if you change them do so over there also.
#[inline]
fn decode_cursor(bytes: &[u8], start_of_indices: usize, index: usize) -> Option<usize> {
    let start = start_of_indices + index * 4;
    let end = start + 4;
    if end > bytes.len() {
        None
    } else {
        Some(u32::from_ne_bytes(bytes[start..end].try_into().expect("is u32 size")) as usize)
    }
}

/// Debug implementation that displays the attestation as a structured output containing:
/// - Number of attestation elements
/// - Total bytes across all elements
/// - List of hex-encoded attestation elements
#[allow(clippy::missing_fields_in_debug)] // We don't want to show `indices_start`.
impl fmt::Debug for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_bytes: usize = self.iter().map(<[u8]>::len).sum();

        f.debug_struct("Attestation")
            .field("num_elements", &self.attestation_elements)
            .field("total_bytes", &total_bytes)
            .field(
                "elements",
                &WrapDebug(|f| {
                    f.debug_list().entries(self.iter().map(DisplayHex::as_hex)).finish()
                }),
            )
            .finish()
    }
}

/// An iterator returning individual attestation elements.
pub struct Iter<'a> {
    inner: &'a [u8],
    indices_start: usize,
    current_index: usize,
}

impl Index<usize> for Attestation {
    type Output = [u8];

    #[track_caller]
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("out of bounds")
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let index = decode_cursor(self.inner, self.indices_start, self.current_index)?;
        let mut slice = &self.inner[index..]; // Start of element.
        let element_len = compact_size::decode_unchecked(&mut slice);
        // Compact size should always fit into a u32 because of `MAX_SIZE` in Core.
        // ref: https://github.com/rust-bitcoin/rust-bitcoin/issues/3264
        let end = element_len as usize;
        self.current_index += 1;
        Some(&slice[..end])
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let total_count = (self.inner.len() - self.indices_start) / 4;
        let remaining = total_count - self.current_index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl<'a> IntoIterator for &'a Attestation {
    type IntoIter = Iter<'a>;
    type Item = &'a [u8];

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// Serde keep backward compatibility with old Vec<Vec<u8>> format
#[cfg(feature = "serde")]
impl serde::Serialize for Attestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        let human_readable = serializer.is_human_readable();
        let mut seq = serializer.serialize_seq(Some(self.attestation_elements))?;

        // Note that the `Iter` strips the varints out when iterating.
        for elem in self {
            if human_readable {
                seq.serialize_element(&internals::serde::SerializeBytesAsHex(elem))?;
            } else {
                seq.serialize_element(&elem)?;
            }
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Attestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::prelude::String;

        struct Visitor; // Human-readable visitor.
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Attestation;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "a sequence of hex arrays")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                use hex::{FromHex, HexToBytesError as E};
                use serde::de::{self, Unexpected};

                let mut ret = match a.size_hint() {
                    Some(len) => Vec::with_capacity(len),
                    None => Vec::new(),
                };

                while let Some(elem) = a.next_element::<String>()? {
                    let vec = Vec::<u8>::from_hex(&elem).map_err(|e| match e {
                        E::InvalidChar(ref e) => {
                            match core::char::from_u32(e.invalid_char().into()) {
                                Some(c) => de::Error::invalid_value(
                                    Unexpected::Char(c),
                                    &"a valid hex character",
                                ),
                                None => de::Error::invalid_value(
                                    Unexpected::Unsigned(e.invalid_char().into()),
                                    &"a valid hex character",
                                ),
                            }
                        }
                        E::OddLengthString(ref e) => {
                            de::Error::invalid_length(e.length(), &"an even length string")
                        }
                    })?;
                    ret.push(vec);
                }
                Ok(Attestation::from_slice(&ret))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_seq(Visitor)
        } else {
            let vec: Vec<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
            Ok(Attestation::from_slice(&vec))
        }
    }
}

impl From<Vec<Vec<u8>>> for Attestation {
    #[inline]
    fn from(vec: Vec<Vec<u8>>) -> Self {
        Attestation::from_slice(&vec)
    }
}

impl From<&[&[u8]]> for Attestation {
    #[inline]
    fn from(slice: &[&[u8]]) -> Self {
        Attestation::from_slice(slice)
    }
}

impl From<&[Vec<u8>]> for Attestation {
    #[inline]
    fn from(slice: &[Vec<u8>]) -> Self {
        Attestation::from_slice(slice)
    }
}

impl From<Vec<&[u8]>> for Attestation {
    #[inline]
    fn from(vec: Vec<&[u8]>) -> Self {
        Attestation::from_slice(&vec)
    }
}

impl Default for Attestation {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Attestation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = Vec::<Vec<u8>>::arbitrary(u)?;
        Ok(Attestation::from_slice(&arbitrary_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Appends all the indices onto the end of a list of elements.
    fn append_u32_vec(elements: &[u8], indices: &[u32]) -> Vec<u8> {
        let mut v = elements.to_vec();
        for &num in indices {
            v.extend_from_slice(&num.to_ne_bytes());
        }
        v
    }

    // An attestation with a single element that is empty (zero length).
    fn single_empty_element() -> Attestation {
        // The first is 0 serialized as a compact size integer.
        // The last four bytes represent start at index 0.
        let content = [0_u8; 5];

        Attestation { attestation_elements: 1, content: content.to_vec(), indices_start: 1 }
    }

    #[test]
    fn attestation_debug_can_display_empty_element() {
        let attestation = single_empty_element();
        println!("{:?}", attestation);
    }

    #[test]
    fn attestation_single_empty_element() {
        let mut got = Attestation::new();
        got.push([]);
        let want = single_empty_element();
        assert_eq!(got, want);
    }

    #[test]
    fn push() {
        // Sanity check default.
        let mut attestation = Attestation::default();
        assert!(attestation.is_empty());
        assert_eq!(attestation.last(), None);
        assert_eq!(attestation.get_back(1), None);

        assert_eq!(attestation.get(0), None);
        assert_eq!(attestation.get(1), None);
        assert_eq!(attestation.get(2), None);
        assert_eq!(attestation.get(3), None);

        // Push a single byte element onto the attestation stack.
        let push = [11_u8];
        attestation.push(push);
        assert!(!attestation.is_empty());

        let elements = [1u8, 11];
        let expected = Attestation {
            attestation_elements: 1,
            content: append_u32_vec(&elements, &[0]), // Start at index 0.
            indices_start: elements.len(),
        };
        assert_eq!(attestation, expected);

        let element_0 = push.as_slice();
        assert_eq!(element_0, &attestation[0]);

        assert_eq!(attestation.get_back(1), None);
        assert_eq!(attestation.last(), Some(element_0));

        assert_eq!(attestation.get(0), Some(element_0));
        assert_eq!(attestation.get(1), None);
        assert_eq!(attestation.get(2), None);
        assert_eq!(attestation.get(3), None);

        // Now push 2 byte element onto the attestation stack.
        let push = [21u8, 22u8];
        attestation.push(push);

        let elements = [1u8, 11, 2, 21, 22];
        let expected = Attestation {
            attestation_elements: 2,
            content: append_u32_vec(&elements, &[0, 2]),
            indices_start: elements.len(),
        };
        assert_eq!(attestation, expected);

        let element_1 = push.as_slice();
        assert_eq!(element_1, &attestation[1]);

        assert_eq!(attestation.get(0), Some(element_0));
        assert_eq!(attestation.get(1), Some(element_1));
        assert_eq!(attestation.get(2), None);
        assert_eq!(attestation.get(3), None);

        assert_eq!(attestation.get_back(1), Some(element_0));
        assert_eq!(attestation.last(), Some(element_1));

        // Now push another 2 byte element onto the attestation stack.
        let push = [31u8, 32u8];
        attestation.push(push);

        let elements = [1u8, 11, 2, 21, 22, 2, 31, 32];
        let expected = Attestation {
            attestation_elements: 3,
            content: append_u32_vec(&elements, &[0, 2, 5]),
            indices_start: elements.len(),
        };
        assert_eq!(attestation, expected);

        let element_2 = push.as_slice();
        assert_eq!(element_2, &attestation[2]);

        assert_eq!(attestation.get(0), Some(element_0));
        assert_eq!(attestation.get(1), Some(element_1));
        assert_eq!(attestation.get(2), Some(element_2));
        assert_eq!(attestation.get(3), None);

        assert_eq!(attestation.get_back(2), Some(element_0));
        assert_eq!(attestation.get_back(1), Some(element_1));
        assert_eq!(attestation.last(), Some(element_2));
    }

    #[test]
    fn exact_sized_iterator() {
        let arbitrary_element = [1_u8, 2, 3];
        let num_pushes = 5; // Somewhat arbitrary.

        let mut attestation = Attestation::default();

        for i in 0..num_pushes {
            assert_eq!(attestation.iter().len(), i);
            attestation.push(arbitrary_element);
        }

        let mut iter = attestation.iter();
        for i in (0..=num_pushes).rev() {
            assert_eq!(iter.len(), i);
            iter.next();
        }
    }

    #[test]
    fn attestation_from_parts() {
        let elements = [1u8, 11, 2, 21, 22];
        let attestation_elements = 2;
        let content = append_u32_vec(&elements, &[0, 2]);
        let indices_start = elements.len();
        let attestation =
            Attestation::from_parts__unstable(content.clone(), attestation_elements, indices_start);
        assert_eq!(attestation.get(0).unwrap(), [11_u8]);
        assert_eq!(attestation.get(1).unwrap(), [21_u8, 22]);
        assert_eq!(attestation.size(), 6);
    }

    #[test]
    fn attestation_from_impl() {
        // Test From implementations with the same 2 elements
        let vec = vec![vec![11], vec![21, 22]];
        let slice_vec: &[Vec<u8>] = &vec;
        let slice_slice: &[&[u8]] = &[&[11u8], &[21, 22]];
        let vec_slice: Vec<&[u8]> = vec![&[11u8], &[21, 22]];

        let attestation_vec_vec = Attestation::from(vec.clone());
        let attestation_slice_vec = Attestation::from(slice_vec);
        let attestation_slice_slice = Attestation::from(slice_slice);
        let attestation_vec_slice = Attestation::from(vec_slice);

        let mut expected = Attestation::from_slice(&vec);
        assert_eq!(expected.len(), 2);
        assert_eq!(expected.to_vec(), vec);

        assert_eq!(attestation_vec_vec, expected);
        assert_eq!(attestation_slice_vec, expected);
        assert_eq!(attestation_slice_slice, expected);
        assert_eq!(attestation_vec_slice, expected);

        // Test clear method
        expected.clear();
        assert!(expected.is_empty());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_backward_compatibility() {
        let old_attestation_format = vec![vec![0u8], vec![2]];
        let new_attestation_format = Attestation::from_slice(&old_attestation_format);

        let old = bincode::serialize(&old_attestation_format).unwrap();
        let new = bincode::serialize(&new_attestation_format).unwrap();

        assert_eq!(old, new);
    }

    #[cfg(feature = "serde")]
    fn arbitrary_attestation() -> Attestation {
        let mut attestation = Attestation::default();

        attestation.push([0_u8]);
        attestation.push([1_u8; 32]);
        attestation.push([2_u8; 72]);

        attestation
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_roundtrips() {
        let original = arbitrary_attestation();
        let ser = bincode::serialize(&original).unwrap();
        let rinsed: Attestation = bincode::deserialize(&ser).unwrap();
        assert_eq!(rinsed, original);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_human_roundtrips() {
        let original = arbitrary_attestation();
        let ser = serde_json::to_string(&original).unwrap();
        let rinsed: Attestation = serde_json::from_str(&ser).unwrap();
        assert_eq!(rinsed, original);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_human() {
        let attestation = Attestation::from_slice(&[vec![0u8, 123, 75], vec![2u8, 6, 3, 7, 8]]);
        let json = serde_json::to_string(&attestation).unwrap();
        assert_eq!(json, r#"["007b4b","0206030708"]"#);
    }
}

// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Quantum Resistant Hash (P2QRH) keys and signatures.
//!
//! This module provides P2QRH signatures used in Bitcoin (implementing BIP-360).

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use io::Write;

use crate::prelude::Vec;
use crate::qubit::serialized_signature::{self, SerializedSignature};
use crate::qubit::SignatureAlgorithm;

/// A BIP-360 serialized P2QRH signature with the corresponding algorithm.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The underlying post-quantum signature data
    pub signature_data: Vec<u8>,
    /// The post-quantum algorithm used
    pub algorithm: SignatureAlgorithm,
}

impl Signature {
    /// Creates a new P2QRH signature
    pub fn new(algorithm: SignatureAlgorithm, signature_data: Vec<u8>) -> Self {
        Signature { algorithm, signature_data }
    }

    /// Deserializes the signature from a slice.
    pub fn from_slice(sl: &[u8]) -> Result<Self, SigFromSliceError> {
        if sl.is_empty() {
            return Err(SigFromSliceError::InvalidSignatureSize(0));
        }

        // First byte is the algorithm
        let algorithm =
            SignatureAlgorithm::from_u8(sl[0]).ok_or(SigFromSliceError::InvalidAlgorithm(sl[0]))?;

        // Rest of the bytes are the signature
        let signature_data = sl[1..].to_vec();

        Ok(Signature { algorithm, signature_data })
    }

    /// Serializes the signature.
    ///
    /// Note: this allocates on the heap, prefer [`serialize`](Self::serialize) if vec is not needed.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.signature_data.len() + 1);
        result.push(self.algorithm.to_u8());
        result.extend_from_slice(&self.signature_data);
        result
    }

    /// Serializes the signature to `writer`.
    pub fn serialize_to_writer<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        let sig = self.serialize();
        sig.write_to(writer)
    }

    /// Serializes the signature (without heap allocation).
    ///
    /// This returns a type with an API very similar to that of `Box<[u8]>`.
    /// You can get a slice from it using deref coercions or turn it into an iterator.
    pub fn serialize(&self) -> SerializedSignature {
        // Custom implementation of serialize for better performance and to avoid circular references
        let total_length = self.signature_data.len() + 1; // +1 for algorithm byte
        let mut data = [0; serialized_signature::MAX_LEN];

        // We need to ensure we don't exceed MAX_LEN
        let actual_length = core::cmp::min(total_length, serialized_signature::MAX_LEN);

        // Set the algorithm byte
        data[0] = self.algorithm.to_u8();

        // Copy the signature data up to the maximum available length
        let sig_bytes_to_copy = actual_length - 1; // Subtract 1 for the algorithm byte
        if sig_bytes_to_copy > 0 {
            let copy_len = core::cmp::min(sig_bytes_to_copy, self.signature_data.len());
            data[1..1 + copy_len].copy_from_slice(&self.signature_data[..copy_len]);
        }

        SerializedSignature::from_raw_parts(data, actual_length)
    }
}

/// An error constructing a [`qubit::Signature`] from a byte slice.
///
/// [`qubit::Signature`]: crate::crypto::qubit::Signature
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigFromSliceError {
    /// Invalid signature algorithm.
    InvalidAlgorithm(u8),
    /// Invalid Qubit signature size
    InvalidSignatureSize(usize),
}

impl From<Infallible> for SigFromSliceError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for SigFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SigFromSliceError::*;

        match *self {
            InvalidAlgorithm(algo) => write!(f, "invalid P2QRH algorithm: {}", algo),
            InvalidSignatureSize(sz) => write!(f, "invalid P2QRH signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigFromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Verifies a P2QRH signature
///
/// This is a placeholder implementation. In a real implementation, this would use
/// the appropriate post-quantum verification algorithm based on the signature's algorithm.
pub fn verify_signature(sig: &Signature, pubkey: &[u8], message: &[u8]) -> bool {
    match sig.algorithm {
        SignatureAlgorithm::Secp256k1 => {
            // Call the secp256k1 verification function
            // This is just a placeholder - actual implementation would verify the signature
            !sig.signature_data.is_empty() && !pubkey.is_empty() && !message.is_empty()
        }
        SignatureAlgorithm::Falcon => {
            // Call the appropriate Falcon verification function
            // This is just a placeholder - actual implementation would verify the signature
            !sig.signature_data.is_empty() && !pubkey.is_empty() && !message.is_empty()
        }
        SignatureAlgorithm::Dilithium => {
            // Call the appropriate Dilithium verification function
            // This is just a placeholder - actual implementation would verify the signature
            !sig.signature_data.is_empty() && !pubkey.is_empty() && !message.is_empty()
        }
        SignatureAlgorithm::Sphincs => {
            // Call the appropriate SPHINCS+ verification function
            // This is just a placeholder - actual implementation would verify the signature
            !sig.signature_data.is_empty() && !pubkey.is_empty() && !message.is_empty()
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let algorithm = match u.int_in_range(0..=3)? {
            0 => SignatureAlgorithm::Secp256k1,
            1 => SignatureAlgorithm::Falcon,
            2 => SignatureAlgorithm::Dilithium,
            3 => SignatureAlgorithm::Sphincs,
            _ => unreachable!(),
        };

        // Generate a random signature length (up to some reasonable limit)
        let sig_len = u.int_in_range(1..=100)?;
        let mut signature_data = Vec::with_capacity(sig_len);
        for _ in 0..sig_len {
            signature_data.push(u.arbitrary()?);
        }

        Ok(Signature { algorithm, signature_data })
    }
}

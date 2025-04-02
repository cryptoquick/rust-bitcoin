// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Qubit (P2QRH).
//!
//! This module provides support for P2QRH (Pay to Quantum Resistant Hash) as defined in BIP-360.

pub mod address;

// Import the PQC crate's types
pub use bitcoinpqc::{Algorithm as PqcAlgorithm, PqcError};
use hashes::{hash_newtype, sha256t, sha256t_tag};

use crate::consensus::Encodable;
// Re-export these so downstream only has to use one `qubit` module.
pub use crate::crypto::qubit::{SigFromSliceError, Signature};
use crate::prelude::Vec;
use crate::{Script, ScriptBuf};

// Qubit test vectors will state the hashes without any reversing
sha256t_tag! {
    pub struct QubitLeafTag = hash_str("QubitLeaf");
}

hash_newtype! {
    /// Qubit-tagged hash with tag \"QubitLeaf\".
    ///
    /// This is used for computing P2QRH script spend hash.
    pub struct QubitLeafHash(sha256t::Hash<QubitLeafTag>);
}

hashes::impl_hex_for_newtype!(QubitLeafHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(QubitLeafHash);

sha256t_tag! {
    pub struct QubitBranchTag = hash_str("QubitBranch");
}

hash_newtype! {
    /// Tagged hash used in Qubit trees.
    ///
    /// See BIP-360 for tagging rules.
    pub struct QubitNodeHash(sha256t::Hash<QubitBranchTag>);
}

hashes::impl_hex_for_newtype!(QubitNodeHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(QubitNodeHash);

sha256t_tag! {
    pub struct QubitTweakTag = hash_str("QubitTweak");
}

hash_newtype! {
    /// Qubit-tagged hash with tag \"QubitTweak\".
    ///
    /// This hash type is used while computing the tweaked quantum-resistant key.
    pub struct QubitTweakHash(sha256t::Hash<QubitTweakTag>);
}

hashes::impl_hex_for_newtype!(QubitTweakHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(QubitTweakHash);

impl From<QubitLeafHash> for QubitNodeHash {
    fn from(leaf: QubitLeafHash) -> QubitNodeHash {
        QubitNodeHash::from_byte_array(leaf.to_byte_array())
    }
}

// Re-use the LeafVersion from taproot for now
pub use crate::taproot::LeafVersion;

impl QubitLeafHash {
    /// Computes the leaf hash from components.
    pub fn from_script(script: &Script, ver: LeafVersion) -> QubitLeafHash {
        let mut eng = sha256t::Hash::<QubitLeafTag>::engine();
        ver.to_consensus().consensus_encode(&mut eng).expect("engines don't error");
        script.consensus_encode(&mut eng).expect("engines don't error");
        let inner = sha256t::Hash::<QubitLeafTag>::from_engine(eng);
        QubitLeafHash::from_byte_array(inner.to_byte_array())
    }
}

/// Enum representing the type of key/signature algorithm used.
/// This can be either standard Secp256k1 or a post-quantum algorithm from `bitcoinpqc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyAlgorithm {
    /// Standard Secp256k1
    Secp256k1,
    /// Post-quantum algorithm
    PostQuantum(PqcAlgorithm),
}

/// Errors related to KeyAlgorithm mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmError {
    /// The provided key type index is unknown.
    UnknownKeyType(u8),
    /// The provided algorithm identifier is unknown.
    UnknownAlgorithmId(u8),
    /// A PQC algorithm from bitcoinpqc has no defined mapping to a BIP-360 ID.
    UnsupportedPqcAlgorithm(PqcAlgorithm),
}

impl KeyAlgorithm {
    /// Get the algorithm from its key type index as defined in BIP-360.
    pub fn from_key_type(key_type: u8) -> Result<Self, AlgorithmError> {
        match key_type {
            0 => Ok(KeyAlgorithm::Secp256k1),
            // PLACEHOLDER MAPPINGS - To be corrected in next step
            1 => Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512)), // Falcon
            2 => Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44)),  // Dilithium
            3 => Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S)), // Sphincs
            _ => Err(AlgorithmError::UnknownKeyType(key_type)),
        }
    }

    /// Get the algorithm from its BIP-360 identifier value (0-3).
    pub fn from_u8(value: u8) -> Result<Self, AlgorithmError> {
        // In BIP-360, the identifier and key type are the same.
        Self::from_key_type(value).map_err(|_| AlgorithmError::UnknownAlgorithmId(value))
    }

    /// Get the BIP-360 identifier value for the algorithm (0-3).
    pub fn to_u8(self) -> Result<u8, AlgorithmError> {
        match self {
            KeyAlgorithm::Secp256k1 => Ok(0),
            // PLACEHOLDER MAPPINGS - To be corrected in next step
            KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512) => Ok(1),
            KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44) => Ok(2),
            KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S) => Ok(3),
            // Add other PQC algorithms if the bitcoinpqc crate supports more and they need mapping
            KeyAlgorithm::PostQuantum(unmapped) =>
                Err(AlgorithmError::UnsupportedPqcAlgorithm(unmapped)),
        }
    }

    /// Get the bit position in the key type bitmask for this algorithm (BIP-360).
    /// Panics if the algorithm cannot be mapped to a BIP-360 ID.
    pub fn bitmask_bit(self) -> u8 {
        match self.to_u8() {
            Ok(id) => 1 << id,
            Err(e) => panic!("Cannot get bitmask bit for unmappable algorithm: {}", e),
        }
    }

    /// Get the BIP-360 key type index for this algorithm (0-3).
    /// Panics if the algorithm cannot be mapped to a BIP-360 ID.
    pub fn key_type(self) -> u8 {
        match self.to_u8() {
            Ok(id) => id,
            Err(e) => panic!("Cannot get key type for unmappable algorithm: {}", e),
        }
    }
}

// Implement Display for AlgorithmError
use core::fmt;
impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AlgorithmError::UnknownKeyType(t) => write!(f, "unknown key type index: {}", t),
            AlgorithmError::UnknownAlgorithmId(id) =>
                write!(f, "unknown algorithm identifier: {}", id),
            AlgorithmError::UnsupportedPqcAlgorithm(algo) =>
                write!(f, "PQC algorithm {:?} has no BIP-360 mapping", algo),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AlgorithmError {}

/// P2QRH Key Type Bitmask (as defined in BIP-360)
///
/// This bitmask indicates which cryptographic algorithms are enabled.
/// Each bit corresponds to a specific algorithm:
/// - 0x01 - Key type 0 - secp256k1
/// - 0x02 - Key type 1 - FALCON-512
/// - 0x04 - Key type 2 - CRYSTALS-Dilithium Level I
/// - 0x08 - Key type 3 - SPHINCS+-128s
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyTypeBitmask(u8);

impl KeyTypeBitmask {
    /// Create a new bitmask with all specified algorithms enabled
    pub fn new(algorithms: &[KeyAlgorithm]) -> Self {
        // Changed to use KeyAlgorithm
        let mut bitmask = 0u8;
        for algo in algorithms {
            bitmask |= algo.bitmask_bit(); // Panics if algo is unmappable
        }
        KeyTypeBitmask(bitmask)
    }

    /// Check if a specific algorithm is enabled in this bitmask
    pub fn is_algorithm_enabled(&self, algorithm: KeyAlgorithm) -> bool {
        match algorithm {
            KeyAlgorithm::Secp256k1 => (self.0 & 0x01) != 0,
            KeyAlgorithm::PostQuantum(pqc_algo) => pqc_algo.contains(PqcAlgorithm::from(self.0)),
        }
    }

    /// Get the raw bitmask value
    pub fn as_u8(&self) -> u8 { self.0 }

    /// Create from a raw bitmask value
    pub fn from_u8(value: u8) -> Self { KeyTypeBitmask(value) }

    /// Get a list of algorithms enabled by this bitmask
    pub fn enabled_algorithms(&self) -> Vec<KeyAlgorithm> {
        // Changed return type
        let mut result = Vec::new();

        // Check each possible algorithm defined in KeyAlgorithm based on BIP-360 key types
        if let Ok(algo) = KeyAlgorithm::from_key_type(0) {
            // Secp256k1
            if self.is_algorithm_enabled(algo) {
                result.push(algo);
            }
        }
        if let Ok(algo) = KeyAlgorithm::from_key_type(1) {
            // Falcon
            if self.is_algorithm_enabled(algo) {
                result.push(algo);
            }
        }
        if let Ok(algo) = KeyAlgorithm::from_key_type(2) {
            // Dilithium
            if self.is_algorithm_enabled(algo) {
                result.push(algo);
            }
        }
        if let Ok(algo) = KeyAlgorithm::from_key_type(3) {
            // Sphincs
            if self.is_algorithm_enabled(algo) {
                result.push(algo);
            }
        }
        // Add checks for other algorithms if needed

        result
    }
}

/// Quantum Attestation Structure (as defined in BIP-360)
///
/// This structure represents a commitment to public keys and related data
/// for quantum-resistant signatures.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Attestation {
    /// The key type bitmask indicating which algorithms are used
    pub key_type_bitmask: KeyTypeBitmask,
    /// Vector of public keys for each enabled algorithm.
    /// For Secp256k1, use crate::PublicKey.
    /// For PQC, use bitcoinpqc::PublicKey.
    /// We store them as Vec<u8> for now for simplicity in this struct,
    /// but conversion will be needed.
    pub public_keys: Vec<(KeyAlgorithm, Vec<u8>)>, // Changed to use KeyAlgorithm
}

impl Attestation {
    /// Create a new attestation with the given key type bitmask and public keys
    pub fn new(
        key_type_bitmask: KeyTypeBitmask,
        public_keys: Vec<(KeyAlgorithm, Vec<u8>)>, // Changed to use KeyAlgorithm
    ) -> Self {
        Attestation { key_type_bitmask, public_keys }
    }

    /// Compute the hash commitment for this attestation
    pub fn compute_commitment(&self) -> [u8; 32] {
        // Sort public keys by algorithm BIP-360 ID (0-3)
        let mut sorted_keys = self.public_keys.clone();
        // This sort relies on KeyAlgorithm::to_u8() not returning Err for keys in the vec.
        // Consider adding checks or error handling during Attestation creation.
        sorted_keys.sort_by_key(|(algo, _)| algo.key_type()); // Sort by BIP-360 ID (0-3)

        // Concatenate all data and hash it
        let mut data = Vec::new();
        data.push(self.key_type_bitmask.as_u8());

        for (algo, pubkey) in sorted_keys {
            // This assumes algo has a valid BIP-360 ID. Consider error handling.
            data.push(algo.key_type()); // Use BIP-360 ID (0-3)
                                        // Add length as a varint
            let len = pubkey.len() as u64;
            // Simple varint encoding
            if len < 0xfd {
                data.push(len as u8);
            } else if len <= 0xffff {
                data.push(0xfd);
                data.extend_from_slice(&(len as u16).to_le_bytes());
            } else if len <= 0xffffffff {
                data.push(0xfe);
                data.extend_from_slice(&(len as u32).to_le_bytes());
            } else {
                data.push(0xff);
                data.extend_from_slice(&len.to_le_bytes());
            }
            data.extend_from_slice(&pubkey);
        }

        // Hash the concatenated data
        use hashes::sha256::Hash;

        let hash = Hash::hash(&data);
        hash.to_byte_array()
    }
}

/// A P2QRH scriptPubKey template
pub struct P2QRHTemplate {
    /// Hash commitment of the attestation
    pub hash_commitment: [u8; 32],
}

impl P2QRHTemplate {
    /// Create a new P2QRH template from an attestation
    pub fn new(attestation: &Attestation) -> Self {
        let hash_commitment = attestation.compute_commitment();
        P2QRHTemplate { hash_commitment }
    }

    /// Generate the scriptPubKey for this P2QRH template
    pub fn script_pubkey(&self) -> ScriptBuf {
        use crate::blockdata::opcodes::all::OP_PUSHNUM_3;
        use crate::blockdata::script::Builder;

        Builder::new().push_opcode(OP_PUSHNUM_3).push_slice(self.hash_commitment).into_script()
    }
}

#[cfg(test)]
mod tests {
    // Import PQC algo for tests explicitly if needed, or rely on KeyAlgorithm::PostQuantum(...)
    use bitcoinpqc::Algorithm as PqcAlgorithm;

    use super::*;

    #[test]
    fn test_key_algorithm_mapping() {
        // New test for KeyAlgorithm
        // Test conversion from key type to algorithm
        assert_eq!(KeyAlgorithm::from_key_type(0), Ok(KeyAlgorithm::Secp256k1));
        // Use correct constants now
        assert_eq!(
            KeyAlgorithm::from_key_type(1),
            Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512))
        );
        assert_eq!(
            KeyAlgorithm::from_key_type(2),
            Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44))
        );
        assert_eq!(
            KeyAlgorithm::from_key_type(3),
            Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S))
        );
        assert_eq!(KeyAlgorithm::from_key_type(4), Err(AlgorithmError::UnknownKeyType(4)));

        // Test conversion from u8 to algorithm
        assert_eq!(KeyAlgorithm::from_u8(0), Ok(KeyAlgorithm::Secp256k1));
        assert_eq!(
            KeyAlgorithm::from_u8(1),
            Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512))
        );
        assert_eq!(
            KeyAlgorithm::from_u8(2),
            Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44))
        );
        assert_eq!(
            KeyAlgorithm::from_u8(3),
            Ok(KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S))
        );
        assert_eq!(KeyAlgorithm::from_u8(4), Err(AlgorithmError::UnknownAlgorithmId(4)));

        // Test conversion back to u8 (BIP-360 ID)
        assert_eq!(KeyAlgorithm::Secp256k1.to_u8(), Ok(0));
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512).to_u8(), Ok(1));
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44).to_u8(), Ok(2));
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S).to_u8(), Ok(3));
        // Assuming SECP256K1_SCHNORR is another constant in PqcAlgorithm and is NOT mapped
        // assert!(KeyAlgorithm::PostQuantum(PqcAlgorithm::SECP256K1_SCHNORR).to_u8().is_err());

        // Test bitmask bit calculation
        assert_eq!(KeyAlgorithm::Secp256k1.bitmask_bit(), 0x01);
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512).bitmask_bit(), 0x02);
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44).bitmask_bit(), 0x04);
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S).bitmask_bit(), 0x08);

        // Test key type (BIP-360)
        assert_eq!(KeyAlgorithm::Secp256k1.key_type(), 0);
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512).key_type(), 1);
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44).key_type(), 2);
        assert_eq!(KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S).key_type(), 3);
    }

    #[test]
    fn test_key_type_bitmask() {
        // Test creating bitmask with all algorithms
        let all_algos = [
            KeyAlgorithm::Secp256k1,
            KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512),
            KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44),
            KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S),
        ];
        let bitmask = KeyTypeBitmask::new(&all_algos);
        assert_eq!(bitmask.as_u8(), 0x0F); // 0b1111

        // Test creating bitmask with specific algorithms
        let some_algos =
            [KeyAlgorithm::Secp256k1, KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44)]; // Secp and Dilithium
        let bitmask = KeyTypeBitmask::new(&some_algos);
        assert_eq!(bitmask.as_u8(), 0x05); // 0b0101

        // Test checking if algorithm is enabled
        let bitmask = KeyTypeBitmask::from_u8(0x06); // Falcon and Dilithium (BIP-360 IDs 1 and 2)
        assert!(!bitmask.is_algorithm_enabled(KeyAlgorithm::Secp256k1));
        assert!(bitmask.is_algorithm_enabled(KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512)));
        assert!(bitmask.is_algorithm_enabled(KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44)));
        assert!(
            !bitmask.is_algorithm_enabled(KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S))
        );

        // Test getting enabled algorithms
        let bitmask = KeyTypeBitmask::from_u8(0x0A); // Falcon and Sphincs (BIP-360 IDs 1 and 3)
        let enabled = bitmask.enabled_algorithms();
        assert_eq!(enabled.len(), 2);
        // Order depends on the implementation of enabled_algorithms, check based on BIP-360 ID order
        assert!(enabled.contains(&KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512)));
        assert!(enabled.contains(&KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S)));
    }

    #[test]
    fn test_attestation() {
        // Create some mock public keys - Note: Use correct PQC constants
        let secp_pk = vec![0x02; 33]; // Example compressed secp key
        let falcon_pk = vec![0xFA; bitcoinpqc::public_key_size(PqcAlgorithm::FN_DSA_512)];
        let dilithium_pk = vec![0xD1; bitcoinpqc::public_key_size(PqcAlgorithm::ML_DSA_44)];
        let sphincs_pk = vec![0x59; bitcoinpqc::public_key_size(PqcAlgorithm::SLH_DSA_128S)];

        // Create attestation with Falcon and Sphincs
        let algos = [
            KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512),
            KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S),
        ];
        let bitmask = KeyTypeBitmask::new(&algos);
        let public_keys = vec![
            (KeyAlgorithm::PostQuantum(PqcAlgorithm::FN_DSA_512), falcon_pk.clone()),
            (KeyAlgorithm::PostQuantum(PqcAlgorithm::SLH_DSA_128S), sphincs_pk.clone()),
        ];
        let attestation = Attestation::new(bitmask, public_keys.clone());

        assert_eq!(attestation.key_type_bitmask.as_u8(), 0x0A); // 0b1010
        assert_eq!(attestation.public_keys.len(), 2);

        // Compute commitment (manual calculation based on BIP-360 spec)
        let mut expected_data = Vec::new();
        expected_data.push(0x0A); // Bitmask

        // Falcon (ID 1)
        expected_data.push(1); // Algorithm ID
        let falcon_len = falcon_pk.len() as u64;
        if falcon_len < 0xfd {
            expected_data.push(falcon_len as u8);
        } else { /* handle larger sizes if needed */
        }
        expected_data.extend_from_slice(&falcon_pk);

        // Sphincs (ID 3)
        expected_data.push(3); // Algorithm ID
        let sphincs_len = sphincs_pk.len() as u64;
        if sphincs_len < 0xfd {
            expected_data.push(sphincs_len as u8);
        } else { /* handle larger sizes if needed */
        }
        expected_data.extend_from_slice(&sphincs_pk);

        let expected_commitment = hashes::sha256::Hash::hash(&expected_data).to_byte_array();
        assert_eq!(attestation.compute_commitment(), expected_commitment);

        // Test with Secp256k1 included
        let algos_with_secp = [
            KeyAlgorithm::Secp256k1,
            KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44), // Dilithium
        ];
        let bitmask_with_secp = KeyTypeBitmask::new(&algos_with_secp);
        let public_keys_with_secp = vec![
            (KeyAlgorithm::Secp256k1, secp_pk.clone()),
            (KeyAlgorithm::PostQuantum(PqcAlgorithm::ML_DSA_44), dilithium_pk.clone()),
        ];
        let attestation_with_secp =
            Attestation::new(bitmask_with_secp, public_keys_with_secp.clone());

        assert_eq!(attestation_with_secp.key_type_bitmask.as_u8(), 0x05); // 0b0101

        // Compute commitment
        let mut expected_data_secp = Vec::new();
        expected_data_secp.push(0x05); // Bitmask

        // Secp256k1 (ID 0) - needs to be sorted first
        expected_data_secp.push(0); // Algorithm ID
        let secp_len = secp_pk.len() as u64;
        if secp_len < 0xfd {
            expected_data_secp.push(secp_len as u8);
        } else { /* handle */
        }
        expected_data_secp.extend_from_slice(&secp_pk);

        // Dilithium (ID 2)
        expected_data_secp.push(2); // Algorithm ID
        let dilithium_len = dilithium_pk.len() as u64;
        if dilithium_len < 0xfd {
            expected_data_secp.push(dilithium_len as u8);
        } else { /* handle */
        }
        expected_data_secp.extend_from_slice(&dilithium_pk);

        let expected_commitment_secp =
            hashes::sha256::Hash::hash(&expected_data_secp).to_byte_array();
        assert_eq!(attestation_with_secp.compute_commitment(), expected_commitment_secp);
    }

    #[test]
    fn test_p2qrh_template() {
        // Create a simple attestation
        let key_type_bitmask = KeyTypeBitmask::from_u8(0x01); // Only Secp256k1
        let secp_pubkey = vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let public_keys = vec![(KeyAlgorithm::Secp256k1, secp_pubkey)];
        let attestation = Attestation::new(key_type_bitmask, public_keys);

        // Create P2QRH template
        let template = P2QRHTemplate::new(&attestation);

        // Generate scriptPubKey
        let script_pubkey = template.script_pubkey();

        // Verify script structure: OP_PUSHNUM_3 <32-byte hash>
        let script_bytes = script_pubkey.as_bytes();
        assert_eq!(script_bytes.len(), 34); // 1 byte OP_PUSHNUM_3 + 1 byte push + 32 bytes hash
        assert_eq!(script_bytes[0], 0x53); // OP_PUSHNUM_3
        assert_eq!(script_bytes[1], 0x20); // Push 32 bytes

        // Verify the hash commitment matches
        let commitment = attestation.compute_commitment();
        assert_eq!(&script_bytes[2..34], &commitment);
    }

    // This test would use actual test vectors from BIP-360 once they are available
    #[test]
    fn test_bip360_vectors() {
        // This is a placeholder for future test vectors from BIP-360
        // Once test vectors are published, specific tests should be added here
        // to validate the implementation against the BIP specification
    }
}

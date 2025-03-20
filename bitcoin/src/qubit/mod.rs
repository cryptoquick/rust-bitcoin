// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Qubit (P2QRH).
//!
//! This module provides support for P2QRH (Pay to Quantum Resistant Hash) as defined in BIP-360.

pub mod address;
pub mod serialized_signature;

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

/// Signature Algorithms supported by P2QRH
///
/// As defined in BIP-360, each algorithm has a specific key type bit position
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SignatureAlgorithm {
    /// Key type 0 - secp256k1
    Secp256k1 = 0,
    /// Key type 1 - FALCON-512
    Falcon = 1,
    /// Key type 2 - CRYSTALS-Dilithium Level I
    Dilithium = 2,
    /// Key type 3 - SPHINCS+-128s
    Sphincs = 3,
}

impl SignatureAlgorithm {
    /// Get the algorithm from its key type index
    pub fn from_key_type(key_type: u8) -> Option<Self> {
        match key_type {
            0 => Some(SignatureAlgorithm::Secp256k1),
            1 => Some(SignatureAlgorithm::Falcon),
            2 => Some(SignatureAlgorithm::Dilithium),
            3 => Some(SignatureAlgorithm::Sphincs),
            _ => None,
        }
    }

    /// Get the algorithm from its identifier value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SignatureAlgorithm::Secp256k1),
            1 => Some(SignatureAlgorithm::Falcon),
            2 => Some(SignatureAlgorithm::Dilithium),
            3 => Some(SignatureAlgorithm::Sphincs),
            _ => None,
        }
    }

    /// Get the algorithm identifier value
    pub fn to_u8(self) -> u8 { self as u8 }

    /// Get the bit position in the key type bitmask for this algorithm
    pub fn bitmask_bit(self) -> u8 { 1 << self as u8 }

    /// Get the key type index for this algorithm (0-3)
    pub fn key_type(self) -> u8 { self as u8 }
}

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
    pub fn new(algorithms: &[SignatureAlgorithm]) -> Self {
        let mut bitmask = 0u8;
        for algo in algorithms {
            bitmask |= algo.bitmask_bit();
        }
        KeyTypeBitmask(bitmask)
    }

    /// Check if a specific algorithm is enabled in this bitmask
    pub fn is_algorithm_enabled(&self, algorithm: SignatureAlgorithm) -> bool {
        (self.0 & algorithm.bitmask_bit()) != 0
    }

    /// Get the raw bitmask value
    pub fn as_u8(&self) -> u8 { self.0 }

    /// Create from a raw bitmask value
    pub fn from_u8(value: u8) -> Self { KeyTypeBitmask(value) }

    /// Get a list of algorithms enabled by this bitmask
    pub fn enabled_algorithms(&self) -> Vec<SignatureAlgorithm> {
        let mut result = Vec::new();

        if self.is_algorithm_enabled(SignatureAlgorithm::Secp256k1) {
            result.push(SignatureAlgorithm::Secp256k1);
        }

        if self.is_algorithm_enabled(SignatureAlgorithm::Falcon) {
            result.push(SignatureAlgorithm::Falcon);
        }

        if self.is_algorithm_enabled(SignatureAlgorithm::Dilithium) {
            result.push(SignatureAlgorithm::Dilithium);
        }

        if self.is_algorithm_enabled(SignatureAlgorithm::Sphincs) {
            result.push(SignatureAlgorithm::Sphincs);
        }

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
    /// Vector of public keys for each enabled algorithm
    pub public_keys: Vec<(SignatureAlgorithm, Vec<u8>)>,
}

impl Attestation {
    /// Create a new attestation with the given key type bitmask and public keys
    pub fn new(
        key_type_bitmask: KeyTypeBitmask,
        public_keys: Vec<(SignatureAlgorithm, Vec<u8>)>,
    ) -> Self {
        Attestation { key_type_bitmask, public_keys }
    }

    /// Compute the hash commitment for this attestation
    pub fn compute_commitment(&self) -> [u8; 32] {
        // Sort public keys by algorithm ID
        let mut sorted_keys = self.public_keys.clone();
        sorted_keys.sort_by_key(|(algo, _)| *algo);

        // Concatenate all data and hash it
        let mut data = Vec::new();
        data.push(self.key_type_bitmask.as_u8());

        for (algo, pubkey) in sorted_keys {
            data.push(algo.to_u8());
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
    use super::*;

    #[test]
    fn test_signature_algorithm() {
        // Test conversion from key type to algorithm
        assert_eq!(SignatureAlgorithm::from_key_type(0), Some(SignatureAlgorithm::Secp256k1));
        assert_eq!(SignatureAlgorithm::from_key_type(1), Some(SignatureAlgorithm::Falcon));
        assert_eq!(SignatureAlgorithm::from_key_type(2), Some(SignatureAlgorithm::Dilithium));
        assert_eq!(SignatureAlgorithm::from_key_type(3), Some(SignatureAlgorithm::Sphincs));
        assert_eq!(SignatureAlgorithm::from_key_type(4), None);

        // Test conversion from u8 to algorithm
        assert_eq!(SignatureAlgorithm::from_u8(0), Some(SignatureAlgorithm::Secp256k1));
        assert_eq!(SignatureAlgorithm::from_u8(1), Some(SignatureAlgorithm::Falcon));
        assert_eq!(SignatureAlgorithm::from_u8(2), Some(SignatureAlgorithm::Dilithium));
        assert_eq!(SignatureAlgorithm::from_u8(3), Some(SignatureAlgorithm::Sphincs));
        assert_eq!(SignatureAlgorithm::from_u8(4), None);

        // Test bitmask bit calculation
        assert_eq!(SignatureAlgorithm::Secp256k1.bitmask_bit(), 0x01);
        assert_eq!(SignatureAlgorithm::Falcon.bitmask_bit(), 0x02);
        assert_eq!(SignatureAlgorithm::Dilithium.bitmask_bit(), 0x04);
        assert_eq!(SignatureAlgorithm::Sphincs.bitmask_bit(), 0x08);

        // Test key type
        assert_eq!(SignatureAlgorithm::Secp256k1.key_type(), 0);
        assert_eq!(SignatureAlgorithm::Falcon.key_type(), 1);
        assert_eq!(SignatureAlgorithm::Dilithium.key_type(), 2);
        assert_eq!(SignatureAlgorithm::Sphincs.key_type(), 3);
    }

    #[test]
    fn test_key_type_bitmask() {
        // Test creating bitmask with all algorithms
        let all_algos = [
            SignatureAlgorithm::Secp256k1,
            SignatureAlgorithm::Falcon,
            SignatureAlgorithm::Dilithium,
            SignatureAlgorithm::Sphincs,
        ];
        let bitmask = KeyTypeBitmask::new(&all_algos);
        assert_eq!(bitmask.as_u8(), 0x0F); // 0b1111

        // Test creating bitmask with specific algorithms
        let some_algos = [SignatureAlgorithm::Secp256k1, SignatureAlgorithm::Dilithium];
        let bitmask = KeyTypeBitmask::new(&some_algos);
        assert_eq!(bitmask.as_u8(), 0x05); // 0b0101

        // Test checking if algorithm is enabled
        let bitmask = KeyTypeBitmask::from_u8(0x06); // Falcon and Dilithium
        assert!(!bitmask.is_algorithm_enabled(SignatureAlgorithm::Secp256k1));
        assert!(bitmask.is_algorithm_enabled(SignatureAlgorithm::Falcon));
        assert!(bitmask.is_algorithm_enabled(SignatureAlgorithm::Dilithium));
        assert!(!bitmask.is_algorithm_enabled(SignatureAlgorithm::Sphincs));

        // Test getting enabled algorithms
        let bitmask = KeyTypeBitmask::from_u8(0x0A); // Falcon and Sphincs
        let enabled = bitmask.enabled_algorithms();
        assert_eq!(enabled.len(), 2);
        assert_eq!(enabled[0], SignatureAlgorithm::Falcon);
        assert_eq!(enabled[1], SignatureAlgorithm::Sphincs);
    }

    #[test]
    fn test_attestation() {
        // Create some mock public keys
        let secp_pubkey = vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let falcon_pubkey = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        // Create attestation with two key types
        let key_type_bitmask = KeyTypeBitmask::from_u8(0x03); // Secp256k1 and Falcon
        let public_keys = vec![
            (SignatureAlgorithm::Falcon, falcon_pubkey.clone()), // Intentionally out of order
            (SignatureAlgorithm::Secp256k1, secp_pubkey.clone()),
        ];

        let attestation = Attestation::new(key_type_bitmask, public_keys);

        // Compute commitment
        let commitment = attestation.compute_commitment();

        // Create another attestation with the same keys but in different order
        let public_keys2 = vec![
            (SignatureAlgorithm::Secp256k1, secp_pubkey.clone()),
            (SignatureAlgorithm::Falcon, falcon_pubkey.clone()),
        ];
        let attestation2 = Attestation::new(key_type_bitmask, public_keys2);

        // The commitments should be the same since they're sorted
        assert_eq!(commitment, attestation2.compute_commitment());

        // Create a different attestation
        let key_type_bitmask3 = KeyTypeBitmask::from_u8(0x01); // Only Secp256k1
        let public_keys3 = vec![(SignatureAlgorithm::Secp256k1, secp_pubkey)];
        let attestation3 = Attestation::new(key_type_bitmask3, public_keys3);

        // This commitment should be different
        assert_ne!(commitment, attestation3.compute_commitment());
    }

    #[test]
    fn test_p2qrh_template() {
        // Create a simple attestation
        let key_type_bitmask = KeyTypeBitmask::from_u8(0x01); // Only Secp256k1
        let secp_pubkey = vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let public_keys = vec![(SignatureAlgorithm::Secp256k1, secp_pubkey)];
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

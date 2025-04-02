// SPDX-License-Identifier: CC0-1.0

//! P2QRH Bitcoin addresses.
//!
//! This module provides P2QRH addresses for Bitcoin (implementing BIP-360).

use core::fmt;

use bitcoinpqc::Algorithm as PqcAlgorithm;

use super::KeyAlgorithm;
use crate::address::{Address, KnownHrp};
use crate::crypto::key::TweakedPublicKey;
use crate::qubit::{Attestation, KeyTypeBitmask, P2QRHTemplate};
use crate::XOnlyPublicKey;

/// Possible human-readable parts for P2QRH addresses
pub const P2QRH_HRP: &str = "qr";

/// A P2QRH Bitcoin address.
///
/// This type is separate from [`Address`] as P2QRH implementations require
/// additional metadata such as the quantum attestation structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QubitAddress {
    /// The address itself
    pub address: Address,
    /// The quantum attestation associated with this address
    pub attestation: Attestation,
    /// The hash commitment of the attestation
    pub hash_commitment: [u8; 32],
}

impl QubitAddress {
    /// Creates a new P2QRH address from a quantum attestation.
    pub fn new(attestation: Attestation, hrp: KnownHrp) -> QubitAddress {
        let template = P2QRHTemplate::new(&attestation);
        let hash_commitment = template.hash_commitment;

        // Convert hash to XOnlyPublicKey (just for P2TR API)
        // We're using this API just to satisfy the P2TR address creation requirements
        let xonly_bytes: [u8; 32] = hash_commitment;
        let xonly = XOnlyPublicKey::from_byte_array(&xonly_bytes)
            .expect("32-byte hash should be valid for XOnlyPublicKey");

        // Create a P2TR address with the hash commitment as a tweaked key
        // We have to use dangerous_assume_tweaked because we're not actually tweaking the key,
        // we're just using a hash as a key directly
        let tweaked = TweakedPublicKey::dangerous_assume_tweaked(xonly);
        let address = Address::p2tr_tweaked(tweaked, hrp);

        QubitAddress { address, attestation, hash_commitment }
    }

    /// Creates a new P2QRH mainnet address from a quantum attestation.
    pub fn new_mainnet(attestation: Attestation) -> QubitAddress {
        Self::new(attestation, KnownHrp::Mainnet)
    }

    /// Creates a new P2QRH testnet address from a quantum attestation.
    pub fn new_testnet(attestation: Attestation) -> QubitAddress {
        Self::new(attestation, KnownHrp::Testnets)
    }

    /// Creates a new P2QRH regtest address from a quantum attestation.
    pub fn new_regtest(attestation: Attestation) -> QubitAddress {
        Self::new(attestation, KnownHrp::Regtest)
    }

    /// Creates a new P2QRH signet address from a quantum attestation.
    pub fn new_signet(attestation: Attestation) -> QubitAddress {
        Self::new(attestation, KnownHrp::Testnets) // Use Testnets for signet
    }

    /// Returns the underlying Bitcoin [`Address`].
    pub fn address(&self) -> &Address { &self.address }

    /// Returns the quantum attestation associated with this address.
    pub fn attestation(&self) -> &Attestation { &self.attestation }

    /// Returns the script pubkey for this address.
    pub fn script_pubkey(&self) -> crate::ScriptBuf { self.address.script_pubkey() }

    /// Checks if the bitmask has the specified algorithm enabled.
    pub fn has_algorithm(&self, algorithm: PqcAlgorithm) -> bool {
        self.attestation.key_type_bitmask.is_algorithm_enabled(KeyAlgorithm::PostQuantum(algorithm))
    }

    /// Gets the public key for a specific algorithm.
    pub fn public_key_for_algorithm(&self, algorithm: PqcAlgorithm) -> Option<&[u8]> {
        self.attestation
            .public_keys
            .iter()
            .find(|(algo, _)| *algo == KeyAlgorithm::PostQuantum(algorithm))
            .map(|(_, pubkey)| pubkey.as_slice())
    }
}

impl fmt::Display for QubitAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.address) }
}

/// A builder to create a P2QRH address from multiple quantum algorithm public keys.
pub struct QubitAddressBuilder {
    /// Map of algorithm to public key
    keys: Vec<(PqcAlgorithm, Vec<u8>)>,
}

impl QubitAddressBuilder {
    /// Creates a new, empty P2QRH address builder.
    pub fn new() -> Self { QubitAddressBuilder { keys: Vec::new() } }

    /// Adds a public key for a specific quantum algorithm.
    pub fn add_key(mut self, algorithm: PqcAlgorithm, public_key: Vec<u8>) -> Self {
        self.keys.push((algorithm, public_key));
        self
    }

    /// Builds a P2QRH address for the given network.
    pub fn build(self, hrp: KnownHrp) -> QubitAddress {
        // Create bitmask based on what algorithms are present
        let algorithms: Vec<KeyAlgorithm> =
            self.keys.iter().map(|(algo, _)| KeyAlgorithm::PostQuantum(*algo)).collect();
        let bitmask = KeyTypeBitmask::new(&algorithms);

        // Create attestation
        let attestation_keys: Vec<(KeyAlgorithm, Vec<u8>)> = self
            .keys
            .iter()
            .map(|(algo, key)| (KeyAlgorithm::PostQuantum(*algo), key.clone()))
            .collect();
        let attestation = Attestation::new(bitmask, attestation_keys);

        // Create address
        QubitAddress::new(attestation, hrp)
    }
}

impl Default for QubitAddressBuilder {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qubit_address_creation() {
        // Create a simple attestation with two algorithms
        let sphincs_pubkey = vec![0x01, 0x02, 0x03, 0x04];
        let dilithium_pubkey = vec![0x05, 0x06, 0x07, 0x08];

        let address = QubitAddressBuilder::new()
            .add_key(PqcAlgorithm::SLH_DSA_128S, sphincs_pubkey.clone())
            .add_key(PqcAlgorithm::ML_DSA_44, dilithium_pubkey.clone())
            .build(KnownHrp::Testnets);

        // Verify the address has correct data
        assert!(address.has_algorithm(PqcAlgorithm::SLH_DSA_128S));
        assert!(address.has_algorithm(PqcAlgorithm::ML_DSA_44));
        assert!(!address.has_algorithm(PqcAlgorithm::FN_DSA_512));

        // Check public key retrieval
        assert_eq!(
            address.public_key_for_algorithm(PqcAlgorithm::SLH_DSA_128S),
            Some(sphincs_pubkey.as_slice())
        );
        assert_eq!(
            address.public_key_for_algorithm(PqcAlgorithm::ML_DSA_44),
            Some(dilithium_pubkey.as_slice())
        );
        assert_eq!(address.public_key_for_algorithm(PqcAlgorithm::FN_DSA_512), None);

        // Verify the script_pubkey
        let script = address.script_pubkey();
        assert_eq!(script, address.address.script_pubkey());
    }
}

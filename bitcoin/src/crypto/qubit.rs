// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Quantum Resistant Hash (P2QRH) keys and signatures.
//!
//! This module provides P2QRH signatures used in Bitcoin (implementing BIP-360).

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoinpqc::{
    Algorithm as PqcAlgorithm, PqcError, PublicKey as PqcPublicKey, Signature as PqcSignature,
};
use io::Write;
use secp256k1::{Error as SecpError, Message as SecpMessage};

// Import secp256k1 types for verification
use crate::key::{PublicKey as SecpPublicKey, Secp256k1};
// Import the new KeyAlgorithm enum and PQC types
use crate::qubit::KeyAlgorithm;
use crate::TapSighashTag;

/// A BIP-360 compliant P2QRH signature, which can be either Secp256k1 or Post-Quantum.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))] // Needs bitcoinpqc serde feature
pub struct Signature {
    /// The algorithm used for this signature.
    pub algorithm: KeyAlgorithm,
    /// The actual signature data. For PQC, this wraps `bitcoinpqc::Signature`.
    /// For Secp256k1, this contains the raw signature bytes.
    pub signature_data: Vec<u8>,
    // TODO: Consider storing PqcSignature directly for PQC cases instead of Vec<u8>
    // to avoid serialization/deserialization within this struct.
}

impl Signature {
    /// Creates a new P2QRH signature.
    #[must_use]
    pub fn new(algorithm: KeyAlgorithm, signature_data: Vec<u8>) -> Self {
        Signature { algorithm, signature_data }
    }

    /// Creates a Signature from a PQC signature and its algorithm.
    #[must_use]
    pub fn from_pqc(pqc_sig: PqcSignature, algorithm: PqcAlgorithm) -> Self {
        Signature {
            algorithm: KeyAlgorithm::PostQuantum(algorithm),
            signature_data: pqc_sig.bytes.clone(), // Access the public `bytes` field and clone it
        }
    }

    /// Creates a Signature from a Secp256k1 signature.
    #[must_use]
    pub fn from_secp(secp_sig: &secp256k1::ecdsa::Signature) -> Self {
        Signature {
            algorithm: KeyAlgorithm::Secp256k1,
            signature_data: secp_sig.serialize_compact().to_vec(),
        }
    }

    /// Deserializes the signature from a slice according to BIP-360 format (`algo_byte` || `sig_bytes`).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input slice is empty
    /// - The algorithm byte is invalid
    /// - The signature data has an invalid size for the algorithm
    pub fn from_slice(sl: &[u8]) -> Result<Self, SigFromSliceError> {
        if sl.is_empty() {
            return Err(SigFromSliceError::InvalidInputLength(0));
        }

        // First byte is the BIP-360 algorithm ID
        let algorithm = KeyAlgorithm::from_u8(sl[0])
            .map_err(|e| SigFromSliceError::InvalidAlgorithm(sl[0], e))?;

        let signature_data = sl[1..].to_vec();

        // Basic validation based on algorithm type
        match algorithm {
            KeyAlgorithm::Secp256k1 =>
                if signature_data.len() != 64 {
                    return Err(SigFromSliceError::InvalidSignatureSize {
                        algo: algorithm,
                        size: signature_data.len(),
                    });
                },
            KeyAlgorithm::PostQuantum(pqc_algo) => {
                // Attempt to parse PQC signature to validate size, but store raw bytes
                // Use checked_signature_size for safety if available, otherwise signature_size
                let expected_size = bitcoinpqc::signature_size(pqc_algo);
                if signature_data.len() != expected_size {
                    return Err(SigFromSliceError::InvalidSignatureSize {
                        algo: algorithm,
                        size: signature_data.len(),
                    });
                }
                // We could parse fully: PqcSignature::from_slice(&signature_data, pqc_algo).map_err(SigFromSliceError::PqcLibError)?;
                // But we keep raw bytes for now.
            }
        }

        Ok(Signature { algorithm, signature_data })
    }

    /// Serializes the signature according to BIP-360 format (`algo_byte` || `sig_bytes`).
    ///
    /// Note: this allocates on the heap.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.signature_data.len() + 1);
        match self.algorithm.to_u8() {
            // Handle potential error from to_u8
            Ok(id) => result.push(id), // Use BIP-360 ID
            Err(_) => {
                // This case should ideally not happen if Signature is constructed correctly,
                // but handle it defensively. Maybe return an error or default value?
                // For now, using a placeholder value (e.g., 255) or panicking.
                // panic!("Attempted to serialize Signature with unmappable algorithm: {:?}", self.algorithm);
                result.push(255); // Placeholder for unmappable algo
            }
        }
        result.extend_from_slice(&self.signature_data);
        result
    }

    /// Serializes the signature to `writer`.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the writer fails.
    pub fn serialize_to_writer<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        let sig_vec = self.to_vec();
        writer.write_all(&sig_vec)
    }
    // The serialize() method previously returned SerializedSignature and avoided allocation.
    // Since SerializedSignature is removed and to_vec() allocates, serialize() is now redundant.
}

/// An error constructing a [`qubit::Signature`] from a byte slice.
///
/// [`qubit::Signature`]: crate::crypto::qubit::Signature
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigFromSliceError {
    /// Input slice was not long enough.
    InvalidInputLength(usize),
    /// Invalid signature algorithm ID (BIP-360).
    InvalidAlgorithm(u8, crate::qubit::AlgorithmError),
    /// Invalid signature size for the specified algorithm.
    InvalidSignatureSize {
        /// The algorithm that was used
        algo: KeyAlgorithm,
        /// The actual size that was provided
        size: usize,
    },
    /// Error from the underlying bitcoinpqc library.
    PqcLibError(PqcError),
    /// Error during Secp256k1 signature parsing.
    SecpError(secp256k1::Error),
}

impl From<Infallible> for SigFromSliceError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for SigFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SigFromSliceError::{
            InvalidAlgorithm, InvalidInputLength, InvalidSignatureSize, PqcLibError, SecpError,
        };

        match *self {
            InvalidInputLength(sz) => write!(f, "invalid input slice length: {sz}"),
            InvalidAlgorithm(id, ref e) => write!(f, "invalid P2QRH algorithm ID {id}: {e}"),
            InvalidSignatureSize { algo, size } =>
                write!(f, "invalid P2QRH signature size {size} for algorithm {algo:?}"),
            PqcLibError(ref e) => write!(f, "PQC library error: {e}"),
            SecpError(ref e) => write!(f, "secp256k1 error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigFromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SigFromSliceError::{InvalidAlgorithm, PqcLibError, SecpError};
        match *self {
            InvalidAlgorithm(_, ref e) => Some(e),
            PqcLibError(ref e) => Some(e),
            SecpError(ref e) => Some(e),
            _ => None,
        }
    }
}

/// An error during P2QRH signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationError {
    /// Error from the underlying PQC library.
    Pqc(PqcError),
    /// Error from the secp256k1 library.
    Secp(SecpError),
    /// Public key has incorrect size or format for the algorithm.
    InvalidPublicKey,
    /// Signature has incorrect size or format for the algorithm.
    InvalidSignatureFormat,
    /// The algorithm used in the signature is not supported or has no mapping.
    UnsupportedAlgorithm(KeyAlgorithm),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use VerificationError::{
            InvalidPublicKey, InvalidSignatureFormat, Pqc, Secp, UnsupportedAlgorithm,
        };
        match *self {
            Pqc(ref e) => write!(f, "PQC verification failed: {e}"),
            Secp(ref e) => write!(f, "secp256k1 verification failed: {e}"),
            InvalidPublicKey => write!(f, "invalid public key for algorithm"),
            InvalidSignatureFormat => write!(f, "invalid signature format for algorithm"),
            UnsupportedAlgorithm(algo) =>
                write!(f, "unsupported algorithm for verification: {algo:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use VerificationError::{Pqc, Secp};
        match *self {
            Pqc(ref e) => Some(e),
            Secp(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Verifies a P2QRH signature against a public key and message.
///
/// The public key must be provided in the correct format for the signature's algorithm.
///
/// # Errors
///
/// Returns an error if:
/// - The public key format is invalid
/// - The signature format is invalid
/// - The signature verification fails
/// - The algorithm is not supported
#[allow(dead_code)]
pub fn verify_signature(
    sig: &Signature,
    pubkey_bytes: &[u8],
    message: &[u8],
) -> Result<(), VerificationError> {
    match sig.algorithm {
        KeyAlgorithm::Secp256k1 => {
            // Parse secp256k1 public key
            let pubkey = SecpPublicKey::from_slice(pubkey_bytes)
                .map_err(|_| VerificationError::InvalidPublicKey)?;

            // Parse secp256k1 signature
            let secp_sig = secp256k1::ecdsa::Signature::from_compact(&sig.signature_data)
                .map_err(|_| VerificationError::InvalidSignatureFormat)?;

            // Hash the message (assuming Taproot sighash - adjust if needed)
            let msg_hash = hashes::sha256t::Hash::<TapSighashTag>::hash(message);
            let secp_msg = SecpMessage::from_digest(msg_hash.to_byte_array());

            // Verify using secp256k1 library
            let secp = Secp256k1::verification_only();
            secp.verify_ecdsa(&secp_msg, &secp_sig, &pubkey.inner).map_err(VerificationError::Secp)
        }
        KeyAlgorithm::PostQuantum(pqc_algo) => {
            // Check if the PQC algorithm is supported by bitcoinpqc verify (it should be if it's in the enum)
            // This check might be redundant if KeyAlgorithm construction ensures valid PQC algos

            // Construct PqcPublicKey and PqcSignature using from_bytes
            let pqc_pk = PqcPublicKey::from_bytes(pqc_algo, pubkey_bytes);
            let pqc_sig = PqcSignature::from_bytes(pqc_algo, &sig.signature_data);

            // Verify using bitcoinpqc library
            bitcoinpqc::verify(&pqc_pk, message, &pqc_sig).map_err(VerificationError::Pqc)
        } // It's good practice to handle all enum variants, though PostQuantum covers all PQC cases.
          // If KeyAlgorithm could somehow contain an unmappable PQC algo, handle it here.
          // Currently, the structure prevents this scenario if constructed via ::new or ::from_pqc.
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Choose between Secp and PQC
        let is_secp = u.ratio(1, 5)?; // Bias towards PQC slightly for testing

        let (algorithm, signature_data) = if is_secp {
            let mut sig_bytes = [0u8; 64];
            u.fill_buffer(&mut sig_bytes)?;
            // Ensure it *could* be a valid compact signature for the purpose of Arbitrary
            // (Actual validity not required here)
            (KeyAlgorithm::Secp256k1, sig_bytes.to_vec())
        } else {
            // Choose a PQC algorithm mapped in BIP-360
            let pqc_algo = match u.int_in_range(1..=3)? {
                // BIP-360 IDs 1, 2, 3
                1 => PqcAlgorithm::FN_DSA_512,
                2 => PqcAlgorithm::ML_DSA_44,
                3 => PqcAlgorithm::SLH_DSA_128S,
                _ => unreachable!(),
            };
            // Use checked_signature_size if available, otherwise signature_size
            let sig_len = bitcoinpqc::signature_size(pqc_algo);
            let mut sig_bytes = vec![0u8; sig_len];
            u.fill_buffer(&mut sig_bytes)?;
            (KeyAlgorithm::PostQuantum(pqc_algo), sig_bytes)
        };

        Ok(Signature { algorithm, signature_data })
    }
}

#[cfg(test)]
mod pqc_tests {
    use super::*;

    #[test]
    fn test_pqc_verify_signature() {
        // Test message
        let message = b"Test message for PQC verification";

        // Test PQC signatures (simulated since we can't easily generate real PQC signatures in tests)
        // Setup for ML-DSA-44 (Dilithium)
        let pqc_algo = PqcAlgorithm::ML_DSA_44;
        let pqc_pubkey_size = bitcoinpqc::public_key_size(pqc_algo);
        let pqc_sig_size = bitcoinpqc::signature_size(pqc_algo);

        // Create mock pubkey and signature data
        let pqc_pubkey = vec![0xD1; pqc_pubkey_size];
        let pqc_sig_data = vec![0xD2; pqc_sig_size];

        // Create PQC Signature instance
        let pqc_signature = Signature::new(KeyAlgorithm::PostQuantum(pqc_algo), pqc_sig_data);

        // Since bitcoinpqc::verify will fail with mocked data,
        // check that the error is properly propagated
        let result = verify_signature(&pqc_signature, &pqc_pubkey, message);
        assert!(result.is_err(), "Verification with mocked PQC data should fail");

        match result {
            Err(VerificationError::Pqc(_)) => {} // Expected error for fake PQC data
            _ => panic!("Unexpected error type: {:?}", result),
        }

        // Test invalid pubkey size
        let result = verify_signature(&pqc_signature, &[0xFF], message);
        assert!(result.is_err(), "Verification with invalid PQC pubkey should fail");

        // Test another PQC algorithm - SLH-DSA-128S (SPHINCS+)
        let sphincs_algo = PqcAlgorithm::SLH_DSA_128S;
        let sphincs_pubkey_size = bitcoinpqc::public_key_size(sphincs_algo);
        let sphincs_sig_size = bitcoinpqc::signature_size(sphincs_algo);

        let sphincs_pubkey = vec![0xE1; sphincs_pubkey_size];
        let sphincs_sig_data = vec![0xE2; sphincs_sig_size];

        let sphincs_signature =
            Signature::new(KeyAlgorithm::PostQuantum(sphincs_algo), sphincs_sig_data);

        let result = verify_signature(&sphincs_signature, &sphincs_pubkey, message);
        assert!(result.is_err(), "Verification with mocked SPHINCS+ data should fail");
    }
}

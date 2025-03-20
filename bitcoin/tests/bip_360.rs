use bitcoin::crypto::qubit::{
    generate_sphincs_signing_key, generate_sphincs_verifying_key, sign_sphincs, verify_signature,
};
use bitcoin::hashes::sha256;
use bitcoin::qubit::{
    Attestation, KeyTypeBitmask, P2QRHTemplate, Signature as QubitSignature, SignatureAlgorithm,
};

#[test]
fn test_p2qrh() {
    // Step 1: Create an attestation with multiple quantum-resistant public keys
    let sphincs_pubkey = vec![
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x02,
    ];
    assert_eq!(sphincs_pubkey.len(), 32, "SPHINCS+ public key should be 32 bytes");

    let ml_dsa_pubkey = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x03,
    ];
    assert_eq!(ml_dsa_pubkey.len(), 32, "ML-DSA public key should be 32 bytes");

    // Step 2: Create a key type bitmask for multiple quantum-resistant algorithms
    let bitmask =
        KeyTypeBitmask::new(&[SignatureAlgorithm::Sphincs, SignatureAlgorithm::Dilithium]);

    // Verify bitmask contains expected algorithms
    assert!(bitmask.is_algorithm_enabled(SignatureAlgorithm::Sphincs));
    assert!(bitmask.is_algorithm_enabled(SignatureAlgorithm::Dilithium));
    assert!(!bitmask.is_algorithm_enabled(SignatureAlgorithm::Secp256k1));

    // Step 3: Create the attestation with public keys for enabled algorithms
    let attestation = Attestation::new(
        bitmask,
        vec![
            (SignatureAlgorithm::Sphincs, sphincs_pubkey.clone()),
            (SignatureAlgorithm::Dilithium, ml_dsa_pubkey.clone()),
        ],
    );

    // Verify attestation contains the expected keys
    assert_eq!(attestation.public_keys.len(), 2);

    // Find the keys for each algorithm
    let has_sphincs_key =
        attestation.public_keys.iter().any(|(algo, _)| *algo == SignatureAlgorithm::Sphincs);
    let has_dilithium_key =
        attestation.public_keys.iter().any(|(algo, _)| *algo == SignatureAlgorithm::Dilithium);
    let has_secp256k1_key =
        attestation.public_keys.iter().any(|(algo, _)| *algo == SignatureAlgorithm::Secp256k1);

    assert!(has_sphincs_key, "Attestation should contain a SPHINCS+ key");
    assert!(has_dilithium_key, "Attestation should contain a Dilithium key");
    assert!(!has_secp256k1_key, "Attestation should not contain a secp256k1 key");

    // Step 4: Create a P2QRH template from the attestation
    let template = P2QRHTemplate::new(&attestation);

    // Step 5: Generate the scriptPubKey for this P2QRH template
    let script_pubkey = template.script_pubkey();

    // Verify script_pubkey format (SegWit v3 with 32-byte hash)
    let script_str = script_pubkey.to_string();
    assert!(script_str.starts_with("OP_PUSHNUM_3 OP_PUSHBYTES_32"));

    // The hash should be deterministic based on our inputs
    let expected_hash = "f6cb62ad4d0240dad522a9393f17bddbe809a070c201625c7faa963a2854fa89";
    assert!(script_str.contains(expected_hash));

    // Step 6: Create simulated post-quantum signatures
    let message = b"Transaction to sign";

    // Generate simulated signatures
    let sphincs_signature = generate_deterministic_sphincs_signature(message);
    let ml_dsa_signature = generate_deterministic_ml_dsa_signature(message);

    // Verify signature sizes
    assert_eq!(sphincs_signature.len(), 4124, "SPHINCS+ signature should be 4124 bytes");
    assert_eq!(ml_dsa_signature.len(), 2100, "ML-DSA signature should be 2100 bytes");

    // Step 7: Create QubitSignatures for both algorithms
    let sphincs_qsig = QubitSignature::new(SignatureAlgorithm::Sphincs, sphincs_signature);
    let ml_dsa_qsig = QubitSignature::new(SignatureAlgorithm::Dilithium, ml_dsa_signature);

    // Step 8: Serialize the signatures
    let sphincs_serialized = sphincs_qsig.to_vec();
    let ml_dsa_serialized = ml_dsa_qsig.to_vec();

    // Verify serialized sizes (should be 1 byte longer than original due to algorithm identifier)
    assert_eq!(
        sphincs_serialized.len(),
        4125,
        "Serialized SPHINCS+ signature should be 4125 bytes"
    );
    assert_eq!(ml_dsa_serialized.len(), 2101, "Serialized ML-DSA signature should be 2101 bytes");
}

// Generate a deterministic simulated SPHINCS+-128s signature
fn generate_deterministic_sphincs_signature(message: &[u8]) -> Vec<u8> {
    // SPHINCS+-128s (small) signatures are ~4,124 bytes
    let mut signature = vec![0u8; 4124];

    // Get the message hash
    let hash = sha256::Hash::hash(message);

    // Copy hash to the first 32 bytes
    let hash_bytes = hash.as_byte_array();
    signature[0..32].copy_from_slice(hash_bytes);

    // Fill the rest with a deterministic pattern
    for i in 32..signature.len() {
        signature[i] = ((i % 256) as u8).wrapping_add(hash_bytes[i % 32]);
    }

    signature
}

// Generate a deterministic simulated ML-DSA-44 signature
fn generate_deterministic_ml_dsa_signature(message: &[u8]) -> Vec<u8> {
    // ML-DSA-44 signatures are ~2,100 bytes (security category 2)
    let mut signature = vec![0u8; 2100];

    // Get the message hash
    let hash = sha256::Hash::hash(message);

    // Copy hash to the first 32 bytes
    let hash_bytes = hash.as_byte_array();
    signature[0..32].copy_from_slice(hash_bytes);

    // Fill the rest with a deterministic pattern
    for i in 32..signature.len() {
        signature[i] = ((i % 256) as u8).wrapping_add(hash_bytes[i % 32]);
    }

    signature
}

#[test]
fn test_sphincs_key_generation() {
    // Create a fixed seed for deterministic testing
    let seed = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    // Generate signing key from the seed
    let signing_key = generate_sphincs_signing_key(&seed).unwrap();

    // Verify the signing key is not empty
    assert!(!signing_key.is_empty());

    // Generate verifying key from the signing key
    let verifying_key = generate_sphincs_verifying_key(&signing_key).unwrap();

    // Verify the verifying key is not empty
    assert!(!verifying_key.is_empty());
}

#[test]
fn test_sphincs_sign_verify() {
    // Create a fixed seed for deterministic testing
    let seed = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    // Generate signing key from the seed
    let signing_key = generate_sphincs_signing_key(&seed).unwrap();

    // Generate verifying key from the signing key
    let verifying_key = generate_sphincs_verifying_key(&signing_key).unwrap();

    // Create a message to sign
    let message = b"This is a test message";

    // Sign the message
    let signature = sign_sphincs(&signing_key, message).unwrap();

    // Verify the signature's algorithm is SPHINCS+
    assert_eq!(signature.algorithm, SignatureAlgorithm::Sphincs);

    // Verify the signature
    assert!(verify_signature(&signature, &verifying_key, message));

    // Verify that the signature fails with a different message
    let wrong_message = b"This is a different message";
    assert!(!verify_signature(&signature, &verifying_key, wrong_message));
}

#[test]
fn test_p2qrh_with_real_sphincs() {
    // Create a seed for the SPHINCS+ key
    let seed = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    // Generate real SPHINCS+ keypair
    let sphincs_sk = generate_sphincs_signing_key(&seed).unwrap();
    let sphincs_pubkey = generate_sphincs_verifying_key(&sphincs_sk).unwrap();

    // Create a simulated ML-DSA public key
    let ml_dsa_pubkey = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x03,
    ];

    // Create a P2QRH attestation with both keys
    let bitmask =
        KeyTypeBitmask::new(&[SignatureAlgorithm::Sphincs, SignatureAlgorithm::Dilithium]);
    let attestation = Attestation::new(
        bitmask,
        vec![
            (SignatureAlgorithm::Sphincs, sphincs_pubkey.clone()),
            (SignatureAlgorithm::Dilithium, ml_dsa_pubkey.clone()),
        ],
    );

    // Create a P2QRH template and generate the scriptPubKey
    let template = P2QRHTemplate::new(&attestation);
    let script_pubkey = template.script_pubkey();

    // Verify script_pubkey is in the expected format for SegWit v3
    let script_str = script_pubkey.to_string();
    assert!(script_str.starts_with("OP_PUSHNUM_3 OP_PUSHBYTES_32"));

    // Sign a message with SPHINCS+
    let message = b"Transaction to sign";
    let sphincs_signature = sign_sphincs(&sphincs_sk, message).unwrap();

    // Verify the signature
    assert!(verify_signature(&sphincs_signature, &sphincs_pubkey, message));

    // Ensure signature has the right algorithm
    assert_eq!(sphincs_signature.algorithm, SignatureAlgorithm::Sphincs);

    // Check serialization and deserialization
    let serialized = sphincs_signature.to_vec();
    let deserialized = QubitSignature::from_slice(&serialized).unwrap();

    // Verify the deserialized signature
    assert_eq!(deserialized.algorithm, SignatureAlgorithm::Sphincs);
    assert!(verify_signature(&deserialized, &sphincs_pubkey, message));
}

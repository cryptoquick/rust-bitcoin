use bitcoin::hashes::sha256;
use bitcoin::qubit::{
    Attestation, KeyTypeBitmask, P2QRHTemplate, Signature as QubitSignature, SignatureAlgorithm,
};

fn main() {
    println!("P2QRH (Pay to Quantum Resistant Hash) Example");
    println!("==============================================");
    println!(
        "This example demonstrates the P2QRH (BIP-360) output type using post-quantum signatures"
    );

    // Step 1: Create an attestation with multiple quantum-resistant public keys
    println!("1. Creating post-quantum keypairs");

    // Use hardcoded SPHINCS+ public key (32 bytes)
    // In real implementation, this would be generated using the slh-dsa crate with Shake128s parameters
    let sphincs_pubkey = vec![
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x02, // Ending with 0x02 for valid x-only format
    ];
    println!("- SPHINCS+-128s (SLH-DSA/FIPS-205) public key: {} bytes", sphincs_pubkey.len());

    // Use hardcoded ML-DSA-44 public key (would be ~1184 bytes in a real implementation)
    let ml_dsa_pubkey = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x03, // Ending with 0x03 for valid x-only format
    ];
    println!("- ML-DSA-44 (CRYSTALS-Dilithium/FIPS-204) public key: {} bytes (would be ~1184 bytes in reality)", ml_dsa_pubkey.len());

    // Step 2: Create a key type bitmask that enables multiple quantum-resistant algorithms
    // As specified in BIP-360, this allows flexibility in algorithm selection
    println!("\n2. Creating key type bitmask for multiple quantum-resistant algorithms");
    let bitmask =
        KeyTypeBitmask::new(&[SignatureAlgorithm::Sphincs, SignatureAlgorithm::Dilithium]);
    println!("- Enabled algorithms: SPHINCS+, Dilithium");

    // Step 3: Create the attestation with public keys for enabled algorithms
    // The attestation structure contains the public keys as described in BIP-360
    println!("\n3. Creating attestation structure with quantum-resistant public keys");
    let attestation = Attestation::new(
        bitmask,
        vec![
            (SignatureAlgorithm::Sphincs, sphincs_pubkey.clone()),
            (SignatureAlgorithm::Dilithium, ml_dsa_pubkey.clone()),
        ],
    );
    println!("- Attestation created successfully");

    // Step 4: Create a P2QRH template from the attestation
    // The P2QRH template is the basis for creating the scriptPubKey
    println!("\n4. Creating P2QRH template from attestation");
    let template = P2QRHTemplate::new(&attestation);
    println!("- P2QRH template created successfully");

    // Step 5: Generate the scriptPubKey for this P2QRH template
    // This creates a SegWit v3 output with the hash commitment of the attestation
    println!("\n5. Generating P2QRH scriptPubKey (SegWit v3 output)");
    let script_pubkey = template.script_pubkey();
    println!("- P2QRH scriptPubKey: {}", script_pubkey);

    // Step 6: Create simulated post-quantum signatures
    println!("\n6. Creating post-quantum signatures for a transaction");
    let message = b"Transaction to sign";

    // Generate a deterministic simulated SPHINCS+-128s signature
    println!("- Generating simulated SPHINCS+-128s signature");
    let sphincs_signature = generate_deterministic_sphincs_signature(message);
    println!("- Created simulated SPHINCS+-128s signature: {} bytes", sphincs_signature.len());

    // Generate a deterministic simulated ML-DSA-44 signature
    println!("- Generating simulated ML-DSA-44 signature");
    let ml_dsa_signature = generate_deterministic_ml_dsa_signature(message);
    println!("- Created simulated ML-DSA-44 signature: {} bytes", ml_dsa_signature.len());

    // Step 7: Create QubitSignatures for both algorithms
    let sphincs_qsig = QubitSignature::new(SignatureAlgorithm::Sphincs, sphincs_signature);
    let ml_dsa_qsig = QubitSignature::new(SignatureAlgorithm::Dilithium, ml_dsa_signature);

    println!("\n7. Serializing the signatures");
    let sphincs_serialized = sphincs_qsig.to_vec();
    let ml_dsa_serialized = ml_dsa_qsig.to_vec();
    println!("- SPHINCS+-128s serialized signature: {} bytes", sphincs_serialized.len());
    println!("- ML-DSA-44 serialized signature: {} bytes", ml_dsa_serialized.len());
    println!("- P2QRH transactions would be notably larger than traditional Bitcoin transactions");

    // Step 8: Create and display a P2QRH address
    // This creates a bech32m address for the P2QRH output
    println!("\n8. Creating P2QRH address (bech32m format)");

    // Get the hash commitment from the scriptPubKey
    // The scriptPubKey format is: OP_PUSHNUM_3 OP_PUSHBYTES_32 <32-byte-hash>
    let script = template.script_pubkey();

    // Print the raw values for reference
    println!("- Using SegWit v3 (witness version 3)");
    println!("- Full P2QRH scriptPubKey: {}", script);
    println!("- Bech32m prefix: bc");

    // For now, just show that we would generate a SegWit v3 address
    // In a real implementation, this would be a proper bech32m encoding
    let address_placeholder = "bc1r...(witness v3)".to_string();
    println!("- P2QRH Address: {} (SegWit v3 address)", address_placeholder);

    // Step 9: Simulate signature verification
    println!("\n9. Verifying the signatures");
    println!("- SPHINCS+-128s signature verification: SUCCESS (simulated)");
    println!("- ML-DSA-44 signature verification: SUCCESS (simulated)");

    println!("\nImplementation Details (BIP-360):");
    println!("- P2QRH uses SegWit v3 outputs with quantum-resistant signature algorithms");
    println!(
        "- Multiple algorithms can be supported in a single output (multi-algorithm security)"
    );
    println!("- Each algorithm has different security assumptions, sizes, and performance characteristics:");
    println!("  * SPHINCS+-128s (hash-based): ~4.1KB signatures, no mathematical assumptions, smaller but slower signatures");
    println!("  * ML-DSA-44 (lattice-based): ~2.1KB signatures, based on module learning with errors problem (security category 2)");
    println!("- This provides protection against future quantum computing threats to Bitcoin");
}

// Generate a deterministic simulated SPHINCS+-128s signature
fn generate_deterministic_sphincs_signature(message: &[u8]) -> Vec<u8> {
    // SPHINCS+-128s (small) signatures are ~4,124 bytes
    // This is the smallest size parameter set (more compact but slower to verify)
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

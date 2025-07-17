use io::Write;
use std::collections::{BTreeMap, BTreeSet};
use crate::Script;
use crate::taproot::{
    TaprootBuilder,
    TaprootMerkleBranch,
    NodeInfo,
    LeafVersion,
    TapNodeHash,
    TaprootBuilderError,
    TAPROOT_CONTROL_BASE_SIZE,
    TAPROOT_CONTROL_NODE_SIZE
};
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script::{
    ScriptBuf,
    Builder
};
use crate::hashes::{Hash, sha256t_hash_newtype};
use std::ops::{Deref, DerefMut};

// Create a tagged hash type for P2QRH using the "QuantumRoot" tag
sha256t_hash_newtype! {
    pub struct QuantumRootTag = hash_str("QuantumRoot");

    /// P2QRH-tagged hash with tag "QuantumRoot".
    ///
    /// This is used for computing the quantum root in P2QRH outputs.
    #[hash_newtype(forward)]
    pub struct QuantumRootHash(_);
}

/// The control byte is the same as the control byte in a P2TR control block, including the 7 bits are used to specify the tapleaf version.
/// The parity bit of the control byte is always 1 since P2QRH does not have a key-spend path.
pub const P2QRH_CONTROL_BYTE: u8 = 0xc1;

/// P2QRH leaf version will always be 0xc0
pub const P2QRH_LEAF_VERSION: u8 = 0xc0;

/// A wrapper around ScriptBuf for P2QRH (Pay to Quantum Resistant Hash) scripts.
pub struct P2qrhScriptBuf {
    inner: ScriptBuf
}

impl P2qrhScriptBuf {
    /// Creates a new P2QRH script from a ScriptBuf.
    pub fn new(inner: ScriptBuf) -> Self {
        Self { inner }
    }
    
    /// Generates P2QRH scriptPubKey output
    /// Only accepts the quantum_root (of type TapNodeHash) since keypath spend is disabled in p2qrh
    pub fn new_p2qrh(quantum_root: TapNodeHash) -> Self {
        // https://github.com/cryptoquick/bips/blob/p2qrh/bip-0360.mediawiki#scriptpubkey
        let quantum_root_hash_bytes: [u8; 32] = quantum_root.to_byte_array();
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_3)

            // automatically pre-fixes with OP_PUSHBYTES_32 (as per size of hash)
            .push_slice(&quantum_root_hash_bytes)
            
            .into_script();
        P2qrhScriptBuf::new(script)
    }

    /// Returns the script as a reference.
    pub fn as_script(&self) -> &Script {
        self.inner.as_script()
    }
}

/// A builder for P2QRH (Pay to Quantum Resistant Hash) scripts.
#[derive(Clone)]
pub struct P2qrhBuilder {
    inner: TaprootBuilder
}

impl Deref for P2qrhBuilder {
    type Target = TaprootBuilder;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for P2qrhBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl P2qrhBuilder {

    /// Creates a new P2QRH builder.
    pub fn new() -> Self {
        Self {
            inner: TaprootBuilder::new()
        }
    }

    /// Adds a leaf with standard TapScript version to the P2QRH builder.
    pub fn add_leaf(
        self,
        depth: u8,
        script: ScriptBuf
    ) -> Result<Self, P2qrhError> {
        match self.inner.add_leaf_with_ver(depth, script, LeafVersion::TapScript) {
            Ok(builder) => Ok(Self { inner: builder }),
            Err(_) => Err(P2qrhError::LeafAdditionError)
        }
    }

    /// Adds a leaf to the P2QRH builder.
    pub fn add_leaf_with_ver(
        self,
        depth: u8,
        script: ScriptBuf,
        leaf_version: LeafVersion,
    ) -> Result<Self, P2qrhError> {
        match self.inner.add_leaf_with_ver(depth, script, leaf_version) {
            Ok(builder) => Ok(Self { inner: builder }),
            Err(_) => Err(P2qrhError::LeafAdditionError)
        }
    }

    /// Finalizes the P2QRH builder.
    pub fn finalize(self) -> Result<P2qrhSpendInfo, P2qrhError> {
        let merkle_root_node_info: NodeInfo = self.inner.try_into_node_info().unwrap();
        
        // From BIP-0360:
        // Instead of the root of the Merkle tree being hashed together with the internal key in P2QRH the root is hashed by itself using the tag "QuantumRoot".
        let quantum_root = QuantumRootHash::hash(merkle_root_node_info.node_hash().as_ref());
        
        Ok(P2qrhSpendInfo {
            quantum_root: Some(quantum_root)
        })
    }

    /// Converts the P2QRH builder into a Taproot builder.
    pub fn into_inner(self) -> TaprootBuilder {
        self.inner
    }

    /// Creates a new [`TaprootSpendInfo`] from a list of scripts (with default script version) and
    /// weights of satisfaction for that script.
    ///  
    /// The weights represent the probability of each branch being taken. If probabilities/weights
    /// for each condition are known, constructing the tree as a Huffman Tree is the optimal way to
    /// minimize average case satisfaction cost. This function takes as input an iterator of
    /// `tuple(u32, ScriptBuf)` where `u32` represents the satisfaction weights of the branch. For
    /// example, [(3, S1), (2, S2), (5, S3)] would construct a [`TapTree`] that has optimal
    /// satisfaction weight when probability for S1 is 30%, S2 is 20% and S3 is 50%. 
    ///  
    /// # Errors:
    ///  
    /// - When the optimal Huffman Tree has a depth more than 128. 
    /// - If the provided list of script weights is empty.
    ///  
    /// # Edge Cases:
    ///  
    /// If the script weight calculations overflow, a sub-optimal tree may be generated. This should
    /// not happen unless you are dealing with billions of branches with weights close to 2^32.
    ///  
    /// [`TapTree`]: crate::taproot::TapTree
    pub fn with_huffman_tree<I>(script_weights: I) -> Result<Self, TaprootBuilderError>
    where
        I: IntoIterator<Item = (u32, ScriptBuf)>,
    {    
        let inner = TaprootBuilder::with_huffman_tree(script_weights)?;
        Ok(P2qrhBuilder { inner })
    }
    
}

// type alias for versioned tap script corresponding Merkle proof
type ScriptMerkleProofMap = BTreeMap<(ScriptBuf, LeafVersion), BTreeSet<TaprootMerkleBranch>>;

/// A struct for P2QRH spend information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2qrhSpendInfo {

    /// The merkle root of the script path.
    pub quantum_root: Option<QuantumRootHash>,

    /*
    /// Map from (script, leaf_version) to (sets of) [`TaprootMerkleBranch`]. More than one control
    /// block for a given script is only possible if it appears in multiple branches of the tree. In
    /// all cases, keeping one should be enough for spending funds, but we keep all of the paths so
    /// that a full tree can be constructed again from spending data if required.
    pub script_map: ScriptMerkleProofMap,
    */

}

impl P2qrhSpendInfo {

    
    /*
    /// Returns a reference to the internal script map.
    pub fn script_map(&self) -> &ScriptMerkleProofMap { &self.script_map }
    
    pub fn control_block(&self, script_ver: &(ScriptBuf, LeafVersion)) -> Option<P2qrhControlBlock> {
        // Create our own control block type that doesn't include key information
        if let Some(merkle_branch) = self.script_map().get(script_ver) {
            Some(P2qrhControlBlock {
                leaf_version: script_ver.1,
                merkle_branch: merkle_branch.iter().next().unwrap().clone(),
            })
        } else {
            None
        }
    }
    */
}

/// A control block for P2QRH (Pay to Quantum Resistant Hash) script path spending.
/// This is a simplified version of Taproot's control block that excludes key-related fields.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2qrhControlBlock {
    /// The merkle branch of the leaf.
    pub merkle_branch: TaprootMerkleBranch,
}

impl P2qrhControlBlock {

    /// Creates a new P2QRH control block.
    /// 
    /// This is a simplified version of Taproot's control block that excludes key-related fields.
    ///
    /// The merkle branch is the path from the leaf to the quantum root.
    /// 
    pub fn new(merkle_branch: TaprootMerkleBranch) -> Self {
        Self { merkle_branch }
    }

    /// Returns the size of control block. Faster and more efficient than calling
    /// `Self::serialize().len()`. Can be handy for fee estimation.
    pub fn size(&self) -> usize {
        TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * self.merkle_branch.len()
    }

    /// Serializes to a writer.
    /// ReturnsThe number of bytes written to the writer.
    pub fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&[P2QRH_CONTROL_BYTE])?;
        self.merkle_branch.encode(writer)?;
        Ok(self.size())
    }

    /// Serializes the control block.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.encode(&mut buf).expect("writers don't error");
        buf
    }

    /// Given a quantum_root and Script, verify that the merkle path found in this control block is correct.
    pub fn verify_script_in_quantum_root_path( &self,
        script: &Script,
        quantum_root: QuantumRootHash) {
        // compute the script hash
        // Initially the curr_hash is the leaf hash
        let mut curr_hash = TapNodeHash::from_script(script, LeafVersion::from_consensus(P2QRH_LEAF_VERSION).unwrap());
        
        // re-construct the merkle root referencing the merkle path found in this control block
        for elem in &self.merkle_branch {
            // Recalculate the curr hash as parent hash
            curr_hash = TapNodeHash::from_node_hashes(curr_hash, *elem);
        }

        assert_eq!(quantum_root, QuantumRootHash::hash(curr_hash.as_ref()) );
    }
}

/// An error type for P2QRH (Pay to Quantum Resistant Hash) scripts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum P2qrhError {
    /// An error that occurs when adding a leaf to the P2QRH builder.
    LeafAdditionError,
}

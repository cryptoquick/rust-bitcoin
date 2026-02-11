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
use crate::hashes::{Hash};
use std::ops::{Deref, DerefMut};

/// The control byte is the same as the control byte in a P2TR control block, including the 7 bits are used to specify the tapleaf version.
/// The parity bit of the control byte is always 1 since P2MR does not have a key-spend path.
pub const P2MR_CONTROL_BYTE: u8 = 0xc1;

/// P2MR leaf version will always be 0xc0
pub const P2MR_LEAF_VERSION: u8 = 0xc0;

/// A wrapper around ScriptBuf for P2MR (Pay to Taproot Script Hash) scripts.
pub struct P2mrScriptBuf {
    inner: ScriptBuf
}

impl P2mrScriptBuf {
    /// Creates a new P2MR script from a ScriptBuf.
    pub fn new(inner: ScriptBuf) -> Self {
        Self { inner }
    }
    
    /// Generates P2MR scriptPubKey output
    /// Only accepts the merkle_root (of type TapNodeHash) since keypath spend is disabled in p2mr
    pub fn new_p2mr(merkle_root: TapNodeHash) -> Self {

        let merkle_root_hash_bytes: [u8; 32] = merkle_root.to_byte_array();
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_2)

            // automatically pre-fixes with OP_PUSHBYTES_32 (as per size of hash)
            .push_slice(&merkle_root_hash_bytes)
            
            .into_script();
        P2mrScriptBuf::new(script)
    }

    /// Returns the script as a reference.
    pub fn as_script(&self) -> &Script {
        self.inner.as_script()
    }

    /// Returns the scriptBuf as a reference.
    pub fn as_scriptbuf(&self) -> ScriptBuf {
        self.inner.clone()
    }
}

/// A builder for P2MR (Pay to Taproot Script Hash) scripts.
#[derive(Clone)]
pub struct P2mrBuilder {
    inner: TaprootBuilder
}

impl Deref for P2mrBuilder {
    type Target = TaprootBuilder;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for P2mrBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl P2mrBuilder {

    /// Creates a new P2MR builder.
    pub fn new() -> Self {
        Self {
            inner: TaprootBuilder::new()
        }
    }

    /// Adds a leaf with standard TapScript version to the P2MR builder.
    pub fn add_leaf(
        self,
        depth: u8,
        script: ScriptBuf
    ) -> Result<Self, P2mrError> {
        match self.inner.add_leaf_with_ver(depth, script, LeafVersion::TapScript) {
            Ok(builder) => Ok(Self { inner: builder }),
            Err(_) => Err(P2mrError::LeafAdditionError)
        }
    }

    /// Adds a leaf to the P2MR builder.
    pub fn add_leaf_with_ver(
        self,
        depth: u8,
        script: ScriptBuf,
        leaf_version: LeafVersion,
    ) -> Result<Self, P2mrError> {
        match self.inner.add_leaf_with_ver(depth, script, leaf_version) {
            Ok(builder) => Ok(Self { inner: builder }),
            Err(_) => Err(P2mrError::LeafAdditionError)
        }
    }

    /// Finalizes the P2MR builder.
    pub fn finalize(self) -> Result<P2mrSpendInfo, P2mrError> {
        let merkle_root_node_info: NodeInfo = self.inner.try_into_node_info().unwrap();
        
        Ok(P2mrSpendInfo {
            merkle_root: Some(merkle_root_node_info.node_hash())
        })
    }

    /// Converts the P2MR builder into a Taproot builder.
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
        Ok(P2mrBuilder { inner })
    }
    
}

// type alias for versioned tap script corresponding Merkle proof
type ScriptMerkleProofMap = BTreeMap<(ScriptBuf, LeafVersion), BTreeSet<TaprootMerkleBranch>>;

/// A struct for P2MR spend information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2mrSpendInfo {

    /// The merkle root of the script path.
    pub merkle_root: Option<TapNodeHash>,

    /*
    /// Map from (script, leaf_version) to (sets of) [`TaprootMerkleBranch`]. More than one control
    /// block for a given script is only possible if it appears in multiple branches of the tree. In
    /// all cases, keeping one should be enough for spending funds, but we keep all of the paths so
    /// that a full tree can be constructed again from spending data if required.
    pub script_map: ScriptMerkleProofMap,
    */

}

impl P2mrSpendInfo {

    
    /*
    /// Returns a reference to the internal script map.
    pub fn script_map(&self) -> &ScriptMerkleProofMap { &self.script_map }
    
    pub fn control_block(&self, script_ver: &(ScriptBuf, LeafVersion)) -> Option<P2mrControlBlock> {
        // Create our own control block type that doesn't include key information
        if let Some(merkle_branch) = self.script_map().get(script_ver) {
            Some(P2mrControlBlock {
                leaf_version: script_ver.1,
                merkle_branch: merkle_branch.iter().next().unwrap().clone(),
            })
        } else {
            None
        }
    }
    */
}

/// A control block for P2MR (Pay to Taproot Script Hash) script path spending.
/// This is a simplified version of Taproot's control block that excludes key-related fields.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct P2mrControlBlock {
    /// The merkle branch of the leaf.
    pub merkle_branch: TaprootMerkleBranch,
}

impl P2mrControlBlock {

    /// Creates a new P2MR control block.
    /// 
    /// This is a simplified version of Taproot's control block that excludes key-related fields.
    ///
    /// The merkle branch is the path from the leaf to the merkle root.
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
        writer.write_all(&[P2MR_CONTROL_BYTE])?;
        self.merkle_branch.encode(writer)?;
        Ok(self.size())
    }

    /// Decodes a P2MR control block from a slice.
    pub fn decode(sl: &[u8]) -> Result<P2mrControlBlock, P2mrError> {
        if sl.len() < TAPROOT_CONTROL_BASE_SIZE
            || (sl.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
        {
            return Err(P2mrError::InvalidControlBlockSize(sl.len()));
        }
        let merkle_branch = TaprootMerkleBranch::decode(&sl[TAPROOT_CONTROL_BASE_SIZE..])
            .map_err(|_| P2mrError::InvalidControlBlockSize(sl.len()))?;
        Ok(P2mrControlBlock { merkle_branch })
    }

    /// Serializes the control block.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.encode(&mut buf).expect("writers don't error");
        buf
    }

    /// Given a merkle_root and Script, verify that the merkle path found in this control block is correct.
    pub fn verify_script_in_merkle_root_path( &self,
        script: &Script,
        merkle_root: TapNodeHash) {
        // compute the script hash
        // Initially the curr_hash is the leaf hash
        let mut curr_hash = TapNodeHash::from_script(script, LeafVersion::from_consensus(P2MR_LEAF_VERSION).unwrap());
        
        // re-construct the merkle root referencing the merkle path found in this control block
        for elem in &self.merkle_branch {
            // Recalculate the curr hash as parent hash
            curr_hash = TapNodeHash::from_node_hashes(curr_hash, *elem);
        }

        assert_eq!(merkle_root, curr_hash);
    }
}

/// An error type for P2MR (Pay to Taproot Script Hash) scripts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum P2mrError {
    /// An error that occurs when adding a leaf to the P2MR builder.
    LeafAdditionError,
    InvalidControlBlockSize(usize),
}

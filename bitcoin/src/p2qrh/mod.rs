use io::Write;
use std::collections::{BTreeMap, BTreeSet};
use crate::Script;
use crate::taproot::{
    TaprootBuilder,
    TaprootMerkleBranch,
    NodeInfo,
    LeafVersion,
    TapNodeHash,
    TAPROOT_CONTROL_BASE_SIZE,
    TAPROOT_CONTROL_NODE_SIZE
};
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script::{
    ScriptBuf,
    Builder
};
use crate::hashes::Hash;
use std::ops::{Deref, DerefMut};

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
    /// Only accepts the merkle_root (of type TapNodeHash) since keypath spend is disabled in p2qrh
    pub fn new_p2qrh(merkle_root: TapNodeHash) -> Self {
        // https://github.com/cryptoquick/bips/blob/p2qrh/bip-0360.mediawiki#scriptpubkey
        let merkle_root_hash_bytes: [u8; 32] = merkle_root.to_byte_array();
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_3)

            // automatically pre-fixes with OP_PUSHBYTES_32 (as per size of hash)
            .push_slice(&merkle_root_hash_bytes)
            
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
        let node_info: NodeInfo = self.inner.try_into_node_info().unwrap();
        Ok(P2qrhSpendInfo {
            merkle_root: Some(node_info.node_hash()),
            //script_map: self.inner.script_map().clone(),
        })
    }

    /// Converts the P2QRH builder into a Taproot builder.
    pub fn into_inner(self) -> TaprootBuilder {
        self.inner
    }
}

// type alias for versioned tap script corresponding Merkle proof
type ScriptMerkleProofMap = BTreeMap<(ScriptBuf, LeafVersion), BTreeSet<TaprootMerkleBranch>>;

/// A struct for P2QRH spend information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2qrhSpendInfo {

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
    /// The version of the leaf.
    pub leaf_version: LeafVersion,
    /// The merkle branch of the leaf.
    pub merkle_branch: TaprootMerkleBranch,
}

impl P2qrhControlBlock {
    /// Creates a new P2QRH control block.
    pub fn new(leaf_version: LeafVersion, merkle_branch: TaprootMerkleBranch) -> Self {
        Self { leaf_version, merkle_branch }
    }

    /// Returns the size of control block. Faster and more efficient than calling
    /// `Self::serialize().len()`. Can be handy for fee estimation.
    pub fn size(&self) -> usize {
        TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * self.merkle_branch.len()
    }

    /// Serializes to a writer.
    ///
    /// ReturnsThe number of bytes written to the writer.
    pub fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&[self.leaf_version.to_consensus() as u8])?;
        self.merkle_branch.encode(writer)?;
        Ok(self.size())
    }

    /// Serializes the control block.
    ///
    /// This would be required when using [`P2qrhControlBlock`] as a witness element while spending an
    /// output via script path. This serialization does not include the [`crate::VarInt`] prefix that would
    /// be applied when encoding this element as a witness.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.encode(&mut buf).expect("writers don't error");
        buf
    }
}

/// An error type for P2QRH (Pay to Quantum Resistant Hash) scripts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum P2qrhError {
    /// An error that occurs when adding a leaf to the P2QRH builder.
    LeafAdditionError,
}

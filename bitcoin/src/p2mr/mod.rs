// SPDX-License-Identifier: CC0-1.0

//! Pay-to-Merkle-Root (P2MR) as specified by BIP-360.
//!
//! P2MR is a witness v2 output type that commits to a merkle root of scripts without a
//! key-path spend (unlike Taproot / P2TR).
//!
//! This module originated on the p2mr branch (formerly p2qrh / p2tsh) and was carried through
//! the merge with current master. Some types were updated to match master's script/taproot API
//! (`ScriptPubKeyBuf`, `TapScriptBuf`, `TaprootMerkleBranchBuf`, etc.).

use core::fmt;
use core::ops::{Deref, DerefMut};

use io::Write;

use crate::prelude::Vec;
use crate::script::ScriptPubKeyBufExt as _;
use crate::taproot::{
    LeafVersion, TapNodeHash, TapNodeHashExt as _, TaprootBuilder, TaprootBuilderError,
    TaprootMerkleBranch, TaprootMerkleBranchBuf, TAPROOT_CONTROL_NODE_SIZE,
};
use crate::{ScriptPubKey, ScriptPubKeyBuf, TapScript, TapScriptBuf, WitnessProgram};

/// Size of the P2MR control-block header (leaf version / parity byte only; no internal key).
///
/// Note: the original 0.32 implementation reused `TAPROOT_CONTROL_BASE_SIZE` (33) in size/decode
/// while only encoding 1 header byte. That mismatch is corrected here to match the encoder.
pub const P2MR_CONTROL_BASE_SIZE: usize = 1;

/// The control byte is the same as the control byte in a P2TR control block, including the 7 bits
/// used to specify the tapleaf version.
/// The parity bit of the control byte is always 1 since P2MR does not have a key-spend path.
pub const P2MR_CONTROL_BYTE: u8 = 0xc1;

/// P2MR leaf version will always be 0xc0.
pub const P2MR_LEAF_VERSION: u8 = 0xc0;

/// A wrapper around [`ScriptPubKeyBuf`] for P2MR (Pay to Merkle Root) scripts.
pub struct P2mrScriptBuf {
    inner: ScriptPubKeyBuf,
}

impl P2mrScriptBuf {
    /// Creates a new P2MR script from a [`ScriptPubKeyBuf`].
    pub fn new(inner: ScriptPubKeyBuf) -> Self { Self { inner } }

    /// Generates P2MR scriptPubKey output.
    ///
    /// Only accepts the merkle root since keypath spend is disabled in P2MR.
    /// Encodes as witness version 2 with a 32-byte program (the merkle root).
    pub fn new_p2mr(merkle_root: TapNodeHash) -> Self {
        let script = ScriptPubKeyBuf::new_witness_program(&WitnessProgram::p2mr(merkle_root));
        Self::new(script)
    }

    /// Returns the script as a reference.
    pub fn as_script(&self) -> &ScriptPubKey { self.inner.as_script() }

    /// Returns a clone of the inner script buffer.
    pub fn as_scriptbuf(&self) -> ScriptPubKeyBuf { self.inner.clone() }
}

/// A builder for P2MR (Pay to Merkle Root) scripts.
#[derive(Clone)]
pub struct P2mrBuilder {
    inner: TaprootBuilder,
}

impl Deref for P2mrBuilder {
    type Target = TaprootBuilder;

    fn deref(&self) -> &Self::Target { &self.inner }
}

impl DerefMut for P2mrBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

impl P2mrBuilder {
    /// Creates a new P2MR builder.
    pub fn new() -> Self { Self { inner: TaprootBuilder::new() } }

    /// Adds a leaf with standard TapScript version to the P2MR builder.
    pub fn add_leaf(self, depth: u8, script: TapScriptBuf) -> Result<Self, P2mrError> {
        match self.inner.add_leaf_with_ver(depth, script, LeafVersion::TapScript) {
            Ok(builder) => Ok(Self { inner: builder }),
            Err(_) => Err(P2mrError::LeafAdditionError),
        }
    }

    /// Adds a leaf to the P2MR builder.
    pub fn add_leaf_with_ver(
        self,
        depth: u8,
        script: TapScriptBuf,
        leaf_version: LeafVersion,
    ) -> Result<Self, P2mrError> {
        match self.inner.add_leaf_with_ver(depth, script, leaf_version) {
            Ok(builder) => Ok(Self { inner: builder }),
            Err(_) => Err(P2mrError::LeafAdditionError),
        }
    }

    /// Finalizes the P2MR builder.
    pub fn finalize(self) -> Result<P2mrSpendInfo, P2mrError> {
        let merkle_root_node_info = self
            .inner
            .try_into_node_info()
            .map_err(|_| P2mrError::LeafAdditionError)?;

        Ok(P2mrSpendInfo { merkle_root: Some(merkle_root_node_info.node_hash()) })
    }

    /// Converts the P2MR builder into a Taproot builder.
    pub fn into_inner(self) -> TaprootBuilder { self.inner }

    /// Creates a new [`P2mrBuilder`] from a list of scripts (with default script version) and
    /// weights of satisfaction for that script.
    ///
    /// See [`TaprootBuilder::with_huffman_tree`] for details.
    pub fn with_huffman_tree<I>(script_weights: I) -> Result<Self, TaprootBuilderError>
    where
        I: IntoIterator<Item = (u32, TapScriptBuf)>,
    {
        let inner = TaprootBuilder::with_huffman_tree(script_weights)?;
        Ok(Self { inner })
    }
}

impl Default for P2mrBuilder {
    fn default() -> Self { Self::new() }
}

/// A struct for P2MR spend information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2mrSpendInfo {
    /// The merkle root of the script path.
    pub merkle_root: Option<TapNodeHash>,
}

/// A control block for P2MR (Pay to Merkle Root) script path spending.
///
/// This is a simplified version of Taproot's control block that excludes key-related fields.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct P2mrControlBlock {
    /// The merkle branch of the leaf.
    pub merkle_branch: TaprootMerkleBranchBuf,
}

impl P2mrControlBlock {
    /// Creates a new P2MR control block.
    ///
    /// This is a simplified version of Taproot's control block that excludes key-related fields.
    ///
    /// The merkle branch is the path from the leaf to the merkle root.
    pub fn new(merkle_branch: TaprootMerkleBranchBuf) -> Self { Self { merkle_branch } }

    /// Returns the size of control block. Faster and more efficient than calling
    /// `Self::serialize().len()`. Can be handy for fee estimation.
    pub fn size(&self) -> usize {
        P2MR_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * self.merkle_branch.len()
    }

    /// Serializes to a writer.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the writer.
    pub fn encode<W: Write + ?Sized>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write_all(&[P2MR_CONTROL_BYTE])?;
        self.merkle_branch.encode(writer)?;
        Ok(self.size())
    }

    /// Decodes a P2MR control block from a slice.
    pub fn decode(sl: &[u8]) -> Result<Self, P2mrError> {
        if sl.len() < P2MR_CONTROL_BASE_SIZE
            || (sl.len() - P2MR_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
        {
            return Err(P2mrError::InvalidControlBlockSize(sl.len()));
        }
        if sl[0] != P2MR_CONTROL_BYTE {
            return Err(P2mrError::InvalidControlBlockSize(sl.len()));
        }
        let merkle_branch = TaprootMerkleBranchBuf::decode(&sl[P2MR_CONTROL_BASE_SIZE..])
            .map_err(|_| P2mrError::InvalidControlBlockSize(sl.len()))?;
        Ok(Self { merkle_branch })
    }

    /// Serializes the control block.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.encode(&mut buf).expect("writers don't error");
        buf
    }

    /// Given a merkle_root and Script, verify that the merkle path found in this control block is
    /// correct.
    ///
    /// # Panics
    ///
    /// Panics if the reconstructed root does not match `merkle_root`.
    pub fn verify_script_in_merkle_root_path(&self, script: &TapScript, merkle_root: TapNodeHash) {
        // Initially the curr_hash is the leaf hash
        let mut curr_hash = TapNodeHash::from_script(
            script,
            LeafVersion::from_consensus(P2MR_LEAF_VERSION).expect("0xc0 is valid"),
        );

        // re-construct the merkle root referencing the merkle path found in this control block
        for elem in &self.merkle_branch {
            curr_hash = TapNodeHash::from_node_hashes(curr_hash, *elem);
        }

        assert_eq!(merkle_root, curr_hash);
    }

    /// Returns a borrowed view of the merkle branch.
    pub fn merkle_branch(&self) -> &TaprootMerkleBranch { self.merkle_branch.as_ref() }
}

/// An error type for P2MR (Pay to Merkle Root) scripts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum P2mrError {
    /// An error that occurs when adding a leaf to the P2MR builder.
    LeafAdditionError,
    /// Control block had an invalid length or header byte.
    InvalidControlBlockSize(usize),
}

impl fmt::Display for P2mrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeafAdditionError => write!(f, "failed to add leaf to P2MR builder"),
            Self::InvalidControlBlockSize(len) => {
                write!(f, "invalid P2MR control block size: {}", len)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for P2mrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LeafAdditionError | Self::InvalidControlBlockSize(_) => None,
        }
    }
}

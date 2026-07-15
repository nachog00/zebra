//! Compact transaction representation for indexers.
//!
//! Parses the same wire format as [`Transaction`] but skips proofs,
//! signatures, and input unlock scripts — extracting only the fields
//! needed for building indexes (outpoints, values, nullifiers, note
//! commitments, ephemeral keys).
//!
//! Reuses zebra-chain's existing deserialization for individual fields
//! (OutPoint, CompactSizeMessage, etc.) and only hand-rolls the skip
//! logic for known-size proof/signature sections.

use std::io::{self, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::{
    block,
    serialization::{CompactSizeMessage, ReadZcashExt, SerializationError, ZcashDeserialize, ZcashDeserializeInto},
    transparent,
};

/// A compact representation of a transaction for indexing purposes.
#[derive(Debug, Clone)]
pub struct CompactTransaction {
    /// Transparent inputs — only the outpoint (prev_hash + prev_index).
    pub transparent_inputs: Vec<transparent::OutPoint>,
    /// Transparent outputs — value + lock_script.
    pub transparent_outputs: Vec<CompactOutput>,
    /// Sapling nullifiers.
    pub sapling_nullifiers: Vec<[u8; 32]>,
    /// Sapling outputs — cmu + ephemeral_key + first 52 bytes of enc_ciphertext.
    pub sapling_outputs: Vec<CompactSaplingOutput>,
    /// Orchard actions — nullifier + cmx + ephemeral_key + first 52 bytes of enc_ciphertext.
    pub orchard_actions: Vec<CompactOrchardAction>,
}

/// Compact transparent output: value + script.
#[derive(Debug, Clone)]
pub struct CompactOutput {
    /// Value in zatoshis.
    pub value: u64,
    /// Lock script bytes.
    pub script: Vec<u8>,
}

/// Compact Sapling output.
#[derive(Debug, Clone)]
pub struct CompactSaplingOutput {
    /// Note commitment (cmu).
    pub cmu: [u8; 32],
    /// Ephemeral key.
    pub ephemeral_key: [u8; 32],
    /// First 52 bytes of the encrypted ciphertext.
    pub enc_ciphertext_head: [u8; 52],
}

/// Compact Orchard action.
#[derive(Debug, Clone)]
pub struct CompactOrchardAction {
    /// Nullifier.
    pub nullifier: [u8; 32],
    /// Note commitment (cmx).
    pub cmx: [u8; 32],
    /// Ephemeral key.
    pub ephemeral_key: [u8; 32],
    /// First 52 bytes of the encrypted ciphertext.
    pub enc_ciphertext_head: [u8; 52],
}

/// A compact block: header + compact transactions.
#[derive(Debug, Clone)]
pub struct CompactBlock {
    /// Block header.
    pub header: block::Header,
    /// Block hash.
    pub hash: block::Hash,
    /// Block height.
    pub height: block::Height,
    /// Compact transactions.
    pub transactions: Vec<CompactTransaction>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Skip exactly `n` bytes from the reader.
fn skip<R: Read>(reader: &mut R, n: usize) -> Result<(), SerializationError> {
    const CHUNK: usize = 4096;
    let mut remaining = n;
    let mut buf = [0u8; CHUNK];
    while remaining > 0 {
        let to_read = remaining.min(CHUNK);
        reader.read_exact(&mut buf[..to_read])?;
        remaining -= to_read;
    }
    Ok(())
}

fn read_compactsize<R: Read>(reader: &mut R) -> Result<usize, SerializationError> {
    let cs: CompactSizeMessage = reader.zcash_deserialize_into()?;
    Ok(cs.into())
}

// ---------------------------------------------------------------------------
// Transparent parsing — reuses zebra's OutPoint
// ---------------------------------------------------------------------------

/// Parse transparent inputs: keep OutPoint, skip unlock_script + sequence.
fn parse_compact_inputs<R: Read>(
    reader: &mut R,
) -> Result<Vec<transparent::OutPoint>, SerializationError> {
    let count = read_compactsize(reader)?;
    let mut inputs = Vec::with_capacity(count);

    for _ in 0..count {
        // Reuse zebra's OutPoint deserialize (32-byte hash + u32 index).
        let outpoint = transparent::OutPoint::zcash_deserialize(&mut *reader)?;

        let is_coinbase = outpoint.hash == crate::transaction::Hash([0; 32])
            && outpoint.index == 0xffff_ffff;

        // Skip unlock_script (CompactSize length + bytes).
        let script_len = read_compactsize(reader)?;
        skip(reader, script_len)?;
        // Skip sequence (4 bytes).
        skip(reader, 4)?;

        if !is_coinbase {
            inputs.push(outpoint);
        }
    }

    Ok(inputs)
}

/// Parse transparent outputs: value + lock_script.
fn parse_compact_outputs<R: Read>(
    reader: &mut R,
) -> Result<Vec<CompactOutput>, SerializationError> {
    let count = read_compactsize(reader)?;
    let mut outputs = Vec::with_capacity(count);

    for _ in 0..count {
        let value = reader.read_u64::<LittleEndian>()?;
        let script_len = read_compactsize(reader)?;
        let mut script = vec![0u8; script_len];
        reader.read_exact(&mut script)?;
        outputs.push(CompactOutput { value, script });
    }

    Ok(outputs)
}

// ---------------------------------------------------------------------------
// V4 Sapling (per-spend layout)
// ---------------------------------------------------------------------------

fn parse_v4_sapling_spends<R: Read>(
    reader: &mut R,
    count: usize,
) -> Result<Vec<[u8; 32]>, SerializationError> {
    let mut nullifiers = Vec::with_capacity(count);
    for _ in 0..count {
        skip(reader, 32)?; // cv
        skip(reader, 32)?; // anchor
        let nullifier = reader.read_32_bytes()?;
        nullifiers.push(nullifier);
        skip(reader, 32)?; // rk
        skip(reader, 192)?; // zkproof
        skip(reader, 64)?; // spend_auth_sig
    }
    Ok(nullifiers)
}

fn parse_v4_sapling_outputs<R: Read>(
    reader: &mut R,
    count: usize,
) -> Result<Vec<CompactSaplingOutput>, SerializationError> {
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        skip(reader, 32)?; // cv
        let cmu = reader.read_32_bytes()?;
        let ephemeral_key = reader.read_32_bytes()?;
        let mut enc_ciphertext_head = [0u8; 52];
        reader.read_exact(&mut enc_ciphertext_head)?;
        skip(reader, 580 - 52)?; // rest of enc_ciphertext
        skip(reader, 80)?; // out_ciphertext
        skip(reader, 192)?; // zkproof
        outputs.push(CompactSaplingOutput {
            cmu,
            ephemeral_key,
            enc_ciphertext_head,
        });
    }
    Ok(outputs)
}

// ---------------------------------------------------------------------------
// V5 Sapling (split prefix/proof layout)
// ---------------------------------------------------------------------------

fn parse_v5_sapling_spend_prefixes<R: Read>(
    reader: &mut R,
    count: usize,
) -> Result<Vec<[u8; 32]>, SerializationError> {
    let mut nullifiers = Vec::with_capacity(count);
    for _ in 0..count {
        // V5 SpendPrefix: cv(32) + nullifier(32) + rk(32).
        skip(reader, 32)?; // cv
        let nullifier = reader.read_32_bytes()?;
        nullifiers.push(nullifier);
        skip(reader, 32)?; // rk
    }
    Ok(nullifiers)
}

fn parse_v5_sapling_output_prefixes<R: Read>(
    reader: &mut R,
    count: usize,
) -> Result<Vec<CompactSaplingOutput>, SerializationError> {
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        // V5 OutputPrefix: cv(32) + cmu(32) + epk(32) + enc_ciphertext(580) + out_ciphertext(80).
        skip(reader, 32)?; // cv
        let cmu = reader.read_32_bytes()?;
        let ephemeral_key = reader.read_32_bytes()?;
        let mut enc_ciphertext_head = [0u8; 52];
        reader.read_exact(&mut enc_ciphertext_head)?;
        skip(reader, 580 - 52)?;
        skip(reader, 80)?;
        outputs.push(CompactSaplingOutput {
            cmu,
            ephemeral_key,
            enc_ciphertext_head,
        });
    }
    Ok(outputs)
}

// ---------------------------------------------------------------------------
// V5 Orchard
// ---------------------------------------------------------------------------

fn parse_v5_orchard_actions<R: Read>(
    reader: &mut R,
    count: usize,
) -> Result<Vec<CompactOrchardAction>, SerializationError> {
    let mut actions = Vec::with_capacity(count);
    for _ in 0..count {
        // Action: cv(32) + nullifier(32) + rk(32) + cmx(32) + epk(32) + enc_ciphertext(580) + out_ciphertext(80).
        skip(reader, 32)?; // cv
        let nullifier = reader.read_32_bytes()?;
        skip(reader, 32)?; // rk
        let cmx = reader.read_32_bytes()?;
        let ephemeral_key = reader.read_32_bytes()?;
        let mut enc_ciphertext_head = [0u8; 52];
        reader.read_exact(&mut enc_ciphertext_head)?;
        skip(reader, 580 - 52)?;
        skip(reader, 80)?;
        actions.push(CompactOrchardAction {
            nullifier,
            cmx,
            ephemeral_key,
            enc_ciphertext_head,
        });
    }
    Ok(actions)
}

// ---------------------------------------------------------------------------
// Top-level transaction parsers
// ---------------------------------------------------------------------------

fn parse_compact_v4<R: Read>(reader: &mut R) -> Result<CompactTransaction, SerializationError> {
    // nVersionGroupId.
    reader.read_u32::<LittleEndian>()?;

    let transparent_inputs = parse_compact_inputs(reader)?;
    let transparent_outputs = parse_compact_outputs(reader)?;

    // lock_time(4) + expiry_height(4).
    skip(reader, 8)?;

    // valueBalanceSapling (8 bytes).
    skip(reader, 8)?;

    let spend_count = read_compactsize(reader)?;
    let sapling_nullifiers = parse_v4_sapling_spends(reader, spend_count)?;

    let output_count = read_compactsize(reader)?;
    let sapling_outputs = parse_v4_sapling_outputs(reader, output_count)?;

    // JoinSplit — skip.
    let joinsplit_count = read_compactsize(reader)?;
    if joinsplit_count > 0 {
        // Groth16 JoinSplit: 1698 bytes each + pubkey(32) + sig(64).
        skip(reader, joinsplit_count * 1698 + 96)?;
    }

    // bindingSigSapling.
    if spend_count > 0 || output_count > 0 {
        skip(reader, 64)?;
    }

    Ok(CompactTransaction {
        transparent_inputs,
        transparent_outputs,
        sapling_nullifiers,
        sapling_outputs,
        orchard_actions: Vec::new(),
    })
}

fn parse_compact_v5<R: Read>(reader: &mut R) -> Result<CompactTransaction, SerializationError> {
    // nVersionGroupId(4) + nConsensusBranchId(4) + lock_time(4) + nExpiryHeight(4).
    skip(reader, 16)?;

    let transparent_inputs = parse_compact_inputs(reader)?;
    let transparent_outputs = parse_compact_outputs(reader)?;

    // --- Sapling ---
    let spend_count = read_compactsize(reader)?;
    let sapling_nullifiers = parse_v5_sapling_spend_prefixes(reader, spend_count)?;

    let output_count = read_compactsize(reader)?;
    let sapling_outputs = parse_v5_sapling_output_prefixes(reader, output_count)?;

    if spend_count > 0 || output_count > 0 {
        skip(reader, 8)?; // valueBalanceSapling
        if spend_count > 0 {
            skip(reader, 32)?; // anchorSapling
        }
        skip(reader, 192 * spend_count)?; // vSpendProofsSapling
        skip(reader, 64 * spend_count)?; // vSpendAuthSigsSapling
        skip(reader, 192 * output_count)?; // vOutputProofsSapling
        skip(reader, 64)?; // bindingSigSapling
    }

    // --- Orchard ---
    let action_count = read_compactsize(reader)?;
    let orchard_actions = parse_v5_orchard_actions(reader, action_count)?;

    if action_count > 0 {
        // flagsOrchard(1) + valueBalanceOrchard(8) + anchorOrchard(32).
        skip(reader, 41)?;
        // sizeProofsOrchard (CompactSize) + proofsOrchard (variable).
        let proof_size = read_compactsize(reader)?;
        skip(reader, proof_size)?;
        // vSpendAuthSigsOrchard (64 * action_count).
        skip(reader, 64 * action_count)?;
        // bindingSigOrchard (64).
        skip(reader, 64)?;
    }

    Ok(CompactTransaction {
        transparent_inputs,
        transparent_outputs,
        sapling_nullifiers,
        sapling_outputs,
        orchard_actions,
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Deserialize a transaction from raw bytes in compact form.
///
/// Supports V1–V5. Skips proofs, signatures, and input unlock scripts.
pub fn compact_deserialize(bytes: &[u8]) -> Result<CompactTransaction, SerializationError> {
    let mut reader = io::Cursor::new(bytes);

    const LOW_31_BITS: u32 = (1 << 31) - 1;
    let header = reader.read_u32::<LittleEndian>()?;
    let version = header & LOW_31_BITS;
    let overwintered = header >> 31 != 0;

    match (version, overwintered) {
        (1, false) | (2, false) | (3, true) => {
            if version >= 3 {
                reader.read_u32::<LittleEndian>()?; // nVersionGroupId
            }
            let transparent_inputs = parse_compact_inputs(&mut reader)?;
            let transparent_outputs = parse_compact_outputs(&mut reader)?;
            Ok(CompactTransaction {
                transparent_inputs,
                transparent_outputs,
                sapling_nullifiers: Vec::new(),
                sapling_outputs: Vec::new(),
                orchard_actions: Vec::new(),
            })
        }
        (4, true) => parse_compact_v4(&mut reader),
        (5, true) => parse_compact_v5(&mut reader),
        _ => Err(SerializationError::Parse("unsupported transaction version for compact deserialize")),
    }
}

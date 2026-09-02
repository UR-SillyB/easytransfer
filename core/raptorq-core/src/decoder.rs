use crate::{ObjectMeta, Result, Symbol};
use raptorq::{EncodingPacket, PayloadId, SourceBlockDecoder};
use std::collections::HashSet;

/// Per-source-block reconstruction state.
struct BlockState {
    decoder: SourceBlockDecoder,
    decoded: Option<Vec<u8>>,
    /// Mirror the upstream decoder's private ESI set so callers can distinguish
    /// a genuinely new equation from a camera re-reading the same displayed QR.
    seen_esi: HashSet<u32>,
}

/// RaptorQ decoder for a single object.
///
/// Accepts symbols in any order via [`Decoder::add_symbol`]; once a source
/// block has collected enough independent symbols it is decoded lazily. Use
/// [`Decoder::block_progress`] to query how many distinct symbols a block has
/// received, and [`Decoder::try_decode`] / [`Decoder::is_complete`] /
/// [`Decoder::assemble`] to obtain the result.
pub struct Decoder {
    meta: ObjectMeta,
    blocks: Vec<BlockState>,
}

impl Decoder {
    /// Bound hostile/non-decodable repair streams. A conforming RaptorQ object
    /// normally finishes at K plus only a handful of repair symbols; 25% or 64
    /// symbols (whichever is larger) leaves generous channel overhead while
    /// preventing the 24-bit ESI space from becoming a memory/CPU budget.
    fn symbol_budget(k: u32) -> u32 {
        k.saturating_add((k / 4).max(64))
    }

    /// Create a decoder from object metadata (typically received out-of-band
    /// via the first QR frame's header, or reconstructed from a resume file).
    pub fn new(meta: ObjectMeta) -> Result<Self> {
        meta.validate().map_err(crate::Error::InvalidObjectMeta)?;
        let oti = meta.oti();
        let blocks = meta
            .blocks
            .iter()
            .map(|b| BlockState {
                decoder: SourceBlockDecoder::new(b.sbn as u8, &oti, b.block_length),
                decoded: None,
                seen_esi: HashSet::new(),
            })
            .collect();
        Ok(Self { meta, blocks })
    }

    #[inline]
    pub fn meta(&self) -> &ObjectMeta {
        &self.meta
    }

    /// Number of distinct symbols received so far for block `sbn`.
    ///
    /// Note: the underlying decoder counts *unique* ESI, which is exactly what
    /// we want for de-duplication / progress reporting.
    pub fn block_progress(&self, sbn: u32) -> Option<u32> {
        // raptorq does not expose received_source_symbols publicly; the precise
        // received-symbol count is tracked at the transfer-engine layer. Here
        // we report K once the block is decoded, else None.
        let b = self.blocks.get(sbn as usize)?;
        let k = self.meta.blocks[sbn as usize].num_source_symbols;
        if b.decoded.is_some() {
            Some(k)
        } else {
            None
        }
    }

    /// Feed a symbol (source or repair, any order, duplicates allowed).
    ///
    /// Returns `Ok(true)` if this symbol caused the whole object to become
    /// decodable, `Ok(false)` otherwise.
    pub fn add_symbol(&mut self, symbol: &Symbol) -> Result<bool> {
        self.add_symbol_with_novelty(symbol)
            .map(|(complete, _novel)| complete)
    }

    /// Feed a symbol and also report whether it contributed a previously
    /// unseen ESI to an unfinished source block. The second result is false for
    /// duplicates, malformed symbols, and symbols targeting an already-decoded
    /// block; those frames must not inflate progress or throughput counters.
    pub fn add_symbol_with_novelty(&mut self, symbol: &Symbol) -> Result<(bool, bool)> {
        let sbn = symbol.id.sbn as usize;
        if sbn >= self.blocks.len() {
            // Same class as the out-of-range ESI / wrong-symbol-size drops
            // below: a hostile or corrupt coordinate, not an unusable decoder.
            // Returning Err here cost the caller its whole chunk decoder (the
            // AF2 receiver drops the slot on Err), so one crafted frame
            // carrying a valid object_id and a bogus SBN could destroy an
            // in-progress chunk repeatedly and stall the transfer for good.
            return Ok((self.is_complete(), false));
        }
        // Defensive: drop hostile symbol coordinates that would panic raptorq.
        // `PayloadId::new` asserts ESI < 2^24, and sub-block unpacking slices
        // `symbol_size` bytes out of the payload — a short/oversized payload is
        // an out-of-range slice. A fountain code just needs other symbols, so
        // silently ignoring a malformed one is safe. This guards both the live
        // path and the cache-replay path (which also calls add_symbol).
        if symbol.id.esi >= (1 << 24) || symbol.data.len() != self.meta.symbol_size as usize {
            return Ok((self.is_complete(), false));
        }
        let block = &mut self.blocks[sbn];
        if block.decoded.is_some() {
            // Already reconstructed; ignore further symbols for this block.
            return Ok((self.is_complete(), false));
        }
        if block.seen_esi.contains(&symbol.id.esi) {
            return Ok((self.is_complete(), false));
        }
        let k = self.meta.blocks[sbn].num_source_symbols;
        let limit = Self::symbol_budget(k);
        if block.seen_esi.len() >= limit as usize {
            return Err(crate::Error::SymbolBudgetExceeded {
                sbn: symbol.id.sbn,
                limit,
            });
        }
        block.seen_esi.insert(symbol.id.esi);
        // `SourceBlockDecoder::decode` both ingests the packet and attempts
        // reconstruction in one call (it is safe to call repeatedly; it keeps
        // all previously-seen symbols internally and re-runs the solver).
        let pkt = EncodingPacket::new(
            PayloadId::new(symbol.id.sbn as u8, symbol.id.esi),
            symbol.data.clone(),
        );
        if let Some(result) = block.decoder.decode(std::iter::once(pkt)) {
            block.decoded = Some(result);
        }
        Ok((self.is_complete(), true))
    }

    /// True once every source block has been reconstructed.
    pub fn is_complete(&self) -> bool {
        self.blocks.iter().all(|b| b.decoded.is_some())
    }

    /// Number of source blocks fully reconstructed.
    pub fn decoded_block_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.decoded.is_some()).count()
    }

    /// Reassemble the original object. Returns `None` until complete.
    pub fn assemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut out = Vec::with_capacity(self.meta.transfer_length as usize);
        for b in &self.blocks {
            out.extend_from_slice(b.decoded.as_ref().unwrap());
        }
        out.truncate(self.meta.transfer_length as usize);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Encoder};

    fn random_data(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| ((i * 1103515245 + 12345) & 0xff) as u8)
            .collect()
    }

    fn encode_decode(
        data: &[u8],
        drop_pct: u32,
        duplicate: bool,
        shuffle: bool,
    ) -> Option<Vec<u8>> {
        let enc = Encoder::new(data, Config::default()).unwrap();
        let meta = enc.meta().clone();

        // Collect all source symbols from every block + ~50% repair overhead.
        let mut syms: Vec<Symbol> = Vec::new();
        for sbn in 0..enc.num_blocks() as u32 {
            let k = meta.blocks[sbn as usize].num_source_symbols;
            syms.extend(enc.source_symbols(sbn).unwrap());
            syms.extend(enc.repair_symbols(sbn, 0, k / 2 + 1).unwrap());
            let _ = k;
        }

        if duplicate {
            let extra: Vec<Symbol> = syms.iter().take(5).cloned().collect();
            syms.extend(extra);
        }
        if shuffle {
            // Simple deterministic shuffle.
            let n = syms.len();
            for i in (1..n).rev() {
                let j = (i.wrapping_mul(2654435761)) % (i + 1);
                syms.swap(i, j);
            }
        }
        if drop_pct > 0 {
            // Deterministic drop: keep symbols whose (index % 100) >= drop_pct.
            syms = syms
                .into_iter()
                .enumerate()
                .filter(|(i, _)| (*i as u32 % 100) >= drop_pct)
                .map(|(_, s)| s)
                .collect();
        }

        let mut dec = Decoder::new(meta).unwrap();
        for s in &syms {
            dec.add_symbol(s).unwrap();
        }
        dec.assemble()
    }

    #[test]
    fn decodes_lossless() {
        let data = random_data(70_000);
        let got = encode_decode(&data, 0, false, false).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn decodes_with_duplicates_and_shuffle() {
        let data = random_data(35_000);
        let got = encode_decode(&data, 0, true, true).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn reports_duplicate_esi_without_progress() {
        let data = random_data(8_000);
        let enc = Encoder::new(&data, Config::default()).unwrap();
        let symbol = enc.source_symbols(0).unwrap().remove(0);
        let mut dec = Decoder::new(enc.meta().clone()).unwrap();
        let (_complete, novel) = dec.add_symbol_with_novelty(&symbol).unwrap();
        assert!(novel);
        let (_complete, novel) = dec.add_symbol_with_novelty(&symbol).unwrap();
        assert!(!novel, "same (sbn, esi) must not inflate progress");
    }

    #[test]
    fn rejects_unbounded_unique_repair_stream() {
        let data = random_data(4_096);
        let enc = Encoder::new(&data, Config::default()).unwrap();
        let meta = enc.meta().clone();
        let k = meta.blocks[0].num_source_symbols;
        let limit = Decoder::symbol_budget(k);
        let mut dec = Decoder::new(meta).unwrap();
        // Seed only the wrapper's hostile-input ledger: this models an upstream
        // decoder that has retained the maximum allowed non-decodable equations
        // without relying on a particular RaptorQ rank outcome in the test.
        dec.blocks[0].seen_esi.extend(0..limit);
        let extra = Symbol::new(0, k + limit, vec![0; 1024]);
        assert!(matches!(
            dec.add_symbol_with_novelty(&extra),
            Err(crate::Error::SymbolBudgetExceeded { .. })
        ));
    }

    #[test]
    fn decodes_with_some_drops() {
        // With 50% repair overhead the codec should still recover a modest
        // number of dropped source symbols.
        let data = random_data(35_000);
        let got = encode_decode(&data, 20, true, true).expect("should recover at 20% drop");
        assert_eq!(got, data);
    }

    #[test]
    fn out_of_range_sbn_is_dropped_without_killing_the_decoder() {
        // The AF2 receiver drops its whole chunk-decoder slot when this call
        // returns Err, so a hostile SBN must be ignored like any other
        // malformed coordinate — otherwise one crafted frame stalls the chunk
        // permanently. Accumulated symbols must survive it.
        let data = random_data(4_096);
        let enc = Encoder::new(&data, Config::default()).unwrap();
        let good = enc.source_symbols(0).unwrap().remove(0);
        let mut dec = Decoder::new(enc.meta().clone()).unwrap();
        let (_complete, novel) = dec.add_symbol_with_novelty(&good).unwrap();
        assert!(novel);

        let blocks = dec.blocks.len() as u32;
        let hostile = Symbol::new(blocks + 7, 0, vec![0; dec.meta.symbol_size as usize]);
        let (_complete, novel) = dec
            .add_symbol_with_novelty(&hostile)
            .expect("an out-of-range SBN must not be a decoder-fatal error");
        assert!(!novel, "a dropped symbol must not inflate progress");

        // The previously accepted symbol is still there.
        assert!(dec.blocks[0].seen_esi.contains(&good.id.esi));
    }
}

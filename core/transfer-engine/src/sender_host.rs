//! Host-agnostic sender session wrapper shared by the thin FFI bindings.
//!
//! The WASM binding (`wasm.rs`) carries its own copy of this logic against
//! `js_sys` types; this module is the portable home used by the Android JNI
//! binding (`jni_sender.rs`). Everything here is plain Rust — no JNI, no
//! wasm-bindgen — so the packing format and playlist semantics are unit-testable
//! on any host (`cargo test -p transfer-engine`).
//!
//! ## Packed QR batch wire format (host-side, mirrors `next_qr_scratch`)
//! `u32le tile_count`, then per tile `u32le side` + `side²` bytes of 0/1 QR
//! modules (1 = dark). Raw AF2 frame bytes never cross the FFI on the hot
//! path — only the rendered bit matrix does (SPEC §9 thin-host division).

use af2::{Af2Sender, SenderConfig, SenderError};

/// Upper bound on simultaneously rendered QR tiles (matches the web sender).
pub const MAX_UI_QR_COUNT: usize = 4;
const MAX_QR_SIDE_MODULES: usize = 177;
/// Scratch capacity for one packed batch: count word + per-tile side+matrix.
pub const QR_BATCH_MAX_BYTES: usize =
    4 + MAX_UI_QR_COUNT * (4 + MAX_QR_SIDE_MODULES * MAX_QR_SIDE_MODULES);

/// Error from [`SenderSession::next_qr_batch`]. `NotStaged` carries the chunk
/// index the host must stage before retrying (the failed call has no side
/// effects — see `Af2Sender::next_frame`'s transactional contract).
#[derive(Debug, PartialEq, Eq)]
pub enum NextQrError {
    NotStaged(u32),
    Failed(String),
}

/// A streaming AF2 sender plus the per-session counters the stats JSON needs.
/// NOT thread-safe: hosts serialize all calls on the handle (same contract as
/// the receiver session).
pub struct SenderSession {
    inner: Af2Sender,
    frames_emitted: u64,
    bytes_emitted: u64,
    start_ms: u64,
}

impl SenderSession {
    /// Streamed (bounded-memory) build from hash-only metadata — the
    /// `SenderBuilderWasm::build_streamed` equivalent. `metas` is
    /// `(kind, path, content_size, BLAKE3-256 of content)`; `chunk_hashes`
    /// holds one BLAKE3-256 per canonical chunk, position-indexed.
    pub fn new_streamed(
        metas: Vec<(u8, String, u64, [u8; 32])>,
        config: SenderConfig,
        chunk_hashes: Vec<[u8; 32]>,
    ) -> Result<Self, String> {
        let manifest =
            af2::manifest::build_manifest_from_hashes(metas, config.chunk_raw_size, chunk_hashes)
                .map_err(|e| format!("AF2 streamed manifest build failed: {e}"))?;
        let inner = Af2Sender::from_manifest_streamed(manifest, config)
            .map_err(|e| format!("AF2 streamed sender build failed: {e}"))?;
        Ok(Self {
            inner,
            frames_emitted: 0,
            bytes_emitted: 0,
            start_ms: crate::time::now_ms(),
        })
    }

    pub fn transfer_id_hex(&self) -> String {
        hex_lower(&self.inner.transfer_id())
    }

    pub fn content_id_hex(&self) -> String {
        hex_lower(&self.inner.content_id())
    }

    pub fn stats_json(&self) -> String {
        let elapsed_ms = crate::time::now_ms().saturating_sub(self.start_ms).max(1);
        let fps = self.frames_emitted as f64 / (elapsed_ms as f64 / 1000.0);
        let throughput_bps = self.bytes_emitted as f64 / (elapsed_ms as f64 / 1000.0);
        format!(
            r#"{{"frames":{},"fps":{:.1},"throughput_bps":{:.0},"bytes":{},"elapsed_ms":{}}}"#,
            self.frames_emitted, fps, throughput_bps, self.bytes_emitted, elapsed_ms
        )
    }

    /// Pull up to `count` frames, QR-encode each, and return the packed batch
    /// (format above). A chunk boundary mid-batch shortens the batch rather
    /// than failing: the frames already pulled are committed and MUST be
    /// rendered — only an empty batch reports `NotStaged` (the host's
    /// stage-and-retry signal).
    pub fn next_qr_batch(&mut self, count: u32) -> Result<Vec<u8>, NextQrError> {
        let n = (count as usize).clamp(1, MAX_UI_QR_COUNT);
        let mut out = vec![0u8; 4]; // tile_count patched at the end
        let mut produced = 0u32;
        for _ in 0..n {
            let frame_bytes = match self.inner.next_frame() {
                Ok(f) => f,
                Err(SenderError::ChunkNotStaged(index)) => {
                    if produced == 0 {
                        return Err(NextQrError::NotStaged(index));
                    }
                    break;
                }
                Err(e) => {
                    return Err(NextQrError::Failed(format!(
                        "AF2 frame generation failed: {e}"
                    )));
                }
            };
            self.frames_emitted = self.frames_emitted.saturating_add(1);
            self.bytes_emitted = self.bytes_emitted.saturating_add(frame_bytes.len() as u64);
            let matrix = qr_protocol::qr_render::encode(&frame_bytes)
                .map_err(|e| NextQrError::Failed(format!("qr encode failed: {e:?}")))?;
            debug_assert!(matrix.size <= MAX_QR_SIDE_MODULES);
            out.extend_from_slice(&(matrix.size as u32).to_le_bytes());
            out.extend(matrix.modules.iter().map(|&dark| dark as u8));
            produced += 1;
        }
        out[..4].copy_from_slice(&produced.to_le_bytes());
        Ok(out)
    }

    /// Provide one chunk's encoded bytes (see `Af2Sender::stage_chunk`).
    /// `raw_hash` (32 bytes) is the host-precomputed BLAKE3 of the RAW chunk,
    /// keeping the in-core hash off the render thread; `None` hashes in-core.
    pub fn stage_chunk(
        &mut self,
        index: u32,
        codec_id: u8,
        bytes: Vec<u8>,
        raw_hash: Option<[u8; 32]>,
    ) -> Result<(), String> {
        let result = match raw_hash {
            Some(digest) => self
                .inner
                .stage_chunk_with_raw_hash(index, codec_id, bytes, digest),
            None => self.inner.stage_chunk(index, codec_id, bytes),
        };
        result.map_err(|e| format!("AF2 stage_chunk failed: {e}"))
    }

    /// Playlist position hint: `Some(chunk)` inside a chunk window, `None`
    /// during bootstrap. Hosts prefetch the next chunk from this.
    pub fn current_chunk_index(&self) -> Option<u32> {
        self.inner.current_chunk_index()
    }

    /// 1-based broadcast epoch.
    pub fn epoch(&self) -> u32 {
        self.inner.epoch()
    }

    /// True while chunk `index` still holds prefetched staged bytes.
    pub fn is_staged(&self, index: u32) -> bool {
        self.inner.is_staged(index)
    }
}

/// JSON-serialize [`af2::plan_chunks`] as `{"chunks":[[item,start,len,...],...]}`
/// (flat triples per chunk — numbers only, no string escaping needed).
pub fn plan_chunks_json(
    metas: &[(u8, String, u64)],
    chunk_raw_size: u32,
) -> Result<String, String> {
    let plan = af2::plan_chunks(metas, chunk_raw_size).map_err(|e| e.to_string())?;
    let mut out = String::from("{\"chunks\":[");
    for (ci, segs) in plan.iter().enumerate() {
        if ci > 0 {
            out.push(',');
        }
        out.push('[');
        for (si, seg) in segs.iter().enumerate() {
            if si > 0 {
                out.push(',');
            }
            out.push_str(&format!("{},{},{}", seg.item, seg.start, seg.len));
        }
        out.push(']');
    }
    out.push_str("]}");
    Ok(out)
}

/// [`af2::chunk::encode_chunk_balanced`] packed into one buffer:
/// `[codec_id: 1 byte][encoded data...]`, so FFI hosts need no return struct.
pub fn encode_chunk_balanced_packed(raw: &[u8], channel_bps: u64, force_full: bool) -> Vec<u8> {
    let (codec_id, data) = af2::chunk::encode_chunk_balanced(raw, channel_bps, force_full);
    let mut out = Vec::with_capacity(1 + data.len());
    out.push(codec_id);
    out.extend_from_slice(&data);
    out
}

/// Parse a packed hash table (`32 × N` bytes) into position-indexed digests.
pub fn parse_hash_table(bytes: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if bytes.len() % 32 != 0 {
        return Err(format!(
            "hash table length {} is not a multiple of 32",
            bytes.len()
        ));
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|c| {
            let mut d = [0u8; 32];
            d.copy_from_slice(c);
            d
        })
        .collect())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use af2::id::{new_hasher, KIND_UTF8_TEXT};

    fn hash32(data: &[u8]) -> [u8; 32] {
        let mut h = new_hasher();
        h.update(data);
        *h.finalize().as_bytes()
    }

    /// Build a real one-chunk streamed sender for `content` and return it
    /// with the staged chunk bytes (host side of the full prep pipeline).
    fn build_one_chunk_sender(content: &[u8]) -> (SenderSession, Vec<u8>) {
        let metas = vec![(KIND_UTF8_TEXT, "msg.txt".to_string(), content.len() as u64)];
        // Single short input ⇒ exactly one chunk with one segment.
        let json = plan_chunks_json(&metas, 8 * 1024 * 1024).unwrap();
        assert_eq!(json, format!("{{\"chunks\":[[0,0,{}]]}}", content.len()));
        let chunk_hashes = vec![hash32(content)];
        let session = SenderSession::new_streamed(
            vec![(
                KIND_UTF8_TEXT,
                "msg.txt".to_string(),
                content.len() as u64,
                hash32(content),
            )],
            SenderConfig {
                symbol_size: 512,
                chunk_raw_size: 8 * 1024 * 1024,
                redundancy_pct: 10,
            },
            chunk_hashes,
        )
        .unwrap();
        (session, content.to_vec())
    }

    #[test]
    fn packed_batch_layout_round_trips() {
        let (mut session, raw) = build_one_chunk_sender(b"hello airferry");
        let packed = encode_chunk_balanced_packed(&raw, 0, true);
        let codec = packed[0];
        let data = packed[1..].to_vec();
        let digest = hash32(&raw);
        session
            .stage_chunk(0, codec, data.clone(), Some(digest))
            .unwrap();

        // Drain frames until the chunk window starts producing data QRs.
        // Staged bytes are consumed as the playlist window moves on, so a
        // later epoch re-signals NotStaged — re-stage and keep going.
        let mut saw_matrix = false;
        for _ in 0..64 {
            match session.next_qr_batch(2) {
                Ok(buf) => {
                    let count = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
                    assert!((1..=2).contains(&count));
                    let mut pos = 4usize;
                    for _ in 0..count {
                        let side =
                            u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
                        assert!((21..=177).contains(&side));
                        assert_eq!(side % 4, 1, "QR sides are 4k+1");
                        pos += 4 + side * side;
                        saw_matrix = true;
                    }
                    assert_eq!(pos, buf.len(), "packed buffer must parse exactly");
                }
                Err(NextQrError::NotStaged(i)) => {
                    assert_eq!(i, 0);
                    session
                        .stage_chunk(0, codec, data.clone(), Some(digest))
                        .unwrap();
                }
                Err(NextQrError::Failed(e)) => panic!("frame generation failed: {e}"),
            }
        }
        assert!(saw_matrix);
    }

    #[test]
    fn unstaged_chunk_signals_not_staged_with_index() {
        let (mut session, _raw) = build_one_chunk_sender(b"hello airferry");
        // Bootstrap frames (root/manifest) come first; once the playlist
        // reaches chunk 0 without staging, the marker must carry index 0.
        let mut hit = None;
        for _ in 0..4096 {
            match session.next_qr_batch(4) {
                Ok(_) => {}
                Err(NextQrError::NotStaged(i)) => {
                    hit = Some(i);
                    break;
                }
                Err(e) => panic!("unexpected: {e:?}"),
            }
        }
        assert_eq!(hit, Some(0));
    }

    #[test]
    fn plan_chunks_json_spans_items_across_chunk_boundary() {
        let metas = vec![
            (1u8, "b.bin".to_string(), 10u64),
            (1u8, "a.bin".to_string(), 10u64),
        ];
        // NFC sort puts a.bin first; chunk size 15 splits both files.
        let json = plan_chunks_json(&metas, 15).unwrap();
        assert_eq!(json, "{\"chunks\":[[1,0,10,0,0,5],[0,5,5]]}");
    }

    #[test]
    fn plan_chunks_json_rejects_empty_stream() {
        assert!(plan_chunks_json(&[], 1024).is_err());
    }

    #[test]
    fn parse_hash_table_validates_alignment() {
        assert_eq!(parse_hash_table(&[7u8; 64]).unwrap().len(), 2);
        assert!(parse_hash_table(&[0u8; 31]).is_err());
    }

    #[test]
    fn stats_json_reports_counters() {
        let (mut session, raw) = build_one_chunk_sender(b"stats");
        session.stage_chunk(0, 0, raw.clone(), None).unwrap();
        for _ in 0..4 {
            let _ = session.next_qr_batch(1);
        }
        let json = session.stats_json();
        assert!(json.contains("\"frames\":4"), "{json}");
        assert!(!session.transfer_id_hex().is_empty());
        assert!(session.epoch() >= 1);
        // Playlist position depends on bootstrap drain speed: bootstrap (None)
        // or the first chunk window (Some(0)) are both valid here.
        assert!(matches!(session.current_chunk_index(), None | Some(0)));
    }
}

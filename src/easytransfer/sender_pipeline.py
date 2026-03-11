from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import math
import os
import sys
import uuid
from collections.abc import Callable, Iterable
from pathlib import Path

from .compression_layer import CompressionPolicy, build_transfer_registry, compress_bytes
from .utils import iter_chunks, pad_right, utc_now_iso, xor_many


@dataclasses.dataclass(frozen=True)
class SenderOptions:
    input_path: Path
    output_dir: Path
    block_size: int
    symbol_size: int
    redundancy: float
    fps: float


@dataclasses.dataclass(frozen=True)
class PlannedFile:
    file_id: int
    abs_path: Path
    rel_path: str
    size: int
    sha256: str
    compressed: bytes
    codec: str
    codec_params: dict[str, object]


ProgressCallback = Callable[[dict[str, object]], None]


def default_progress_printer(event: dict[str, object]) -> None:
    et = event.get("event")
    if et == "scan_start":
        _print(f"Scanning input: {event['input']}")
    elif et == "scan_done":
        _print(f"Discovered {event['file_count']} file(s)")
    elif et == "file_start":
        _print(
            f"[{event['index']}/{event['total']}] {event['path']} bytes={event['size']} codec={event['codec']}"
        )
    elif et == "file_done":
        _print(
            f"  done blocks={event['blocks']} source_symbols={event['source_symbols']} repair_symbols={event['repair_symbols']}"
        )
    elif et == "package_done":
        _print(
            f"Complete frames={event['frames']} files={event['files']} manifest={event['manifest_path']}"
        )


def run_sender_pipeline(
    *,
    input_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    block_size: int = 64 * 1024,
    symbol_size: int = 1024,
    redundancy: float = 0.0,
    fps: float = 30.0,
    progress: ProgressCallback | None = None,
) -> tuple[Path, Path]:
    if progress is None:
        progress = default_progress_printer

    opts = SenderOptions(
        input_path=Path(input_path).resolve(),
        output_dir=Path(output_dir).resolve(),
        block_size=int(block_size),
        symbol_size=int(symbol_size),
        redundancy=float(redundancy),
        fps=float(fps),
    )
    _validate_options(opts)

    progress({"event": "scan_start", "input": str(opts.input_path)})
    root, file_paths = _collect_files(opts.input_path)
    progress({"event": "scan_done", "file_count": len(file_paths)})

    registry = build_transfer_registry()
    planned: list[PlannedFile] = []
    for idx, fp in enumerate(file_paths):
        raw = fp.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        env, comp = compress_bytes(raw, registry=registry, policy=CompressionPolicy.AUTO)
        planned.append(
            PlannedFile(
                file_id=idx,
                abs_path=fp,
                rel_path=fp.relative_to(root).as_posix(),
                size=len(raw),
                sha256=sha,
                compressed=comp,
                codec=env.codec,
                codec_params=dict(env.params),
            )
        )

    opts.output_dir.mkdir(parents=True, exist_ok=True)
    frames_path = opts.output_dir / "frames.jsonl"
    manifest_path = opts.output_dir / "manifest.json"

    stream_id = str(uuid.uuid4())
    frame_id = 0
    repairs: list[dict[str, object]] = []
    files_manifest: list[dict[str, object]] = []
    sources_manifest: list[dict[str, object]] = []
    totals = {
        "files": len(planned),
        "input_bytes": sum(p.size for p in planned),
        "compressed_bytes": 0,
        "blocks": 0,
        "source_symbols": 0,
        "repair_symbols": 0,
        "frames": 0,
    }

    with frames_path.open("w", encoding="utf-8") as out:
        _ = out.write(
            json.dumps(
                {
                    "v": 1,
                    "kind": "header",
                    "stream_id": stream_id,
                    "transfer_id": stream_id,
                    "created_utc": utc_now_iso(),
                    "fps": opts.fps,
                    "block_size": opts.block_size,
                    "symbol_size": opts.symbol_size,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        frame_id += 1

        for i, pf in enumerate(planned, start=1):
            progress(
                {
                    "event": "file_start",
                    "index": i,
                    "total": len(planned),
                    "path": pf.rel_path,
                    "size": pf.size,
                    "codec": pf.codec,
                }
            )
            file_source_ids: list[str] = []
            file_blocks = 0
            file_source_symbols = 0
            file_repair_symbols = 0

            _ = out.write(
                json.dumps(
                    {
                        "v": 1,
                        "kind": "file_header",
                        "frame": frame_id,
                        "frame_seq": frame_id,
                        "t": _frame_time(frame_id, opts.fps),
                        "transfer_id": stream_id,
                        "file_id": pf.file_id,
                        "path": pf.rel_path,
                        "file_name": pf.rel_path,
                        "size": pf.size,
                        "file_size": pf.size,
                        "codec": pf.codec,
                        "compression": pf.codec,
                        "codec_params": pf.codec_params,
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
            frame_id += 1

            for block_index, block in enumerate(iter_chunks(pf.compressed, opts.block_size)):
                file_blocks += 1
                totals["blocks"] += 1
                symbols = list(iter_chunks(block, opts.symbol_size))
                if not symbols:
                    symbols = [b""]
                k = len(symbols)

                for symbol_index, symbol_bytes in enumerate(symbols):
                    sid = f"f{pf.file_id}:b{block_index}:s{symbol_index}"
                    file_source_ids.append(sid)
                    sources_manifest.append(
                        {
                            "symbol_id": sid,
                            "file": pf.rel_path,
                            "index": len(file_source_ids) - 1,
                            "size": len(symbol_bytes),
                            "sha256": hashlib.sha256(symbol_bytes).hexdigest(),
                        }
                    )
                    _ = out.write(
                        json.dumps(
                            {
                                "v": 1,
                                "kind": "symbol",
                                "frame": frame_id,
                                "frame_seq": frame_id,
                                "t": _frame_time(frame_id, opts.fps),
                                "transfer_id": stream_id,
                                "file_id": pf.file_id,
                                "path": pf.rel_path,
                                "block": block_index,
                                "block_id": block_index,
                                "block_len": len(block),
                                "symbol": symbol_index,
                                "symbol_index": symbol_index,
                                "symbol_id": sid,
                                "k": k,
                                "source_symbol_total": k,
                                "redundant": False,
                                "is_repair": False,
                                "payload_b64": base64.b64encode(symbol_bytes).decode("ascii"),
                                "crc32": _crc32_u32(symbol_bytes),
                                "payload_crc32": _crc32_u32(symbol_bytes),
                            },
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                    frame_id += 1
                    file_source_symbols += 1
                    totals["source_symbols"] += 1

                repair_count = int(math.ceil(k * max(opts.redundancy, 0.0)))
                for repair_idx in range(repair_count):
                    source_indices = _select_repair_indices(k, repair_idx)
                    parity_payload = _xor_for_indices(symbols, source_indices)
                    rid = f"f{pf.file_id}:b{block_index}:r{repair_idx}"
                    xor_of = [f"f{pf.file_id}:b{block_index}:s{j}" for j in source_indices]
                    repairs.append(
                        {
                            "symbol_id": rid,
                            "xor_of": xor_of,
                            "file_id": pf.file_id,
                            "block": block_index,
                            "block_id": block_index,
                            "size": len(parity_payload),
                            "sha256": hashlib.sha256(parity_payload).hexdigest(),
                            "file": pf.rel_path,
                        }
                    )
                    _ = out.write(
                        json.dumps(
                            {
                                "v": 1,
                                "kind": "symbol",
                                "frame": frame_id,
                                "frame_seq": frame_id,
                                "t": _frame_time(frame_id, opts.fps),
                                "transfer_id": stream_id,
                                "file_id": pf.file_id,
                                "path": pf.rel_path,
                                "block": block_index,
                                "block_id": block_index,
                                "block_len": len(block),
                                "symbol": k + repair_idx,
                                "symbol_index": k + repair_idx,
                                "symbol_id": rid,
                                "k": k,
                                "source_symbol_total": k,
                                "redundant": True,
                                "is_repair": True,
                                "repair_of": xor_of,
                                "payload_b64": base64.b64encode(parity_payload).decode("ascii"),
                                "crc32": _crc32_u32(parity_payload),
                                "payload_crc32": _crc32_u32(parity_payload),
                            },
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                    frame_id += 1
                    file_repair_symbols += 1
                    totals["repair_symbols"] += 1

            _ = out.write(
                json.dumps(
                    {
                        "v": 1,
                        "kind": "file_footer",
                        "frame": frame_id,
                        "frame_seq": frame_id,
                        "t": _frame_time(frame_id, opts.fps),
                        "transfer_id": stream_id,
                        "file_id": pf.file_id,
                        "path": pf.rel_path,
                        "sha256": pf.sha256,
                        "file_sha256": pf.sha256,
                        "compressed_bytes": len(pf.compressed),
                        "blocks": file_blocks,
                        "data_symbols": file_source_symbols,
                        "redundant_symbols": file_repair_symbols,
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
            frame_id += 1

            files_manifest.append(
                {
                    "id": pf.file_id,
                    "path": pf.rel_path,
                    "size": pf.size,
                    "sha256": pf.sha256,
                    "compression": pf.codec,
                    "compression_params": pf.codec_params,
                    "source_symbol_ids": file_source_ids,
                    "compressed_bytes": len(pf.compressed),
                }
            )
            totals["compressed_bytes"] += len(pf.compressed)
            progress(
                {
                    "event": "file_done",
                    "blocks": file_blocks,
                    "source_symbols": file_source_symbols,
                    "repair_symbols": file_repair_symbols,
                }
            )

        _ = out.write(
            json.dumps(
                {
                    "v": 1,
                    "kind": "eos",
                    "frame": frame_id,
                    "frame_seq": frame_id,
                    "t": _frame_time(frame_id, opts.fps),
                    "stream_id": stream_id,
                    "transfer_id": stream_id,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        frame_id += 1

    totals["frames"] = frame_id
    manifest = {
        "version": 1,
        "protocol": "easytransfer/1",
        "stream_id": stream_id,
        "transfer_id": stream_id,
        "created_utc": utc_now_iso(),
        "interop": {"codec_profile": "common-v1", "allowed_codecs": list(registry.available())},
        "options": {
            "block_size": opts.block_size,
            "symbol_size": opts.symbol_size,
            "redundancy": opts.redundancy,
            "fps": opts.fps,
        },
        "files": files_manifest,
        "sources": sources_manifest,
        "repairs": repairs,
        "frames": {
            "path": frames_path.name,
            "format": "jsonl+base64",
            "count": frame_id,
        },
        "totals": totals,
    }
    _ = manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    progress(
        {
            "event": "package_done",
            "frames": frame_id,
            "files": len(planned),
            "manifest_path": str(manifest_path),
        }
    )
    return manifest_path, frames_path


def _validate_options(opts: SenderOptions) -> None:
    if not opts.input_path.exists():
        raise FileNotFoundError(str(opts.input_path))
    if opts.block_size <= 0:
        raise ValueError("block_size must be > 0")
    if opts.symbol_size <= 0:
        raise ValueError("symbol_size must be > 0")
    if opts.symbol_size > opts.block_size:
        raise ValueError("symbol_size must be <= block_size")
    if opts.redundancy < 0.0 or math.isnan(opts.redundancy):
        raise ValueError("redundancy must be >= 0")
    if opts.fps <= 0.0 or math.isnan(opts.fps):
        raise ValueError("fps must be > 0")


def _collect_files(input_path: Path) -> tuple[Path, list[Path]]:
    if input_path.is_file():
        return input_path.parent, [input_path]
    if not input_path.is_dir():
        raise ValueError(f"--input must be a file or directory: {input_path}")
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(input_path):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_file():
                files.append(p.resolve())
    files.sort(key=lambda p: str(p))
    return input_path, files


def _frame_time(frame: int, fps: float) -> float:
    return frame / fps


def _select_repair_indices(k: int, repair_idx: int) -> list[int]:
    if k <= 0:
        return []
    if k == 1:
        return [0]

    basis_count = max(1, int(math.ceil(math.log2(k + 1))))
    if repair_idx < basis_count:
        bit = repair_idx
        out = [i for i in range(k) if (((i + 1) >> bit) & 1) == 1]
        if len(out) >= 2:
            return out

    # Deterministic pseudo-random dense equation for additional repairs.
    seed = (repair_idx + 1) * 0x9E3779B1
    width = min(k, max(2, int(math.sqrt(k)) + 2))
    out_set: set[int] = set()
    x = seed & 0xFFFFFFFF
    while len(out_set) < width:
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        out_set.add(int(x % k))
    return sorted(out_set)


def _xor_for_indices(symbols: list[bytes], indices: Iterable[int]) -> bytes:
    selected = [symbols[i] for i in indices]
    if not selected:
        return b""
    max_len = max(len(x) for x in selected)
    padded = [pad_right(x, max_len) for x in selected]
    return xor_many(padded)


def _crc32_u32(data: bytes) -> int:
    import zlib

    return zlib.crc32(data) & 0xFFFFFFFF


def _print(msg: str) -> None:
    _ = sys.stdout.write(msg + "\n")
    _ = sys.stdout.flush()

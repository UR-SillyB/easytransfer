from __future__ import annotations

import base64
import dataclasses
import json
import os
import random
import zlib
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import cast

from .fec_recovery import estimate_additional_repair_needed


class ScannerInputError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class ScanConfig:
    loss_rate: float = 0.0
    burst_rate: float = 0.0
    seed: int | None = None


@dataclasses.dataclass(frozen=True)
class ScanResult:
    received_path: Path
    feedback_path: Path
    stats: dict[str, int]
    feedback: dict[str, object]


def scan_frames(
    *,
    frames_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    loss_rate: float = 0.0,
    burst_rate: float = 0.0,
    seed: int | None = None,
) -> ScanResult:

    cfg = ScanConfig(loss_rate=float(loss_rate), burst_rate=float(burst_rate), seed=seed)
    _validate_rates(cfg)

    frames_p = Path(frames_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    received_path = out_dir / "received.jsonl"
    feedback_path = out_dir / "feedback.json"

    rng = random.Random(cfg.seed)

    stats: dict[str, int] = {
        "lines_total": 0,
        "lines_kept": 0,
        "lines_dropped_random": 0,
        "lines_dropped_burst": 0,
        "symbol_lines_total": 0,
        "symbol_lines_kept": 0,
        "frames_dropped_crc_mismatch": 0,
        "frames_dropped_crc_unverifiable": 0,
        "frames_crc_skipped": 0,
        "symbols_emitted": 0,
        "symbols_dropped_decode": 0,
        "symbols_dropped_duplicate": 0,
    }

    truth_k: dict[str, int] = {}
    truth_meta: dict[str, dict[str, object]] = {}
    truth_source_ids: dict[str, set[str]] = defaultdict(set)
    truth_repair_equations: dict[str, dict[str, tuple[str, ...]]] = defaultdict(dict)
    with frames_p.open("r", encoding="utf-8") as fin_truth:
        for _ln, rec in _iter_jsonl(fin_truth, source=str(frames_p)):
            if not _is_sender_symbol_record(rec):
                continue
            bkey = _block_key(rec)
            sid = _symbol_id_str(rec)
            is_repair = _is_repair_symbol(rec)
            if not is_repair:
                truth_k[bkey] = truth_k.get(bkey, 0) + 1
                truth_source_ids[bkey].add(sid)
            else:
                xor_of = _repair_source_ids(rec)
                if xor_of:
                    truth_repair_equations[bkey][sid] = xor_of
            if bkey not in truth_meta:
                block_val = _frame_int(rec, "block", "block_id")
                truth_meta[bkey] = {
                    "file_id": rec.get("file_id"),
                    "path": rec.get("path"),
                    "block": block_val,
                    "block_len": rec.get("block_len"),
                }

    block_symbol_ids: dict[str, set[str]] = defaultdict(set)
    block_repair_counts: dict[str, int] = defaultdict(int)
    block_data_counts: dict[str, int] = defaultdict(int)
    block_source_ids: dict[str, set[str]] = defaultdict(set)
    block_repair_ids: dict[str, set[str]] = defaultdict(set)

    burst_remaining = 0

    with frames_p.open("r", encoding="utf-8") as fin, received_path.open("w", encoding="utf-8") as fout:
        for line_no, frame in _iter_jsonl(fin, source=str(frames_p)):
            stats["lines_total"] += 1
            frame_id = _frame_id(frame, fallback=line_no - 1)

            drop_reason, burst_remaining = _simulate_drop(
                rng=rng,
                loss_rate=cfg.loss_rate,
                burst_rate=cfg.burst_rate,
                burst_remaining=burst_remaining,
            )
            if drop_reason is not None:
                if drop_reason == "random":
                    stats["lines_dropped_random"] += 1
                elif drop_reason == "burst":
                    stats["lines_dropped_burst"] += 1
                else:
                    _ = stats.setdefault("frames_dropped_other", 0)
                    stats["frames_dropped_other"] += 1
                continue

            crc_status = _validate_frame_crc(frame)
            if crc_status == "mismatch":
                stats["frames_dropped_crc_mismatch"] += 1
                continue
            if crc_status == "unverifiable":
                stats["frames_dropped_crc_unverifiable"] += 1
                continue
            if crc_status == "skipped":
                stats["frames_crc_skipped"] += 1

            stats["lines_kept"] += 1

            if not _is_sender_symbol_record(frame):
                continue

            stats["symbol_lines_total"] += 1
            bkey = _block_key(frame)
            sid = _symbol_id_str(frame)
            if sid in block_symbol_ids[bkey]:
                stats["symbols_dropped_duplicate"] += 1
                continue
            block_symbol_ids[bkey].add(sid)

            is_repair = _is_repair_symbol(frame)
            if is_repair:
                block_repair_counts[bkey] += 1
                block_repair_ids[bkey].add(sid)
            else:
                block_data_counts[bkey] += 1
                block_source_ids[bkey].add(sid)

            payload_b64 = cast(str, frame["payload_b64"])
            try:
                payload = base64.b64decode(payload_b64, validate=True)
            except Exception:
                stats["symbols_dropped_decode"] += 1
                continue
            sym_len = frame.get("symbol_len")
            if isinstance(sym_len, int) and sym_len != len(payload):
                stats["symbols_dropped_decode"] += 1
                continue
            expected_crc = _find_int(frame, ("payload_crc32", "crc32", "crc"))
            if expected_crc is not None:
                computed = zlib.crc32(payload) & 0xFFFFFFFF
                if computed != expected_crc:
                    stats["symbols_dropped_decode"] += 1
                    continue

            block_val = _frame_int(frame, "block", "block_id")
            symbol_val = _frame_int(frame, "symbol", "symbol_index")
            frame_seq_val = _frame_int(frame, "frame", "frame_seq")

            out_rec: dict[str, object] = {
                "symbol_id": sid,
                "data_b64": payload_b64,
                "payload_b64": payload_b64,
                "crc32": zlib.crc32(payload) & 0xFFFFFFFF,
                "payload_crc32": zlib.crc32(payload) & 0xFFFFFFFF,
                "file_id": frame.get("file_id"),
                "path": frame.get("path"),
                "block": block_val,
                "block_id": block_val,
                "symbol": symbol_val,
                "symbol_index": symbol_val,
                "redundant": bool(is_repair),
                "is_repair": bool(is_repair),
                "frame": frame.get("frame", frame_id),
                "frame_seq": frame_seq_val if frame_seq_val is not None else frame_id,
                "transfer_id": frame.get("transfer_id"),
            }
            _ = fout.write(json.dumps(out_rec, ensure_ascii=False) + "\n")
            stats["symbols_emitted"] += 1
            stats["symbol_lines_kept"] += 1

    feedback = _build_feedback(
        frames_path=str(frames_p),
        cfg=cfg,
        stats=stats,
        block_symbol_ids=block_symbol_ids,
        block_k=truth_k,
        block_repair_counts=block_repair_counts,
        block_data_counts=block_data_counts,
        block_meta=truth_meta,
        block_source_ids=block_source_ids,
        block_repair_ids=block_repair_ids,
        truth_source_ids=truth_source_ids,
        truth_repair_equations=truth_repair_equations,
    )

    _ = feedback_path.write_text(json.dumps(feedback, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return ScanResult(
        received_path=received_path,
        feedback_path=feedback_path,
        stats=stats,
        feedback=feedback,
    )


def _validate_rates(cfg: ScanConfig) -> None:
    for name, v in ("loss_rate", cfg.loss_rate), ("burst_rate", cfg.burst_rate):
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"{name} must be within [0,1], got {v}")


def _iter_jsonl(fin: Iterable[str], *, source: str) -> Iterator[tuple[int, dict[str, object]]]:
    for line_no, line in enumerate(fin, start=1):
        s = line.strip()
        if not s:
            continue
        try:
            parsed = cast(object, json.loads(s))
        except json.JSONDecodeError as e:
            raise ScannerInputError(f"Invalid JSON at {source}:{line_no}: {e}") from e
        if not isinstance(parsed, dict):
            raise ScannerInputError(f"Expected JSON object at {source}:{line_no}, got {type(parsed).__name__}")
        yield line_no, cast(dict[str, object], parsed)


def _frame_id(frame: dict[str, object], *, fallback: int) -> int:
    for k in ("frame_id", "frame", "frame_seq", "seq", "index", "i"):
        v = frame.get(k)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    return int(fallback)


def _simulate_drop(
    *,
    rng: random.Random,
    loss_rate: float,
    burst_rate: float,
    burst_remaining: int,
) -> tuple[str | None, int]:

    if burst_remaining > 0:
        return "burst", burst_remaining - 1

    if burst_rate > 0.0 and rng.random() < burst_rate:
        burst_len = rng.randint(2, 8)
        return "burst", burst_len - 1

    if loss_rate > 0.0 and rng.random() < loss_rate:
        return "random", 0

    return None, 0


def _validate_frame_crc(frame: dict[str, object]) -> str:

    expected = _find_int(frame, ("crc32", "frame_crc32", "crc"))
    if expected is None:
        return "skipped"

    payload = _frame_payload_bytes(frame)
    if payload is None:
        return "unverifiable"

    computed = zlib.crc32(payload) & 0xFFFFFFFF
    return "ok" if computed == expected else "mismatch"


def _frame_payload_bytes(frame: dict[str, object]) -> bytes | None:

    for key in (
        "payload_b64",
        "frame_b64",
        "data_b64",
        "bytes_b64",
        "payload",
        "data",
    ):
        v = frame.get(key)
        if isinstance(v, str):
            try:
                return base64.b64decode(v, validate=True)
            except Exception:
                continue
    return None


def _build_feedback(
    *,
    frames_path: str,
    cfg: ScanConfig,
    stats: dict[str, int],
    block_symbol_ids: dict[str, set[str]],
    block_k: dict[str, int],
    block_repair_counts: dict[str, int],
    block_data_counts: dict[str, int],
    block_meta: dict[str, dict[str, object]],
    block_source_ids: dict[str, set[str]],
    block_repair_ids: dict[str, set[str]],
    truth_source_ids: dict[str, set[str]],
    truth_repair_equations: dict[str, dict[str, tuple[str, ...]]],
) -> dict[str, object]:
    blocks: dict[str, object] = {}
    need_list: list[dict[str, object]] = []
    total_need = 0

    additional_need = estimate_additional_repair_needed(
        expected_source_ids=truth_source_ids,
        received_source_ids=block_source_ids,
        received_repair_ids=block_repair_ids,
        repair_equations=truth_repair_equations,
    )

    all_blocks = set(block_k.keys()) | set(block_symbol_ids.keys())
    for block_id in sorted(all_blocks, key=lambda x: (len(x), x)):
        received = len(block_symbol_ids[block_id])
        k = block_k.get(block_id)
        need = None
        missing_source_ids: list[str] | None = None
        missing_source_count: int | None = None
        if isinstance(k, int) and k > 0:
            need = int(additional_need.get(block_id, 0))
            expected_sources = truth_source_ids.get(block_id)
            got_sources = block_source_ids.get(block_id)
            if expected_sources is not None and got_sources is not None:
                missing = sorted(expected_sources - got_sources)
                missing_source_ids = missing
                missing_source_count = len(missing)
        block_entry: dict[str, object] = {
            "k": k,
            "received": received,
            "received_data": int(block_data_counts.get(block_id, 0)),
            "received_repair": int(block_repair_counts.get(block_id, 0)),
            "need_repair": need,
            "missing_source_count": missing_source_count,
            "missing_source_symbol_ids": missing_source_ids,
            "received_repair_equations": len(block_repair_ids.get(block_id, set())),
        }
        meta = block_meta.get(block_id)
        if meta:
            for mk, mv in meta.items():
                if mv is not None:
                    block_entry[mk] = mv
        blocks[block_id] = block_entry
        if isinstance(need, int) and need > 0:
            out_need: dict[str, object] = {"block_id": block_id, "need_repair": need}
            if meta:
                file_id = meta.get("file_id")
                path = meta.get("path")
                block = meta.get("block")
                if file_id is not None:
                    out_need["file_id"] = file_id
                if path is not None:
                    out_need["path"] = path
                if block is not None:
                    out_need["block"] = block
            need_list.append(out_need)
            total_need += need

    return {
        "version": 1,
        "input_frames": frames_path,
        "loss": cast(dict[str, object], dataclasses.asdict(cfg)),
        "stats": stats,
        "blocks": blocks,
        "recommendation": {
            "need_blocks": need_list,
            "total_need_repair": total_need,
            "note": "补传建议基于可解方程数估算。对 need_blocks 中每个 block 至少补传 need_repair 个新修复符号。",
        },
    }


def _find_int(obj: dict[str, object], keys: tuple[str, ...]) -> int | None:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            try:
                if s.startswith("0x"):
                    return int(s, 16)
                if s.isdigit():
                    return int(s)
            except Exception:
                continue
    return None


def _is_sender_symbol_record(rec: dict[str, object]) -> bool:
    if rec.get("kind") != "symbol":
        return False
    if not isinstance(rec.get("payload_b64"), str):
        return False
    if _frame_int(rec, "block", "block_id") is None:
        return False
    if _frame_int(rec, "symbol", "symbol_index") is None:
        return False
    return True


def _block_key(rec: dict[str, object]) -> str:
    file_id = _frame_int(rec, "file_id")
    block = _frame_int(rec, "block", "block_id")
    if file_id is not None and block is not None:
        return f"{file_id}:{block}"
    return f"{rec.get('file_id')}:{rec.get('block', rec.get('block_id'))}"


def _symbol_id_str(rec: dict[str, object]) -> str:
    sid = rec.get("symbol_id")
    if isinstance(sid, str) and sid:
        return sid
    file_id = _frame_int(rec, "file_id")
    block = _frame_int(rec, "block", "block_id")
    symbol = _frame_int(rec, "symbol", "symbol_index")
    transfer_id = rec.get("transfer_id")
    prefix = f"{transfer_id}:" if isinstance(transfer_id, str) and transfer_id else ""
    if file_id is None or block is None or symbol is None:
        return prefix + "unknown"
    if _is_repair_symbol(rec):
        k = _frame_int(rec, "k", "source_symbol_total")
        ridx = symbol if k is None else max(0, symbol - k)
        return f"{prefix}f{file_id}:b{block}:r{ridx}"
    return f"{prefix}f{file_id}:b{block}:s{symbol}"


def _frame_int(rec: dict[str, object], *keys: str) -> int | None:
    for k in keys:
        v = rec.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            s = v.strip()
            if s and (s.isdigit() or (s.startswith("-") and s[1:].isdigit())):
                return int(s)
    return None


def _is_repair_symbol(rec: dict[str, object]) -> bool:
    v = rec.get("redundant")
    if isinstance(v, bool):
        return v
    v2 = rec.get("is_repair")
    if isinstance(v2, bool):
        return v2
    return False


def _repair_source_ids(rec: dict[str, object]) -> tuple[str, ...]:
    for key in ("xor_of", "repair_of"):
        val = rec.get(key)
        if not isinstance(val, list):
            continue
        out: list[str] = []
        bad = False
        for x in cast(list[object], val):
            if not isinstance(x, str) or not x:
                bad = True
                break
            out.append(x)
        if not bad and out:
            return tuple(out)
    return tuple()

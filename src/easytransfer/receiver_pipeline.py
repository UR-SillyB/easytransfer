from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import cast

from .compression_layer import CompressionEnvelope, DecompressionLimits, build_default_registry, decompress_bytes
from .fec_recovery import parse_source_symbol_id, recover_sources_with_repairs
from .utils import JSONValue, ensure_json_object, sha256_hex


class ReceiverError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class FileSpec:
    path: str
    size: int
    sha256: str
    compression: str
    compression_params: dict[str, JSONValue]
    source_symbol_ids: tuple[str, ...]


@dataclasses.dataclass
class ReceiverReport:
    ok: bool
    files_written: list[str]
    files_failed: list[str]
    recovered_source_symbols: list[str]
    missing_source_symbols: list[str]
    missing_repair_symbols: list[str]
    verified_source_symbols: int
    verified_repair_symbols: int
    errors: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "files_written": self.files_written,
            "files_failed": self.files_failed,
            "recovered_source_symbols": self.recovered_source_symbols,
            "missing_source_symbols": self.missing_source_symbols,
            "missing_repair_symbols": self.missing_repair_symbols,
            "verified_source_symbols": self.verified_source_symbols,
            "verified_repair_symbols": self.verified_repair_symbols,
            "errors": self.errors,
        }


def load_manifest(
    manifest_path: str | os.PathLike[str],
) -> tuple[list[FileSpec], dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    p = Path(manifest_path)
    if not p.exists():
        raise ReceiverError(f"Manifest not found: {manifest_path}")
    try:
        loaded = cast(object, json.loads(p.read_text(encoding="utf-8")))
    except json.JSONDecodeError as e:
        raise ReceiverError(f"Invalid manifest JSON: {e}") from e
    if not isinstance(loaded, dict):
        raise ReceiverError("Manifest must be a JSON object")
    raw = cast(dict[str, object], loaded)

    files: list[FileSpec] = []
    source_specs: dict[str, dict[str, object]] = {}

    files_obj = raw.get("files")
    if not isinstance(files_obj, list):
        files_obj = []
    for obj_raw in cast(list[object], files_obj):
        if not isinstance(obj_raw, dict):
            continue
        obj = cast(dict[str, object], obj_raw)
        sid_list_obj = obj.get("source_symbol_ids")
        if not isinstance(sid_list_obj, list):
            continue
        sid_list: list[str] = []
        bad_sid = False
        for sid_item in cast(list[object], sid_list_obj):
            if not isinstance(sid_item, str):
                bad_sid = True
                break
            sid_list.append(sid_item)
        if bad_sid:
            continue

        path = obj.get("path")
        size = obj.get("size")
        sha = obj.get("sha256")
        compression = obj.get("compression")
        params_obj = obj.get("compression_params", {})
        if not isinstance(path, str) or not isinstance(size, int) or not isinstance(sha, str):
            continue
        if not isinstance(compression, str):
            compression = "none"
        if not isinstance(params_obj, dict):
            params_obj = {}
        try:
            params = ensure_json_object(cast(dict[object, object], params_obj))
        except ValueError:
            params = {}

        files.append(
            FileSpec(
                path=path,
                size=size,
                sha256=sha,
                compression=compression,
                compression_params=params,
                source_symbol_ids=tuple(sid_list),
            )
        )

        # Android-generated manifests can omit "sources": we still register file source ids.
        for sid in sid_list:
            spec = source_specs.get(sid)
            if spec is None:
                source_specs[sid] = {"symbol_id": sid}
            parsed = parse_source_symbol_id(sid)
            if parsed is not None:
                source_specs[sid]["file"] = path

    sources_raw = raw.get("sources")
    if isinstance(sources_raw, list):
        for s_raw in cast(list[object], sources_raw):
            if not isinstance(s_raw, dict):
                continue
            s = cast(dict[str, object], s_raw)
            sid = s.get("symbol_id")
            if isinstance(sid, str):
                source_specs[sid] = s

    repair_specs: dict[str, dict[str, object]] = {}
    repairs_raw = raw.get("repairs")
    if isinstance(repairs_raw, list):
        for r_raw in cast(list[object], repairs_raw):
            if not isinstance(r_raw, dict):
                continue
            rep = cast(dict[str, object], r_raw)
            rid = rep.get("symbol_id")
            if isinstance(rid, str):
                repair_specs[rid] = rep

    return files, source_specs, repair_specs


def load_scanner_artifact(input_path: str | os.PathLike[str]) -> dict[str, bytes]:
    p = Path(input_path)
    if not p.exists():
        raise ReceiverError(f"Scanner artifact not found: {input_path}")
    out: dict[str, bytes] = {}

    sources: list[Path]
    if p.is_dir():
        candidates = sorted(x for x in p.iterdir() if x.is_file() and x.suffix.lower() in {".jsonl", ".ndjson"})
        preferred = [x for x in candidates if x.name == "received.jsonl"]
        sources = preferred + [x for x in candidates if x not in preferred]
    else:
        sources = [p]

    for src in sources:
        records = _read_jsonl(src)
        for rec in records:
            sid = _record_symbol_id(rec)
            if sid is None or sid in out:
                continue
            payload_b64 = _record_payload_b64(rec)
            if payload_b64 is None:
                continue
            try:
                data = base64.b64decode(payload_b64, validate=False)
            except Exception as e:
                raise ReceiverError(f"Invalid base64 for symbol {sid}: {e}") from e
            out[sid] = data

    return out


def _record_symbol_id(rec: dict[str, object]) -> str | None:
    sid_obj = rec.get("symbol_id")
    if isinstance(sid_obj, str) and sid_obj:
        return sid_obj

    file_id = _frame_int(rec, "file_id")
    block = _frame_int(rec, "block", "block_id")
    symbol = _frame_int(rec, "symbol", "symbol_index")
    if file_id is None or block is None or symbol is None:
        return None

    transfer_id = rec.get("transfer_id")
    prefix = f"{transfer_id}:" if isinstance(transfer_id, str) and transfer_id else ""
    is_repair = _frame_bool(rec, "redundant", "is_repair")
    if is_repair:
        k = _frame_int(rec, "k", "source_symbol_total")
        ridx = symbol if k is None else max(0, symbol - k)
        return f"{prefix}f{file_id}:b{block}:r{ridx}"
    return f"{prefix}f{file_id}:b{block}:s{symbol}"


def _record_payload_b64(rec: dict[str, object]) -> str | None:
    payload_obj = rec.get("data_b64")
    if isinstance(payload_obj, str):
        return payload_obj
    payload_obj = rec.get("payload_b64")
    if isinstance(payload_obj, str):
        return payload_obj
    return None


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = cast(object, json.loads(s))
            except json.JSONDecodeError as e:
                raise ReceiverError(f"Invalid JSONL at {path}:{line_no}: {e}") from e
            if isinstance(obj, dict):
                records.append(cast(dict[str, object], obj))
    return records


def _safe_join(base_dir: Path, rel_path: str) -> Path:
    rel = Path(rel_path)
    if rel.is_absolute() or ".." in rel.parts:
        raise ReceiverError(f"Unsafe output path: {rel_path}")
    out = (base_dir / rel).resolve()
    base = base_dir.resolve()
    if not str(out).startswith(str(base) + os.sep) and out != base:
        raise ReceiverError(f"Unsafe output path: {rel_path}")
    return out


def _validate_symbol_payload(*, symbol_id: str, payload: bytes, spec: Mapping[str, object]) -> None:
    size = spec.get("size")
    if isinstance(size, int) and size >= 0 and len(payload) != size:
        raise ReceiverError(f"Symbol size mismatch for {symbol_id}: got={len(payload)} expected={size}")
    sha = spec.get("sha256")
    if isinstance(sha, str) and sha:
        got = hashlib.sha256(payload).hexdigest()
        if got != sha:
            raise ReceiverError(f"Symbol sha256 mismatch for {symbol_id}: got={got} expected={sha}")


def _normalize_repair_spec(rep: dict[str, object]) -> dict[str, object]:
    out = dict(rep)
    xor_of = out.get("xor_of")
    if not isinstance(xor_of, list):
        repair_of = out.get("repair_of")
        if isinstance(repair_of, list):
            out["xor_of"] = repair_of
    return out


def _frame_int(obj: Mapping[str, object], *keys: str) -> int | None:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            s = v.strip()
            if s and (s.isdigit() or (s.startswith("-") and s[1:].isdigit())):
                return int(s)
    return None


def _frame_bool(obj: Mapping[str, object], *keys: str) -> bool:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in {"1", "true", "yes"}:
                return True
            if s in {"0", "false", "no"}:
                return False
    return False


def _sort_source_ids(ids: Iterable[str]) -> list[str]:
    def _key(sid: str) -> tuple[int, int, str]:
        parsed = parse_source_symbol_id(sid)
        if parsed is None:
            return (10**9, 10**9, sid)
        block_id, idx = parsed
        try:
            _file_no, block_no = block_id.split(":", 1)
            return (int(block_no), idx, sid)
        except Exception:
            return (10**9, idx, sid)

    return sorted(ids, key=_key)


def run_receiver(input_path: str, manifest_path: str, output_dir: str) -> ReceiverReport:
    files, source_specs, repair_specs_raw = load_manifest(manifest_path)
    have = load_scanner_artifact(input_path)
    repair_specs = {rid: _normalize_repair_spec(rep) for rid, rep in repair_specs_raw.items()}

    errors: list[str] = []
    verified_source_symbols = 0
    verified_repair_symbols = 0

    for sid, payload in list(have.items()):
        if sid in source_specs:
            try:
                _validate_symbol_payload(symbol_id=sid, payload=payload, spec=source_specs[sid])
                verified_source_symbols += 1
            except ReceiverError as e:
                errors.append(str(e))
                _ = have.pop(sid, None)
        elif sid in repair_specs:
            try:
                _validate_symbol_payload(symbol_id=sid, payload=payload, spec=repair_specs[sid])
                verified_repair_symbols += 1
            except ReceiverError as e:
                errors.append(str(e))
                _ = have.pop(sid, None)

    recovered_source = recover_sources_with_repairs(
        have=have,
        source_specs=source_specs,
        repair_specs=repair_specs,
        validate_source=lambda sid, payload, spec: _validate_symbol_payload(symbol_id=sid, payload=payload, spec=spec),
        errors=errors,
    )

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files_written: list[str] = []
    files_failed: list[str] = []

    registry = build_default_registry()
    limits = DecompressionLimits(
        max_output_bytes=512 * 1024 * 1024,
        max_input_bytes=512 * 1024 * 1024,
        max_ratio=5000.0,
    )

    for f in files:
        try:
            chunks: list[bytes] = []
            for sid in _sort_source_ids(f.source_symbol_ids):
                if sid not in have:
                    raise ReceiverError(f"Missing source symbol {sid} for file {f.path}")
                chunks.append(have[sid])
            compressed = b"".join(chunks)
            env = CompressionEnvelope(
                codec=f.compression,
                original_size=f.size,
                compressed_size=len(compressed),
                params=f.compression_params,
            )
            raw = decompress_bytes(env, compressed, registry=registry, limits=limits)
            got = sha256_hex(raw)
            if got != f.sha256:
                raise ReceiverError(f"SHA256 mismatch for {f.path}: got={got} expected={f.sha256}")

            out_path = _safe_join(out_dir, f.path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            _ = out_path.write_bytes(raw)
            files_written.append(f.path)
        except Exception as e:
            files_failed.append(f.path)
            errors.append(str(e))

    missing_source = sorted([sid for sid in source_specs.keys() if sid not in have])
    missing_repair = sorted([sid for sid in repair_specs.keys() if sid not in have])
    report = ReceiverReport(
        ok=(len(files_failed) == 0 and len(missing_source) == 0),
        files_written=sorted(files_written),
        files_failed=sorted(set(files_failed)),
        recovered_source_symbols=sorted(set(recovered_source)),
        missing_source_symbols=missing_source,
        missing_repair_symbols=missing_repair,
        verified_source_symbols=verified_source_symbols,
        verified_repair_symbols=verified_repair_symbols,
        errors=errors,
    )
    _ = (Path(output_dir) / "receiver_report.json").write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report

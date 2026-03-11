from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Mapping
from typing import cast


_SOURCE_ID_RE = re.compile(r"(?:.+:)?f(?P<file>\d+):b(?P<block>\d+):s(?P<symbol>\d+)$")
_REPAIR_ID_RE = re.compile(r"(?:.+:)?f(?P<file>\d+):b(?P<block>\d+):r(?P<repair>\d+)$")


def parse_source_symbol_id(symbol_id: str) -> tuple[str, int] | None:
    m = _SOURCE_ID_RE.match(symbol_id)
    if m is None:
        return None
    file_id = int(m.group("file"))
    block_id = int(m.group("block"))
    symbol_idx = int(m.group("symbol"))
    return f"{file_id}:{block_id}", symbol_idx


def parse_repair_symbol_id(symbol_id: str) -> tuple[str, int] | None:
    m = _REPAIR_ID_RE.match(symbol_id)
    if m is None:
        return None
    file_id = int(m.group("file"))
    block_id = int(m.group("block"))
    repair_idx = int(m.group("repair"))
    return f"{file_id}:{block_id}", repair_idx


def estimate_additional_repair_needed(
    *,
    expected_source_ids: Mapping[str, set[str]],
    received_source_ids: Mapping[str, set[str]],
    received_repair_ids: Mapping[str, set[str]],
    repair_equations: Mapping[str, Mapping[str, tuple[str, ...]]],
) -> dict[str, int]:
    need_by_block: dict[str, int] = {}
    all_blocks = set(expected_source_ids.keys()) | set(received_source_ids.keys())
    for block_id in all_blocks:
        expected = set(expected_source_ids.get(block_id, set()))
        got = set(received_source_ids.get(block_id, set()))
        missing = sorted(expected - got)
        if not missing:
            need_by_block[block_id] = 0
            continue

        col = {sid: i for i, sid in enumerate(missing)}
        eqs = repair_equations.get(block_id, {})
        masks: list[int] = []
        for rid in received_repair_ids.get(block_id, set()):
            xor_of = eqs.get(rid)
            if xor_of is None:
                continue
            mask = 0
            for sid in xor_of:
                idx = col.get(sid)
                if idx is not None:
                    mask |= 1 << idx
            if mask != 0:
                masks.append(mask)

        rank = _gf2_rank(masks)
        need_by_block[block_id] = max(0, len(missing) - rank)
    return need_by_block


def recover_sources_with_repairs(
    *,
    have: dict[str, bytes],
    source_specs: Mapping[str, Mapping[str, object]],
    repair_specs: Mapping[str, Mapping[str, object]],
    validate_source: Callable[[str, bytes, Mapping[str, object]], None],
    errors: list[str],
) -> list[str]:
    recovered: list[str] = []
    source_by_block = _build_source_block_index(source_specs)
    repair_by_block = _build_repair_block_index(repair_specs, valid_source_ids=set(source_specs.keys()))

    progressed = True
    while progressed:
        progressed = False

        # First pass: peel equations that miss exactly one source symbol.
        for block_id, source_ids in source_by_block.items():
            source_set = set(source_ids)
            for rid, xor_of in repair_by_block.get(block_id, {}).items():
                rep_payload = have.get(rid)
                if rep_payload is None:
                    continue
                missing = [sid for sid in xor_of if sid in source_set and sid not in have]
                if len(missing) != 1:
                    continue
                known = [sid for sid in xor_of if sid in source_set and sid in have]
                if len(known) + 1 != len(xor_of):
                    continue
                try:
                    max_len = max([len(rep_payload)] + [len(have[sid]) for sid in known])
                except ValueError:
                    continue
                out = bytearray(_pad(rep_payload, max_len))
                for sid in known:
                    _xor_inplace(out, _pad(have[sid], max_len))
                target = missing[0]
                payload = _trim_to_spec(bytes(out), source_specs.get(target, {}))
                try:
                    validate_source(target, payload, source_specs.get(target, {}))
                except Exception as e:
                    errors.append(str(e))
                    continue
                if target not in have:
                    have[target] = payload
                    recovered.append(target)
                    progressed = True

        if progressed:
            continue

        # Second pass: solve remaining unknowns by full-rank linear system per block.
        for block_id, source_ids in source_by_block.items():
            missing = [sid for sid in source_ids if sid not in have]
            if not missing:
                continue
            solved = _solve_block_unknowns(
                block_id=block_id,
                missing_ids=missing,
                source_ids=source_ids,
                have=have,
                source_specs=source_specs,
                repair_by_block=repair_by_block,
                validate_source=validate_source,
                errors=errors,
            )
            if not solved:
                continue
            for sid, payload in solved.items():
                if sid in have:
                    continue
                have[sid] = payload
                recovered.append(sid)
                progressed = True

    return recovered


def _build_source_block_index(source_specs: Mapping[str, Mapping[str, object]]) -> dict[str, list[str]]:
    grouped: dict[str, list[tuple[int, str]]] = defaultdict(list)
    fallback: dict[str, list[str]] = defaultdict(list)
    for sid in source_specs.keys():
        parsed = parse_source_symbol_id(sid)
        if parsed is None:
            fallback["unknown:0"].append(sid)
            continue
        block_id, symbol_idx = parsed
        grouped[block_id].append((symbol_idx, sid))
    out: dict[str, list[str]] = {}
    for block_id, rows in grouped.items():
        out[block_id] = [sid for _idx, sid in sorted(rows, key=lambda x: x[0])]
    for block_id, rows in fallback.items():
        out[block_id] = sorted(rows)
    return out


def _build_repair_block_index(
    repair_specs: Mapping[str, Mapping[str, object]],
    *,
    valid_source_ids: set[str],
) -> dict[str, dict[str, tuple[str, ...]]]:
    out: dict[str, dict[str, tuple[str, ...]]] = defaultdict(dict)
    for rid, rep in repair_specs.items():
        parsed = parse_repair_symbol_id(rid)
        if parsed is None:
            continue
        block_id, _repair_idx = parsed
        xor_of_obj = rep.get("xor_of")
        if not isinstance(xor_of_obj, list):
            continue
        source_ids: list[str] = []
        bad = False
        for x in cast(list[object], xor_of_obj):
            if not isinstance(x, str):
                bad = True
                break
            if x not in valid_source_ids:
                bad = True
                break
            source_ids.append(x)
        if bad or not source_ids:
            continue
        out[block_id][rid] = tuple(source_ids)
    return out


def _solve_block_unknowns(
    *,
    block_id: str,
    missing_ids: list[str],
    source_ids: list[str],
    have: dict[str, bytes],
    source_specs: Mapping[str, Mapping[str, object]],
    repair_by_block: Mapping[str, Mapping[str, tuple[str, ...]]],
    validate_source: Callable[[str, bytes, Mapping[str, object]], None],
    errors: list[str],
) -> dict[str, bytes]:
    unknown = sorted(missing_ids, key=_sort_key_for_symbol_id)
    if not unknown:
        return {}
    col = {sid: i for i, sid in enumerate(unknown)}
    max_len = 0
    for sid in source_ids:
        n = _spec_size(source_specs.get(sid, {}))
        if n is not None:
            max_len = max(max_len, n)
        if sid in have:
            max_len = max(max_len, len(have[sid]))
    for rid in repair_by_block.get(block_id, {}).keys():
        if rid in have:
            max_len = max(max_len, len(have[rid]))
    if max_len <= 0:
        return {}

    source_set = set(source_ids)
    rows: list[tuple[int, bytearray]] = []
    for rid, xor_of in repair_by_block.get(block_id, {}).items():
        rep_payload = have.get(rid)
        if rep_payload is None:
            continue
        rhs = bytearray(_pad(rep_payload, max_len))
        mask = 0
        unresolved = False
        for sid in xor_of:
            if sid not in source_set:
                unresolved = True
                break
            idx = col.get(sid)
            if idx is not None:
                mask |= 1 << idx
                continue
            payload = have.get(sid)
            if payload is None:
                unresolved = True
                break
            _xor_inplace(rhs, _pad(payload, max_len))
        if unresolved:
            continue
        if mask == 0:
            if any(rhs):
                errors.append(f"Inconsistent repair equation {rid} on block {block_id}")
            continue
        rows.append((mask, rhs))

    solved_rows = _solve_rows_full_rank(rows=rows, var_count=len(unknown))
    if solved_rows is None:
        errors.append(f"Inconsistent XOR equations on block {block_id}")
        return {}
    if solved_rows == []:
        return {}

    out: dict[str, bytes] = {}
    for sid, idx in col.items():
        rec = bytes(solved_rows[idx])
        rec = _trim_to_spec(rec, source_specs.get(sid, {}))
        try:
            validate_source(sid, rec, source_specs.get(sid, {}))
        except Exception as e:
            errors.append(str(e))
            continue
        out[sid] = rec
    return out


def _solve_rows_full_rank(*, rows: list[tuple[int, bytearray]], var_count: int) -> list[bytearray] | None:
    if var_count <= 0:
        return []
    pivots: dict[int, tuple[int, bytearray]] = {}
    width = 0
    for mask, rhs in rows:
        width = max(width, len(rhs))
        m = mask
        r = bytearray(rhs)
        while m:
            lead = m.bit_length() - 1
            pivot = pivots.get(lead)
            if pivot is None:
                pivots[lead] = (m, r)
                break
            pm, pr = pivot
            m ^= pm
            _xor_inplace(r, pr)
        if m == 0 and any(r):
            return None

    if len(pivots) < var_count:
        return []

    leads_desc = sorted(pivots.keys(), reverse=True)
    for lead in leads_desc:
        pm, pr = pivots[lead]
        for other in list(pivots.keys()):
            if other == lead:
                continue
            om, orhs = pivots[other]
            if ((om >> lead) & 1) == 0:
                continue
            om ^= pm
            _xor_inplace(orhs, pr)
            pivots[other] = (om, orhs)

    solved = [bytearray(width) for _ in range(var_count)]
    for lead, (mask, rhs) in pivots.items():
        if mask != (1 << lead):
            return []
        if lead >= var_count:
            continue
        solved[lead][: len(rhs)] = rhs
    return solved


def _gf2_rank(masks: list[int]) -> int:
    basis: dict[int, int] = {}
    for row in masks:
        x = row
        while x:
            lead = x.bit_length() - 1
            pivot = basis.get(lead)
            if pivot is None:
                basis[lead] = x
                break
            x ^= pivot
    return len(basis)


def _spec_size(spec: Mapping[str, object]) -> int | None:
    n = spec.get("size")
    if isinstance(n, bool):
        return None
    if isinstance(n, int) and n >= 0:
        return n
    return None


def _trim_to_spec(data: bytes, spec: Mapping[str, object]) -> bytes:
    n = _spec_size(spec)
    if n is None:
        return data
    if n <= len(data):
        return data[:n]
    return data + (b"\x00" * (n - len(data)))


def _pad(data: bytes, n: int) -> bytes:
    if len(data) >= n:
        return data
    return data + (b"\x00" * (n - len(data)))


def _xor_inplace(dst: bytearray, src: bytes) -> None:
    n = min(len(dst), len(src))
    for i in range(n):
        dst[i] ^= src[i]


def _sort_key_for_symbol_id(symbol_id: str) -> tuple[int, str]:
    parsed = parse_source_symbol_id(symbol_id)
    if parsed is None:
        return (10**9, symbol_id)
    _block, idx = parsed
    return (idx, symbol_id)

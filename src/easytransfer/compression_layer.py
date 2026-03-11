from __future__ import annotations

import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from .utils import JSONValue, ensure_json_object

try:
    import bz2 as _bz2
except Exception:
    _bz2 = None

try:
    import lzma as _lzma
except Exception:
    _lzma = None


MiB = 1024 * 1024

_GZIP_WBITS = zlib.MAX_WBITS | 16
_DEFLATE_WBITS = -zlib.MAX_WBITS


def _require_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    if isinstance(value, float):
        if not value.is_integer():
            raise ValueError(f"{field} must be an integer")
        return int(value)
    raise ValueError(f"{field} must be an integer")


class DecompressionError(ValueError):
    """Raised when compressed data is invalid or unsafe to decompress."""

    pass


def _policy_level(policy: "CompressionPolicy", *, default_level: int = 6) -> int:
    if policy == CompressionPolicy.FAST_STREAM:
        return 1
    if policy == CompressionPolicy.BEST_RATIO:
        return 9
    if policy == CompressionPolicy.BALANCED:
        return default_level
    return default_level


def _decompress_zlib_stream(
    data: bytes,
    *,
    limits: "DecompressionLimits",
    wbits: int,
    stream_name: str,
) -> bytes:
    limits.validate()
    if len(data) > limits.max_input_bytes:
        raise DecompressionError("compressed input exceeds max_input_bytes")
    d = zlib.decompressobj(wbits)
    out = bytearray()
    remaining = limits.max_output_bytes
    chunk = d.decompress(data, remaining)
    out += chunk
    remaining -= len(chunk)
    while not d.eof:
        if remaining <= 0:
            raise DecompressionError("decompressed output exceeds max_output_bytes")
        chunk = d.decompress(b"", remaining)
        if not chunk:
            break
        out += chunk
        remaining -= len(chunk)
    if not d.eof:
        raise DecompressionError(f"truncated {stream_name} stream")
    if d.unused_data:
        raise DecompressionError("unexpected trailing data")
    _check_decompression_limits(limits, compressed_len=len(data), emitted_len=len(out))
    return bytes(out)


@dataclass(frozen=True, slots=True)
class DecompressionLimits:
    """Hard limits to prevent decompression bombs."""

    max_output_bytes: int = 256 * MiB
    max_ratio: float = 200.0
    max_input_bytes: int = 256 * MiB

    def validate(self) -> None:
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if self.max_input_bytes <= 0:
            raise ValueError("max_input_bytes must be positive")
        if self.max_ratio <= 0:
            raise ValueError("max_ratio must be positive")


class CompressionPolicy(str, Enum):
    AUTO = "auto"
    NONE = "none"
    BEST_RATIO = "best_ratio"
    BALANCED = "balanced"
    FAST_STREAM = "fast_stream"


@dataclass(frozen=True, slots=True)
class CompressionEnvelope:
    codec: str
    original_size: int
    compressed_size: int
    params: dict[str, JSONValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "codec": self.codec,
            "original_size": int(self.original_size),
            "compressed_size": int(self.compressed_size),
            "params": dict(self.params),
        }

    @staticmethod
    def from_dict(d: Mapping[str, object]) -> "CompressionEnvelope":
        return CompressionEnvelope(
            codec=str(d["codec"]),
            original_size=_require_int(d["original_size"], field="original_size"),
            compressed_size=_require_int(d["compressed_size"], field="compressed_size"),
            params=ensure_json_object(d.get("params", {})),
        )


class Codec(Protocol):
    name: str

    def compress(self, data: bytes, *, policy: CompressionPolicy) -> tuple[bytes, dict[str, JSONValue]]:
        ...

    def decompress(self, data: bytes, *, limits: DecompressionLimits, params: Mapping[str, JSONValue]) -> bytes:
        ...


class _NoneCodec:
    name: str = "none"

    def compress(self, data: bytes, *, policy: CompressionPolicy) -> tuple[bytes, dict[str, JSONValue]]:
        _ = policy
        return data, {}

    def decompress(self, data: bytes, *, limits: DecompressionLimits, params: Mapping[str, JSONValue]) -> bytes:
        _ = params
        _check_decompression_limits(limits, compressed_len=len(data), emitted_len=len(data))
        return data


class _ZlibCodec:
    name: str = "zlib"

    def compress(self, data: bytes, *, policy: CompressionPolicy) -> tuple[bytes, dict[str, JSONValue]]:
        level = _policy_level(policy, default_level=6)
        return zlib.compress(data, level), {"level": level}

    def decompress(self, data: bytes, *, limits: DecompressionLimits, params: Mapping[str, JSONValue]) -> bytes:
        _ = params
        return _decompress_zlib_stream(data, limits=limits, wbits=zlib.MAX_WBITS, stream_name="zlib")


class _GzipCodec:
    name: str = "gzip"

    def compress(self, data: bytes, *, policy: CompressionPolicy) -> tuple[bytes, dict[str, JSONValue]]:
        level = _policy_level(policy, default_level=6)
        comp = zlib.compressobj(level=level, method=zlib.DEFLATED, wbits=_GZIP_WBITS)
        out = comp.compress(data) + comp.flush()
        return out, {"level": level}

    def decompress(self, data: bytes, *, limits: DecompressionLimits, params: Mapping[str, JSONValue]) -> bytes:
        _ = params
        return _decompress_zlib_stream(data, limits=limits, wbits=_GZIP_WBITS, stream_name="gzip")


class _DeflateCodec:
    name: str = "deflate"

    def compress(self, data: bytes, *, policy: CompressionPolicy) -> tuple[bytes, dict[str, JSONValue]]:
        level = _policy_level(policy, default_level=6)
        comp = zlib.compressobj(level=level, method=zlib.DEFLATED, wbits=_DEFLATE_WBITS)
        out = comp.compress(data) + comp.flush()
        return out, {"level": level}

    def decompress(self, data: bytes, *, limits: DecompressionLimits, params: Mapping[str, JSONValue]) -> bytes:
        _ = params
        return _decompress_zlib_stream(data, limits=limits, wbits=_DEFLATE_WBITS, stream_name="deflate")


class _Bz2Codec:
    name: str = "bz2"

    def compress(self, data: bytes, *, policy: CompressionPolicy) -> tuple[bytes, dict[str, JSONValue]]:
        if _bz2 is None:
            raise RuntimeError("bz2 not available")
        level = _policy_level(policy, default_level=6)
        return _bz2.compress(data, compresslevel=level), {"level": level}

    def decompress(self, data: bytes, *, limits: DecompressionLimits, params: Mapping[str, JSONValue]) -> bytes:
        _ = params
        if _bz2 is None:
            raise DecompressionError("bz2 not available")
        limits.validate()
        if len(data) > limits.max_input_bytes:
            raise DecompressionError("compressed input exceeds max_input_bytes")
        dec = _bz2.BZ2Decompressor()
        out = bytearray()
        remaining = limits.max_output_bytes
        try:
            chunk = dec.decompress(data, max_length=remaining)
        except EOFError as e:
            raise DecompressionError("invalid bz2 stream") from e
        out += chunk
        remaining -= len(chunk)
        while remaining > 0 and not dec.eof:
            try:
                chunk = dec.decompress(b"", max_length=remaining)
            except EOFError:
                break
            if not chunk:
                break
            out += chunk
            remaining -= len(chunk)
        if not dec.eof:
            if remaining == 0:
                raise DecompressionError("decompressed output exceeds max_output_bytes")
            raise DecompressionError("truncated bz2 stream")
        if dec.unused_data:
            raise DecompressionError("unexpected trailing data")
        _check_decompression_limits(limits, compressed_len=len(data), emitted_len=len(out))
        return bytes(out)


class _LzmaCodec:
    name: str = "lzma"

    def compress(self, data: bytes, *, policy: CompressionPolicy) -> tuple[bytes, dict[str, JSONValue]]:
        if _lzma is None:
            raise RuntimeError("lzma not available")
        preset = _policy_level(policy, default_level=6)
        return _lzma.compress(data, preset=preset, format=_lzma.FORMAT_XZ), {"preset": preset, "format": "xz"}

    def decompress(self, data: bytes, *, limits: DecompressionLimits, params: Mapping[str, JSONValue]) -> bytes:
        _ = params
        if _lzma is None:
            raise DecompressionError("lzma not available")
        limits.validate()
        if len(data) > limits.max_input_bytes:
            raise DecompressionError("compressed input exceeds max_input_bytes")
        dec = _lzma.LZMADecompressor(format=_lzma.FORMAT_XZ)
        out = bytearray()
        remaining = limits.max_output_bytes
        chunk = dec.decompress(data, max_length=remaining)
        out += chunk
        remaining -= len(chunk)
        while not dec.eof:
            if remaining <= 0:
                raise DecompressionError("decompressed output exceeds max_output_bytes")
            chunk = dec.decompress(b"", max_length=remaining)
            if not chunk:
                break
            out += chunk
            remaining -= len(chunk)
        if not dec.eof:
            raise DecompressionError("truncated lzma stream")
        if dec.unused_data:
            raise DecompressionError("unexpected trailing data")
        _check_decompression_limits(limits, compressed_len=len(data), emitted_len=len(out))
        return bytes(out)


def _check_decompression_limits(limits: DecompressionLimits, *, compressed_len: int, emitted_len: int) -> None:
    if emitted_len > limits.max_output_bytes:
        raise DecompressionError("decompressed output exceeds max_output_bytes")
    if compressed_len <= 0:
        if emitted_len > 0:
            raise DecompressionError("invalid empty compressed input")
        return
    ratio = emitted_len / float(compressed_len)
    if ratio > limits.max_ratio:
        raise DecompressionError("decompression ratio exceeds max_ratio")


class CompressionRegistry:
    """Registry of available codecs (runtime-detected)."""

    def __init__(self) -> None:
        self._codecs: dict[str, Codec] = {}

    def register(self, codec: Codec) -> None:
        self._codecs[codec.name] = codec

    def get(self, name: str) -> Codec:
        try:
            return self._codecs[name]
        except KeyError as e:
            raise KeyError(f"Unknown codec: {name}") from e

    def available(self) -> tuple[str, ...]:
        return tuple(sorted(self._codecs.keys()))


def build_default_registry() -> CompressionRegistry:
    """Create a registry using stdlib codecs available at runtime."""

    reg = CompressionRegistry()
    reg.register(_NoneCodec())
    reg.register(_ZlibCodec())
    reg.register(_GzipCodec())
    reg.register(_DeflateCodec())
    if _bz2 is not None:
        reg.register(_Bz2Codec())
    if _lzma is not None:
        reg.register(_LzmaCodec())
    return reg


def build_transfer_registry() -> CompressionRegistry:
    """Create an interop registry shared across sender/scanner/receiver apps."""

    reg = CompressionRegistry()
    reg.register(_NoneCodec())
    reg.register(_ZlibCodec())
    reg.register(_GzipCodec())
    reg.register(_DeflateCodec())
    return reg


def _auto_policy_for_size(n: int) -> CompressionPolicy:
    if n <= 1 * MiB:
        return CompressionPolicy.BEST_RATIO
    if n <= 32 * MiB:
        return CompressionPolicy.BALANCED
    return CompressionPolicy.FAST_STREAM


def compress_bytes(
    data: bytes,
    *,
    registry: CompressionRegistry | None = None,
    policy: CompressionPolicy = CompressionPolicy.AUTO,
) -> tuple[CompressionEnvelope, bytes]:
    """Compress *data* and return (envelope, compressed_bytes)."""

    reg = registry or build_default_registry()
    if policy == CompressionPolicy.AUTO:
        policy = _auto_policy_for_size(len(data))

    if policy == CompressionPolicy.NONE:
        codec = reg.get("none")
        compressed, params = codec.compress(data, policy=policy)
        env = CompressionEnvelope(codec=codec.name, original_size=len(data), compressed_size=len(compressed), params=params)
        return env, compressed

    if len(data) <= 1 * MiB and policy == CompressionPolicy.BEST_RATIO:
        best_env: CompressionEnvelope | None = None
        best_payload: bytes | None = None
        for name in reg.available():
            codec = reg.get(name)
            payload, params = codec.compress(data, policy=CompressionPolicy.BEST_RATIO)
            env = CompressionEnvelope(codec=name, original_size=len(data), compressed_size=len(payload), params=params)
            if best_env is None or env.compressed_size < best_env.compressed_size:
                best_env, best_payload = env, payload
        if best_env is None or best_payload is None:
            raise RuntimeError("no codecs available")
        return best_env, best_payload

    if policy == CompressionPolicy.BEST_RATIO:
        codec = reg.get("lzma") if "lzma" in reg.available() else reg.get("bz2") if "bz2" in reg.available() else reg.get("zlib")
    elif policy == CompressionPolicy.FAST_STREAM:
        codec = reg.get("zlib")
    else:
        codec = reg.get("zlib")

    compressed, params = codec.compress(data, policy=policy)
    if len(data) and codec.name != "none" and len(compressed) >= len(data):
        codec = reg.get("none")
        compressed, params = codec.compress(data, policy=CompressionPolicy.NONE)
    env = CompressionEnvelope(codec=codec.name, original_size=len(data), compressed_size=len(compressed), params=params)
    return env, compressed


def decompress_bytes(
    envelope: CompressionEnvelope,
    data: bytes,
    *,
    registry: CompressionRegistry | None = None,
    limits: DecompressionLimits | None = None,
) -> bytes:
    """Decompress using *envelope* with safety limits."""

    reg = registry or build_default_registry()
    lim = limits or DecompressionLimits()
    lim.validate()
    if envelope.original_size > lim.max_output_bytes:
        raise DecompressionError("original_size exceeds max_output_bytes")
    if envelope.compressed_size != len(data):
        raise DecompressionError("compressed_size mismatch")
    if envelope.original_size < 0 or envelope.compressed_size < 0:
        raise DecompressionError("negative size in envelope")
    try:
        codec = reg.get(envelope.codec)
    except KeyError as e:
        raise DecompressionError(str(e)) from e
    out = codec.decompress(data, limits=lim, params=envelope.params)
    if envelope.original_size != len(out):
        raise DecompressionError("original_size mismatch")
    return out

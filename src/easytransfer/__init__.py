from __future__ import annotations

from .compression_layer import (
    CompressionEnvelope,
    CompressionPolicy,
    CompressionRegistry,
    DecompressionError,
    DecompressionLimits,
    build_default_registry,
    build_transfer_registry,
    compress_bytes,
    decompress_bytes,
)
from .models import ManifestFileEntry, TransferManifest
from .protocol import (
    Frame,
    FrameType,
    NeedMoreData,
    decode_enveloped_payload,
    decode_frame,
    encode_enveloped_payload,
    encode_frame,
    iter_decode_frames,
    xor_parity,
    xor_recover_one,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "CompressionEnvelope",
    "CompressionPolicy",
    "CompressionRegistry",
    "DecompressionError",
    "DecompressionLimits",
    "build_default_registry",
    "build_transfer_registry",
    "compress_bytes",
    "decompress_bytes",
    "ManifestFileEntry",
    "TransferManifest",
    "Frame",
    "FrameType",
    "NeedMoreData",
    "encode_frame",
    "decode_frame",
    "iter_decode_frames",
    "encode_enveloped_payload",
    "decode_enveloped_payload",
    "xor_parity",
    "xor_recover_one",
]

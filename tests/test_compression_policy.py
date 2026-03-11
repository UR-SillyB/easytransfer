from __future__ import annotations

import unittest

from easytransfer.compression_layer import (
    CompressionEnvelope,
    CompressionPolicy,
    DecompressionLimits,
    build_default_registry,
    build_transfer_registry,
    compress_bytes,
    decompress_bytes,
)


class CompressionPolicyTests(unittest.TestCase):
    def test_small_file_auto_picks_best_available_ratio(self) -> None:
        data = (b"A" * 1024) * 200
        reg = build_default_registry()

        env_auto, payload_auto = compress_bytes(data, registry=reg, policy=CompressionPolicy.AUTO)

        compressed_sizes = {}
        for name in reg.available():
            codec = reg.get(name)
            payload, _params = codec.compress(data, policy=CompressionPolicy.BEST_RATIO)
            compressed_sizes[name] = len(payload)

        min_size = min(compressed_sizes.values())
        self.assertEqual(env_auto.compressed_size, min_size)
        self.assertEqual(len(payload_auto), min_size)

    def test_transfer_registry_contains_only_interop_codecs(self) -> None:
        reg = build_transfer_registry()
        self.assertEqual(set(reg.available()), {"none", "zlib", "gzip", "deflate"})

    def test_transfer_registry_roundtrip_for_all_codecs(self) -> None:
        data = (b"hello-world-" * 800) + bytes(range(64))
        reg = build_transfer_registry()
        for name in reg.available():
            codec = reg.get(name)
            payload, params = codec.compress(data, policy=CompressionPolicy.BALANCED)
            checked = decompress_bytes(
                CompressionEnvelope(codec=name, original_size=len(data), compressed_size=len(payload), params=params),
                payload,
                registry=reg,
                limits=DecompressionLimits(max_output_bytes=16 * 1024 * 1024, max_input_bytes=16 * 1024 * 1024, max_ratio=2000.0),
            )
            self.assertEqual(checked, data)


if __name__ == "__main__":
    unittest.main()

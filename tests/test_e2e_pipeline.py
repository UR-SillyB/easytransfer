from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from easytransfer.receiver_pipeline import run_receiver
from easytransfer.scanner_pipeline import scan_frames
from easytransfer.sender_pipeline import run_sender_pipeline


class EndToEndPipelineTests(unittest.TestCase):
    def test_sender_scanner_receiver_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            input_dir = root / "input"
            send_dir = root / "send"
            scan_dir = root / "scan"
            recv_dir = root / "recv"
            input_dir.mkdir(parents=True, exist_ok=True)

            (input_dir / "a.txt").write_text("hello" * 2000, encoding="utf-8")
            (input_dir / "b.bin").write_bytes(b"x" * 50000)

            manifest_path, frames_path = run_sender_pipeline(
                input_path=str(input_dir),
                output_dir=str(send_dir),
                block_size=32768,
                symbol_size=1024,
                redundancy=0.25,
                fps=30.0,
            )
            scan_frames(
                frames_path=str(frames_path),
                output_dir=str(scan_dir),
                loss_rate=0.0,
                burst_rate=0.0,
                seed=1,
            )
            report = run_receiver(
                input_path=str(scan_dir / "received.jsonl"),
                manifest_path=str(manifest_path),
                output_dir=str(recv_dir),
            )

            self.assertTrue(report.ok)
            self.assertEqual(sorted(report.files_failed), [])
            self.assertEqual(
                (recv_dir / "a.txt").read_text(encoding="utf-8"),
                (input_dir / "a.txt").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (recv_dir / "b.bin").read_bytes(),
                (input_dir / "b.bin").read_bytes(),
            )

    def test_receiver_recovers_one_missing_source_symbol_with_repair(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            input_dir = root / "input"
            send_dir = root / "send"
            scan_dir = root / "scan"
            recv_dir = root / "recv"
            input_dir.mkdir(parents=True, exist_ok=True)

            data = ("recover-me-" * 1200).encode("utf-8")
            (input_dir / "recover.txt").write_bytes(data)

            manifest_path, frames_path = run_sender_pipeline(
                input_path=str(input_dir),
                output_dir=str(send_dir),
                block_size=65536,
                symbol_size=1024,
                redundancy=0.5,
                fps=30.0,
            )

            frames = []
            with frames_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    frames.append(json.loads(line))

            target_source_symbol = None
            for rec in frames:
                if rec.get("kind") == "symbol" and rec.get("redundant") is False:
                    target_source_symbol = rec.get("symbol_id")
                    break
            self.assertIsNotNone(target_source_symbol)

            scan_dir.mkdir(parents=True, exist_ok=True)
            received_path = scan_dir / "received.jsonl"
            with received_path.open("w", encoding="utf-8") as out:
                for rec in frames:
                    if rec.get("kind") != "symbol":
                        continue
                    if rec.get("symbol_id") == target_source_symbol:
                        continue
                    out_rec = {
                        "symbol_id": rec.get("symbol_id"),
                        "data_b64": rec.get("payload_b64"),
                        "path": rec.get("path"),
                        "file_id": rec.get("file_id"),
                        "block": rec.get("block"),
                        "symbol": rec.get("symbol"),
                        "redundant": rec.get("redundant"),
                    }
                    out.write(json.dumps(out_rec, ensure_ascii=False) + "\n")

            report = run_receiver(
                input_path=str(received_path),
                manifest_path=str(manifest_path),
                output_dir=str(recv_dir),
            )

            self.assertTrue(report.ok)
            self.assertIn(target_source_symbol, report.recovered_source_symbols)
            self.assertEqual(
                (recv_dir / "recover.txt").read_bytes(),
                (input_dir / "recover.txt").read_bytes(),
            )

    def test_receiver_recovers_multiple_missing_sources_with_linear_solver(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            input_dir = root / "input"
            send_dir = root / "send"
            recv_dir = root / "recv"
            scan_dir = root / "scan"
            input_dir.mkdir(parents=True, exist_ok=True)

            payload = random.Random(123).randbytes(4096)
            (input_dir / "f.bin").write_bytes(payload)

            manifest_path, frames_path = run_sender_pipeline(
                input_path=str(input_dir),
                output_dir=str(send_dir),
                block_size=4096,
                symbol_size=512,
                redundancy=0.5,
                fps=30.0,
            )

            with manifest_path.open("r", encoding="utf-8") as mf:
                manifest = json.load(mf)
            source_ids = manifest["files"][0]["source_symbol_ids"]
            self.assertGreaterEqual(len(source_ids), 8)
            drop_ids = {source_ids[1], source_ids[2]}

            frames = []
            with frames_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    if rec.get("kind") == "symbol":
                        frames.append(rec)

            scan_dir.mkdir(parents=True, exist_ok=True)
            received_path = scan_dir / "received.jsonl"
            with received_path.open("w", encoding="utf-8") as out:
                for rec in frames:
                    sid = rec.get("symbol_id")
                    if sid in drop_ids:
                        continue
                    out.write(
                        json.dumps(
                            {
                                "symbol_id": sid,
                                "data_b64": rec.get("payload_b64"),
                                "payload_b64": rec.get("payload_b64"),
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

            report = run_receiver(
                input_path=str(received_path),
                manifest_path=str(manifest_path),
                output_dir=str(recv_dir),
            )

            self.assertTrue(report.ok)
            for sid in drop_ids:
                self.assertIn(sid, report.recovered_source_symbols)
            self.assertEqual((recv_dir / "f.bin").read_bytes(), payload)

    def test_scanner_recommendation_not_false_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            input_dir = root / "input"
            send_dir = root / "send"
            scan_dir = root / "scan"
            recv_dir = root / "recv"
            input_dir.mkdir(parents=True, exist_ok=True)

            payload = random.Random(123).randbytes(4096)
            (input_dir / "f.bin").write_bytes(payload)

            manifest_path, frames_path = run_sender_pipeline(
                input_path=str(input_dir),
                output_dir=str(send_dir),
                block_size=4096,
                symbol_size=512,
                redundancy=0.5,
                fps=30.0,
            )

            result = scan_frames(
                frames_path=str(frames_path),
                output_dir=str(scan_dir),
                loss_rate=0.16,
                burst_rate=0.0,
                seed=1,
            )
            report = run_receiver(
                input_path=str(scan_dir / "received.jsonl"),
                manifest_path=str(manifest_path),
                output_dir=str(recv_dir),
            )

            recommendation = result.feedback.get("recommendation", {})
            total_need = recommendation.get("total_need_repair", 0)
            if not report.ok:
                self.assertIsInstance(total_need, int)
                self.assertGreater(total_need, 0)
            else:
                self.assertEqual(total_need, 0)

    def test_receiver_accepts_payload_only_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            input_dir = root / "input"
            send_dir = root / "send"
            recv_dir = root / "recv"
            scan_dir = root / "scan"
            input_dir.mkdir(parents=True, exist_ok=True)

            (input_dir / "x.txt").write_text("payload-only-format" * 500, encoding="utf-8")

            manifest_path, frames_path = run_sender_pipeline(
                input_path=str(input_dir),
                output_dir=str(send_dir),
                block_size=32768,
                symbol_size=1024,
                redundancy=0.2,
                fps=30.0,
            )

            scan_dir.mkdir(parents=True, exist_ok=True)
            received_path = scan_dir / "received.jsonl"
            with frames_path.open("r", encoding="utf-8") as f, received_path.open("w", encoding="utf-8") as out:
                for line in f:
                    rec = json.loads(line)
                    if rec.get("kind") != "symbol":
                        continue
                    out.write(
                        json.dumps(
                            {
                                "symbol_id": rec.get("symbol_id"),
                                "payload_b64": rec.get("payload_b64"),
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

            report = run_receiver(
                input_path=str(received_path),
                manifest_path=str(manifest_path),
                output_dir=str(recv_dir),
            )
            self.assertTrue(report.ok)
            self.assertEqual((recv_dir / "x.txt").read_text(encoding="utf-8"), (input_dir / "x.txt").read_text(encoding="utf-8"))

    def test_scanner_accepts_block_id_symbol_index_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            send_dir = root / "send"
            scan_dir = root / "scan"
            send_dir.mkdir(parents=True, exist_ok=True)

            payload = "aGVsbG8="
            frames_path = send_dir / "frames.jsonl"
            frames_path.write_text(
                "\n".join(
                    [
                        json.dumps({"v": 1, "kind": "header", "stream_id": "tid"}),
                        json.dumps(
                            {
                                "v": 1,
                                "kind": "symbol",
                                "transfer_id": "tid",
                                "file_id": 0,
                                "block_id": 0,
                                "symbol_index": 0,
                                "source_symbol_total": 1,
                                "is_repair": False,
                                "symbol_id": "tid:f0:b0:s0",
                                "payload_b64": payload,
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = scan_frames(
                frames_path=str(frames_path),
                output_dir=str(scan_dir),
                loss_rate=0.0,
                burst_rate=0.0,
                seed=7,
            )
            lines = (scan_dir / "received.jsonl").read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertEqual(rec["symbol_id"], "tid:f0:b0:s0")
            self.assertEqual(rec["block_id"], 0)
            self.assertEqual(rec["symbol_index"], 0)
            recommendation = result.feedback.get("recommendation", {})
            self.assertEqual(recommendation.get("total_need_repair"), 0)


if __name__ == "__main__":
    unittest.main()

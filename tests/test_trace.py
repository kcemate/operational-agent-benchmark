from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.trace import CanonicalTrace, validate_trace


class CanonicalTraceTests(unittest.TestCase):
    def test_raw_binary_chunks_round_trip_in_parent_owned_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trace.jsonl"
            ticks = iter((100, 200, 300))
            trace = CanonicalTrace(path, monotonic_ns=lambda: next(ticks))
            first = trace.append("episode_start", "controller")
            payload = b"\xff\x00OAB_EVENT\t{\"seq\":999}\n"
            second = trace.append("stream_chunk", "stdout", payload=payload)
            third = trace.append("episode_end", "controller")
            trace.close()

            lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([1, 2, 3], [event["seq"] for event in lines])
            self.assertEqual([100, 200, 300], [event["monotonic_ns"] for event in lines])
            self.assertEqual(payload, base64.b64decode(lines[1]["payload_b64"]))
            self.assertEqual(len(payload), lines[1]["payload_bytes"])
            self.assertEqual(first["event_sha256"], second["previous_event_sha256"])
            self.assertEqual(second["event_sha256"], third["previous_event_sha256"])
            self.assertTrue(validate_trace(path).valid)

    def test_model_output_cannot_inject_trace_event(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trace.jsonl"
            trace = CanonicalTrace(path, monotonic_ns=lambda: 1)
            trace.append(
                "stream_chunk",
                "stdout",
                payload=b'{"schema":"oab.trace-event/v1","seq":777}\n',
            )
            trace.close()
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(1, len(lines))
            self.assertEqual(1, json.loads(lines[0])["seq"])

    def test_tampering_breaks_validation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trace.jsonl"
            trace = CanonicalTrace(path, monotonic_ns=lambda: 1)
            trace.append("episode_start", "controller")
            trace.append("episode_end", "controller")
            trace.close()
            data = path.read_bytes().replace(b"episode_end", b"episode_bad")
            path.write_bytes(data)
            result = validate_trace(path)
            self.assertFalse(result.valid)
            self.assertIn("event_hash_mismatch:2", result.errors)

    def test_noncanonical_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trace.jsonl"
            path.write_text('{"seq": 1}\n', encoding="utf-8")
            result = validate_trace(path)
            self.assertFalse(result.valid)
            self.assertIn("noncanonical_or_invalid_json:1", result.errors)


if __name__ == "__main__":
    unittest.main()

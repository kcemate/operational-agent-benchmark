from __future__ import annotations

import unittest

from tools.run_model_smoke import _behavioral_observation_valid, _smoke_exit_code


class ModelSmokeStatusTests(unittest.TestCase):
    def valid_record(self) -> dict[str, object]:
        return {
            "runner_status": "completed",
            "valid_for_authoritative_scoring": False,
            "reason_codes": ["provider_identity_source_unverified"],
            "all_declared_gates_passed": True,
            "controller_usage": {"api_calls": 1, "input_tokens": 10, "output_tokens": 2},
            "trace_sha256": "sha256:" + "1" * 64,
            "output_tree_sha256": "sha256:" + "2" * 64,
        }

    def test_valid_provisional_behavioral_observation_succeeds(self) -> None:
        record = self.valid_record()
        self.assertTrue(_behavioral_observation_valid(record))
        self.assertEqual(0, _smoke_exit_code([record]))

    def test_runner_invalid_cannot_succeed_even_when_gates_pass(self) -> None:
        record = self.valid_record()
        record["runner_status"] = "runner_invalid"
        self.assertFalse(_behavioral_observation_valid(record))
        self.assertEqual(2, _smoke_exit_code([record]))

    def test_zero_model_calls_cannot_succeed(self) -> None:
        record = self.valid_record()
        record["controller_usage"] = {"api_calls": 0, "input_tokens": 0, "output_tokens": 0}
        self.assertFalse(_behavioral_observation_valid(record))
        self.assertEqual(2, _smoke_exit_code([record]))

    def test_missing_trace_digest_cannot_succeed(self) -> None:
        record = self.valid_record()
        record["trace_sha256"] = None
        self.assertFalse(_behavioral_observation_valid(record))
        self.assertEqual(2, _smoke_exit_code([record]))

    def test_unexpected_identity_reason_cannot_succeed(self) -> None:
        record = self.valid_record()
        record["reason_codes"] = ["controller_identity_adapter_digest_invalid"]
        self.assertFalse(_behavioral_observation_valid(record))
        self.assertEqual(2, _smoke_exit_code([record]))


if __name__ == "__main__":
    unittest.main()

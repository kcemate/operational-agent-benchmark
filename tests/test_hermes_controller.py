from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oab.hermes_controller import HermesCliController
from oab.strict_runner import (
    ControllerInfrastructureError,
    FinalResponse,
    ToolRequest,
    ToolResult,
)


FAKE_HERMES = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
if os.environ.get("OAB_TEST_SECRET"):
    sys.exit(97)
args = sys.argv[1:]
if "--safe-mode" in args:
    sys.exit(96)
if os.environ.get("HERMES_SAFE_MODE") != "1" or os.environ.get("HERMES_IGNORE_RULES") != "1":
    sys.exit(95)
if os.environ.get("HERMES_IGNORE_USER_CONFIG"):
    sys.exit(94)
prompt = args[args.index("-z") + 1]
usage = pathlib.Path(args[args.index("--usage-file") + 1])
usage.write_text(json.dumps({
    "model": "test-model",
    "provider": "test-provider",
    "api_calls": 1,
    "input_tokens": 10,
    "output_tokens": 5,
    "estimated_cost_usd": 0.25,
    "cost_status": "estimated",
    "cost_source": "models.dev",
    "session_id": "local-session-1",
    "failed": False,
    "completed": True
}))
if '"history":[]' in prompt:
    print(json.dumps({"kind":"tool","request_id":"r1","tool":"read_text","arguments":{"path":"input/a.txt"}}))
else:
    print(json.dumps({"kind":"final","text":"done"}))
'''


class HermesCliControllerTests(unittest.TestCase):
    def make_executable(self, root: Path) -> Path:
        executable = root / "fake-hermes"
        executable.write_text(FAKE_HERMES)
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return executable

    def test_tool_free_stateless_adapter_replays_protocol_and_marks_identity_attested(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            executable = self.make_executable(Path(td))
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
            )
            with patch.dict(os.environ, {"OAB_TEST_SECRET": "must-not-leak"}):
                identity = controller.begin({
                    "schema": "oab.controller-context/v1",
                    "episode_id": "episode-opaque",
                    "task_utf8": "Read the input.",
                    "input_manifest": {"entries": []},
                    "tools": ["read_text", "write_text", "mock_action"],
                    "allowed_effects": [],
                    "leaf_network_policy": "denied",
                })
            self.assertEqual(identity.returned_route, "test-provider/test-model")
            self.assertEqual(identity.identity_source, "adapter_runtime")
            self.assertEqual(identity.execution_class, "model")
            self.assertRegex(identity.controller_executable_sha256 or "", r"^sha256:[0-9a-f]{64}$")
            first = controller.next(None)
            self.assertIsInstance(first, ToolRequest)
            self.assertEqual(first.arguments["path"], "input/a.txt")
            second = controller.next(ToolResult("r1", True, {"text": "hello"}))
            self.assertIsInstance(second, FinalResponse)
            self.assertEqual(second.text, "done")
            self.assertEqual(controller.total_api_calls, 2)
            self.assertEqual(controller.total_input_tokens, 20)
            self.assertEqual(controller.total_output_tokens, 10)
            usage = controller.usage_snapshot()
            self.assertEqual(2, usage["api_calls"])
            self.assertEqual(20, usage["input_tokens"])
            self.assertEqual(10, usage["output_tokens"])
            self.assertGreaterEqual(usage["latency_ms"], 0.0)
            self.assertEqual(0.5, usage["cost_usd"])
            self.assertEqual(0.5, usage["known_cost_usd"])
            self.assertEqual(0, usage["unknown_cost_api_calls"])

    def test_observed_cost_threshold_stops_after_at_most_one_overshooting_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            executable = self.make_executable(Path(td))
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
                max_observed_cost_usd=0.30,
            )
            controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})
            first = controller.next(None)
            self.assertIsInstance(first, ToolRequest)
            with self.assertRaisesRegex(
                ControllerInfrastructureError, "controller_observed_cost_threshold_exceeded"
            ):
                controller.next(ToolResult("r1", True, {"text": "hello"}))
            usage = controller.usage_snapshot()
            self.assertEqual(2, usage["api_calls"])
            self.assertEqual(0.5, usage["known_cost_usd"])
            self.assertEqual(0, usage["unknown_cost_api_calls"])

    def test_mixed_known_unknown_cost_preserves_known_lower_bound(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            executable = self.make_executable(Path(td))
            executable.write_text(
                FAKE_HERMES.replace(
                    '    "estimated_cost_usd": 0.25,',
                    '    **({"estimated_cost_usd": 0.25} if \'"history":[]\' in prompt else {}),',
                )
            )
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
                allow_unknown_costs=True,
            )
            controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})
            controller.next(None)
            final = controller.next(ToolResult("r1", True, {"text": "hello"}))
            self.assertIsInstance(final, FinalResponse)
            usage = controller.usage_snapshot()
            self.assertIsNone(usage["cost_usd"])
            self.assertEqual(0.25, usage["known_cost_usd"])
            self.assertEqual(1, usage["unknown_cost_api_calls"])

    def test_unknown_cost_posture_stops_after_first_unpriced_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            executable = self.make_executable(Path(td))
            executable.write_text(FAKE_HERMES.replace('    "estimated_cost_usd": 0.25,\n', ""))
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
                allow_unknown_costs=False,
            )
            with self.assertRaisesRegex(
                ControllerInfrastructureError, "controller_cost_telemetry_unknown"
            ):
                controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})
            usage = controller.usage_snapshot()
            self.assertEqual(1, usage["api_calls"])
            self.assertEqual(0.0, usage["known_cost_usd"])
            self.assertEqual(1, usage["unknown_cost_api_calls"])

    def test_missing_api_call_telemetry_is_infrastructure_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            executable = self.make_executable(root)
            executable.write_text(FAKE_HERMES.replace('    "api_calls": 1,\n', ""))
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
            )
            with self.assertRaisesRegex(ControllerInfrastructureError, "controller_usage_invalid"):
                controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})
            self.assertEqual(0, controller.total_api_calls)

    def test_pins_and_attests_reasoning_effort_from_isolated_hermes_home(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            executable = self.make_executable(root)
            hermes_home = root / "runtime-home"
            hermes_home.mkdir()
            config = hermes_home / "config.yaml"
            config.write_text(
                "agent:\n  model: test-model\n  provider: test-provider\n  reasoning_effort: medium\n",
                encoding="utf-8",
            )
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
                hermes_home=hermes_home,
                reasoning_effort="medium",
            )
            controller_work = root / "controller-work"
            controller_work.mkdir()
            environment = controller._environment(controller_work)
            self.assertEqual(environment["HERMES_HOME"], str(hermes_home.resolve()))
            self.assertEqual("1", environment["HERMES_SAFE_MODE"])
            self.assertEqual("1", environment["HERMES_IGNORE_RULES"])
            self.assertNotIn("HERMES_IGNORE_USER_CONFIG", environment)
            identity = controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})
            self.assertEqual(identity.reasoning_effort, "medium")
            self.assertRegex(identity.controller_config_sha256 or "", r"^sha256:[0-9a-f]{64}$")

            first = controller.next(None)
            self.assertIsInstance(first, ToolRequest)
            config.write_text(config.read_text().replace("medium", "high"), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "controller_config_changed"):
                controller.next(ToolResult("r1", True, {"text": "hello"}))

    def test_rejects_reasoning_effort_that_does_not_match_runtime_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            executable = self.make_executable(root)
            hermes_home = root / "runtime-home"
            hermes_home.mkdir()
            (hermes_home / "config.yaml").write_text(
                "agent:\n  reasoning_effort: high\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "reasoning_effort_config_mismatch"):
                HermesCliController(
                    model="test-model",
                    provider="test-provider",
                    executable=executable,
                    hermes_home=hermes_home,
                    reasoning_effort="medium",
                )

    def test_rejects_executable_changed_after_construction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            executable = self.make_executable(Path(td))
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
            )
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(RuntimeError, "controller_executable_changed"):
                controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})

    def test_rejects_non_json_model_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            executable = Path(td) / "bad-hermes"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json,pathlib,sys\n"
                "a=sys.argv[1:]; pathlib.Path(a[a.index('--usage-file')+1]).write_text(json.dumps({'model':'test-model','provider':'test-provider','api_calls':1,'completed':True,'failed':False,'session_id':'s'}))\n"
                "print('not-json')\n"
            )
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
            )
            with self.assertRaisesRegex(ValueError, "model_protocol_json_invalid"):
                controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})

    def test_rejects_non_object_usage_receipt_as_infrastructure_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            executable = Path(td) / "bad-usage-hermes"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib,sys\n"
                "a=sys.argv[1:]; pathlib.Path(a[a.index('--usage-file')+1]).write_text('[]')\n"
                "print('{\"kind\":\"final\",\"text\":\"done\"}')\n"
            )
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
            )
            with self.assertRaisesRegex(RuntimeError, "hermes_usage_receipt_invalid"):
                controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})

    def test_deeply_nested_model_json_is_protocol_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            executable = Path(td) / "deep-json-hermes"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json,pathlib,sys\n"
                "a=sys.argv[1:]; pathlib.Path(a[a.index('--usage-file')+1]).write_text(json.dumps({'model':'test-model','provider':'test-provider','api_calls':1,'completed':True,'failed':False,'session_id':'s'}))\n"
                "print('[' * 1200 + '0' + ']' * 1200)\n"
            )
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
            )
            with self.assertRaisesRegex(ValueError, "model_protocol_json_invalid"):
                controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})

    def test_classifies_provider_failures_without_exposing_stderr(self) -> None:
        cases = (
            ("HTTP 401: invalid API key SECRET-VALUE", "provider_authentication_invalid"),
            ("model_not_available_for_integrator", "provider_route_unavailable"),
            ("reasoning_effort is unsupported", "provider_reasoning_effort_unsupported"),
            ("HTTP 429 rate limit exceeded", "provider_rate_limited"),
            ("unexpected upstream failure SECRET-VALUE", "controller_infrastructure_invalid"),
        )
        for stderr, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as td:
                executable = Path(td) / "failed-hermes"
                executable.write_text(
                    "#!/usr/bin/env python3\n"
                    "import json,pathlib,sys\n"
                    "a=sys.argv[1:]\n"
                    "p=pathlib.Path(a[a.index('--usage-file')+1])\n"
                    "p.write_text(json.dumps({'api_calls':0,'completed':False,'failed':True}))\n"
                    f"sys.stderr.write({stderr!r})\n"
                    "raise SystemExit(1)\n"
                )
                executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
                controller = HermesCliController(
                    model="test-model",
                    provider="test-provider",
                    executable=executable,
                    timeout_seconds=10,
                )
                with self.assertRaises(ControllerInfrastructureError) as captured:
                    controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})
                self.assertEqual(expected, captured.exception.reason_code)
                self.assertNotIn("SECRET-VALUE", str(captured.exception))

    def test_failed_provider_turn_accounts_for_usage_before_classification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            executable = root / "charged-failure-hermes"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json,pathlib,sys\n"
                "a=sys.argv[1:]\n"
                "p=pathlib.Path(a[a.index('--usage-file')+1])\n"
                "p.write_text(json.dumps({'model':'test-model','provider':'test-provider','api_calls':1,'input_tokens':7,'output_tokens':0,'estimated_cost_usd':0.4,'completed':False,'failed':True,'session_id':'failed-1'}))\n"
                "sys.stderr.write('HTTP 401 unauthorized')\n"
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            controller = HermesCliController(
                model="test-model",
                provider="test-provider",
                executable=executable,
                timeout_seconds=10,
            )
            with self.assertRaises(ControllerInfrastructureError) as captured:
                controller.begin({"schema": "oab.controller-context/v1", "episode_id": "opaque"})
            self.assertEqual("provider_authentication_invalid", captured.exception.reason_code)
            usage = controller.usage_snapshot()
            self.assertEqual(1, usage["api_calls"])
            self.assertEqual(7, usage["input_tokens"])
            self.assertEqual(0.4, usage["cost_usd"])


if __name__ == "__main__":
    unittest.main()

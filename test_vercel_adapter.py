import importlib.util
import json
from pathlib import Path
import unittest
from contextlib import contextmanager
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "acp_vercel_adapter", Path(__file__).parent / "api" / "index.py")
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)

import gateway


class VercelAdapterTests(unittest.TestCase):
    def test_runtime_bundle_excludes_local_records_and_build_inputs(self):
        config = json.loads((Path(__file__).parent / "vercel.json").read_text(encoding="utf-8"))
        excluded = config["functions"]["api/index.py"]["excludeFiles"]
        self.assertIn("records/**", excluded)
        self.assertIn("state_import.py", excluded)
        self.assertIn("**/.env*", excluded)
        self.assertIn(".agents/**", excluded)
        self.assertIn("scripts/**", excluded)
        self.assertIn("site/**", excluded)

    def test_adapter_selects_shared_database_even_in_vercel_dev(self):
        self.assertTrue(gateway.postgres_store.enabled())

    def test_restores_route_and_preserves_repeated_caller_query(self):
        self.assertEqual(
            adapter.restore_request_path(
                "/api?__acp_path=%2Finternal%2Fsecurity%2Fevents&severity=HIGH&severity=CRITICAL"),
            "/internal/security/events?severity=HIGH&severity=CRITICAL")

    def test_restores_query_embedded_in_vercel_route_capture(self):
        self.assertEqual(
            adapter.restore_request_path(
                "/api?__acp_path=%2Fnotice%3Fowner%3Dzachshallbetter%26name%3DAzimuth"),
            "/notice?owner=zachshallbetter&name=Azimuth")

    def test_accepts_vercel_original_path_when_internal_route_parameter_is_stripped(self):
        self.assertEqual(
            adapter.restore_request_path(
                "/notice?owner=zachshallbetter&name=Azimuth&path=notice"),
            "/notice?owner=zachshallbetter&name=Azimuth&path=notice")

    def test_rejects_missing_or_duplicate_route_parameters(self):
        for path in ("/api", "/api?__acp_path=/health&__acp_path=/ready"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                adapter.restore_request_path(path)

    def test_rejects_unsafe_route_values_and_large_urls(self):
        for path in ("/api?__acp_path=relative", "/api",
                     "/api?__acp_path=%2Fbad%5Cpath", "/api?__acp_path=%2Fbad%0Apath",
                     "/api?__acp_path=%2F%23fragment",
                     "/api?__acp_path=%2Fhealth%3F__acp_path%3D%2Fadmin"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                adapter.restore_request_path(path)
        with self.assertRaises(ValueError):
            adapter.restore_request_path("/api?" + "x" * adapter.MAX_URL_BYTES)

    def test_storage_failure_returns_structured_503_response(self):
        @contextmanager
        def unavailable():
            raise gateway.postgres_store.StorageError("synthetic test failure")
            yield None

        handler = object.__new__(gateway.Handler)
        response = {}
        handler._send_reply = lambda code, body, headers=None: response.update(
            code=code, body=body, headers=headers)
        with patch.object(gateway.postgres_store, "transaction", unavailable):
            handler._with_database_transaction(lambda: None)

        self.assertEqual(response["code"], 503)
        self.assertEqual(response["body"]["error"], "STATE_STORE_UNAVAILABLE")
        self.assertIsNone(response["headers"])

    def test_invalid_route_logging_cannot_prevent_the_json_refusal(self):
        for path in ("/api?" + "&".join("secret=value" for _ in range(257)),
                     "http://[invalid/?secret=value"):
            handler = object.__new__(adapter.handler)
            handler.path = path
            response = {}
            handler.reply = lambda code, body: response.update(code=code, body=body)
            with self.subTest(path=path), patch.object(adapter.logging, "warning") as warning:
                self.assertFalse(handler._restore_path())
                self.assertEqual(response["code"], 400)
                self.assertEqual(response["body"]["error"], "INVALID_REWRITE")
                self.assertNotIn("secret", str(warning.call_args))


    def test_a_host_that_fails_its_configuration_check_refuses_everything_but_health(self):
        responses = []
        with patch.dict(adapter._BOOT, {"checked": False, "problem": None}), \
                patch.object(adapter, "boot_check", side_effect=SystemExit("ACP_GATEWAY_TOKEN is required")):
            for path, allowed in (("/api?__acp_path=%2Fhealth", True), ("/api?__acp_path=%2Fready", False)):
                handler = object.__new__(adapter.handler)
                handler.path = path
                handler.discard_body = lambda: None
                handler.reply = lambda code, body: responses.append((code, body))
                self.assertEqual(handler._restore_path(), allowed)
        self.assertEqual(responses, [(503, responses[0][1])])
        self.assertEqual(responses[0][1]["error"], "MISCONFIGURED")

    def test_an_unexpected_failure_rolls_back_and_a_serialization_conflict_is_retried(self):
        attempts = {"opened": 0, "committed": 0}

        @contextmanager
        def transaction():
            attempts["opened"] += 1
            yield None
            attempts["committed"] += 1

        handler = object.__new__(gateway.Handler)
        response = {}
        handler._send_reply = lambda code, body, headers=None: response.update(code=code, body=body)

        def failing():
            handler.upstream_failure(RuntimeError("boom"), "Retry.")
        with patch.object(gateway.postgres_store, "transaction", transaction):
            handler._with_database_transaction(failing)
        self.assertEqual((attempts["opened"], attempts["committed"]), (1, 0), "nothing a failed request wrote is kept")
        self.assertEqual(response["code"], 502)

        conflict = type("SerializationFailure", (Exception,), {"sqlstate": "40001"})
        calls = {"n": 0}

        def conflicted_once():
            calls["n"] += 1
            if calls["n"] == 1:
                handler.upstream_failure(conflict("could not serialize"), "Retry.")
            else:
                handler.reply(200, {"ok": True})
        attempts.update(opened=0, committed=0)
        with patch.object(gateway.postgres_store, "transaction", transaction), patch.object(gateway.time, "sleep"):
            handler._with_database_transaction(conflicted_once)
        self.assertEqual((attempts["opened"], attempts["committed"], response["code"]), (2, 1, 200))

if __name__ == "__main__":
    unittest.main()

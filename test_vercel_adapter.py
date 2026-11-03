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


if __name__ == "__main__":
    unittest.main()

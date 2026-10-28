"""
Unit & Integration Tests for v32.0.0 Cloud, Concurrency & Security Engineering Upgrades
========================================================================================
Validates:
1. PathSecurityValidator: path canonicalization, existence check, sensitive file blocklist.
2. BackgroundJobManager: async multi-threaded worker pool, job state lifecycle (QUEUED -> RUNNING -> COMPLETED / FAILED).
3. GUIWorkbenchHandler Threaded HTTP REST API:
   - GET /api/status (v32.0.0, 55 Rust modules, threaded concurrency, Firebase enabled)
   - GET /api/cloud/status (Firebase project and collection status)
   - GET /api/cloud/sync (Firestore & Storage synchronization with RBAC)
   - GET /api/pipeline?async=1 (202 Accepted async job creation)
   - GET /api/jobs?id=... (job status polling and result delivery)
   - SEC-01 Path Traversal / Sensitive File Block (400 Bad Request on /etc/shadow)
   - SEC-03 Cross-Origin Request Block (403 Forbidden on external origin)
"""

import json
import os
import socketserver
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import unittest

from reverse_forge.gui_server import (
    GUIWorkbenchHandler,
    PathSecurityValidator,
    BackgroundJobManager,
    job_manager,
)
from reverse_forge.firebase_sync import firebase_sync, UserRole, AuthUserContext


class TestPathSecurityValidator(unittest.TestCase):
    def test_valid_file_passes(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"\x7fELF" + b"\x00" * 32)
            temp_path = tf.name

        try:
            ok, real_path = PathSecurityValidator.validate_safe_path(temp_path)
            self.assertTrue(ok)
            self.assertEqual(real_path, os.path.realpath(temp_path))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_nonexistent_file_rejected(self):
        ok, msg = PathSecurityValidator.validate_safe_path("/nonexistent/bogus/path_12345.bin")
        self.assertFalse(ok)
        self.assertIn("File does not exist", msg)

    def test_empty_path_rejected(self):
        ok, msg = PathSecurityValidator.validate_safe_path("")
        self.assertFalse(ok)
        self.assertIn("Empty or invalid", msg)

    def test_sensitive_files_blocked(self):
        sensitive_samples = [
            "/etc/shadow",
            "/home/user/.ssh/id_rsa",
            "/project/.env",
            "/home/user/.git-credentials",
            "/etc/sudoers",
        ]
        for s in sensitive_samples:
            ok, msg = PathSecurityValidator.validate_safe_path(s)
            self.assertFalse(ok)
            self.assertTrue("Access to sensitive file" in msg or "File does not exist" in msg)


class TestBackgroundJobManager(unittest.TestCase):
    def test_job_lifecycle_completion(self):
        mgr = BackgroundJobManager(max_workers=2)

        def sample_work(x: int, y: int) -> int:
            time.sleep(0.05)
            return x * y

        job_id = mgr.submit_job("multiply_task", sample_work, 6, 7)
        self.assertTrue(job_id.startswith("job_"))

        # Poll for completion
        for _ in range(30):
            job = mgr.get_job(job_id)
            self.assertIsNotNone(job)
            if job["status"] == "COMPLETED":
                break
            time.sleep(0.02)

        final_job = mgr.get_job(job_id)
        self.assertEqual(final_job["status"], "COMPLETED")
        self.assertEqual(final_job["progress_pct"], 100)
        self.assertEqual(final_job["result"], 42)
        self.assertIsNone(final_job["error"])
        self.assertIsNotNone(final_job["finished_at"])

    def test_job_failure_captured(self):
        mgr = BackgroundJobManager(max_workers=2)

        def failing_task():
            raise ValueError("Intentional simulated failure in worker")

        job_id = mgr.submit_job("failing_task", failing_task)

        for _ in range(30):
            job = mgr.get_job(job_id)
            if job["status"] == "FAILED":
                break
            time.sleep(0.02)

        final_job = mgr.get_job(job_id)
        self.assertEqual(final_job["status"], "FAILED")
        self.assertIn("Intentional simulated failure", final_job["error"])
        self.assertIsNone(final_job["result"])


class TestHardenedThreadedGUIWorkbenchServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class ThreadedTestServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

        cls.port = 19200
        cls.server = None
        for p in range(19200, 19280):
            try:
                cls.server = ThreadedTestServer(("127.0.0.1", p), GUIWorkbenchHandler)
                cls.port = p
                break
            except OSError:
                continue

        assert cls.server is not None, "Failed to bind threaded test workbench server"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.25)

        # Create temporary valid test binary
        cls.test_file = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        cls.test_file.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x90" * 256)
        cls.test_file.close()

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()
        if os.path.exists(cls.test_file.name):
            os.remove(cls.test_file.name)

    def test_api_status_metadata(self):
        url = f"http://127.0.0.1:{self.port}/api/status"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ready")
            self.assertEqual(data["version"], "32.0.0-rust-bicentennial")
            self.assertEqual(data["rust_modules"], 55)
            self.assertTrue(data["firebase_sync_enabled"])
            self.assertEqual(data["concurrency"], "threaded_worker_pool")

    def test_api_cloud_status(self):
        url = f"http://127.0.0.1:{self.port}/api/cloud/status"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            c_st = data["cloud_status"]
            self.assertIn("project_id", c_st)
            self.assertIn("firestore", c_st)
            self.assertIn("storage", c_st)
            self.assertIn("authenticated_user", c_st)

    def test_api_cloud_sync_execution(self):
        from reverse_forge.gui_server import firebase_sync
        from reverse_forge.firebase_sync import jwt
        jwt_secret = "v32_cloud_jwt_secret_32_bytes_minimum_len!!"
        firebase_sync.auth.verification_key = jwt_secret
        firebase_sync.auth.allowed_algorithms = ["HS256"]
        token = jwt.encode(
            {
                "sub": "analyst_v32",
                "email": "analyst@v32.local",
                "role": "ANALYST",
                "tenant_id": "default_tenant",
                "iss": firebase_sync.auth.expected_issuer,
                "aud": firebase_sync.auth.expected_audience,
                "exp": time.time() + 3600,
            },
            jwt_secret,
            algorithm="HS256",
        )
        encoded = urllib.parse.quote(self.test_file.name)
        url = f"http://127.0.0.1:{self.port}/api/cloud/sync?path={encoded}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            sync_info = data["cloud_sync"]
            self.assertIn("firestore_path", sync_info)
            self.assertIn("storage_binary_uri", sync_info)
            self.assertIn("findings_count", sync_info)

    def test_api_pipeline_async_and_jobs_polling(self):
        encoded = urllib.parse.quote(self.test_file.name)
        url = f"http://127.0.0.1:{self.port}/api/pipeline?async=1&path={encoded}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 202)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "accepted")
            job_id = data["job_id"]
            self.assertTrue(job_id.startswith("job_"))

        # Poll /api/jobs?id=...
        poll_url = f"http://127.0.0.1:{self.port}/api/jobs?id={job_id}"
        for _ in range(250):
            with urllib.request.urlopen(poll_url) as p_resp:
                self.assertEqual(p_resp.status, 200)
                p_data = json.loads(p_resp.read().decode("utf-8"))
                self.assertEqual(p_data["status"], "ok")
                job = p_data["job"]
                if job["status"] in ("COMPLETED", "FAILED"):
                    break
            time.sleep(0.1)

        self.assertIn(job["status"], ("COMPLETED", "FAILED"))

    def test_security_path_traversal_blocked(self):
        url = f"http://127.0.0.1:{self.port}/api/hex?path=/etc/shadow"
        try:
            with urllib.request.urlopen(url) as resp:
                self.fail("Expected HTTPError 400 for sensitive file access")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            err_data = json.loads(e.read().decode("utf-8"))
            self.assertEqual(err_data["status"], "error")

    def test_security_cors_external_origin_blocked(self):
        url = f"http://127.0.0.1:{self.port}/api/status"
        req = urllib.request.Request(url, headers={"Origin": "https://malicious-external-site.com"})
        try:
            with urllib.request.urlopen(req) as resp:
                self.fail("Expected HTTPError 403 for untrusted external Origin")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)
            err_data = json.loads(e.read().decode("utf-8"))
            self.assertEqual(err_data["status"], "error")


if __name__ == "__main__":
    unittest.main()

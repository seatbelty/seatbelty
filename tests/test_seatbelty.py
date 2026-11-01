#!/usr/bin/env python3
"""
Seatbelty Test & CI Validation Suite
Validates that hooks, pattern matching, exit codes, and redactions pass all automated checks.
"""
import json
import subprocess
import sys
import unittest

class TestSeatbeltyHooks(unittest.TestCase):
    def run_hook(self, script_path, payload):
        res = subprocess.run(
            [sys.executable, script_path],
            input=json.dumps(payload),
            text=True,
            capture_output=True
        )
        self.assertEqual(res.returncode, 0, f"Hook failed with error: {res.stderr}")
        return json.loads(res.stdout.strip())

    def test_pre_guard_allows_safe_command(self):
        payload = {"toolName": "run_command", "args": {"CommandLine": "npm test"}}
        res = self.run_hook("scripts/pre_tool_guard.py", payload)
        self.assertEqual(res.get("decision"), "allow")

    def test_pre_guard_blocks_destructive_git(self):
        payload = {"toolName": "run_command", "args": {"CommandLine": "git push --force origin main"}}
        res = self.run_hook("scripts/pre_tool_guard.py", payload)
        self.assertEqual(res.get("decision"), "deny")
        self.assertIn("SEATBELTY BLOCKED", res.get("reason", ""))

    def test_pre_guard_blocks_rm_root(self):
        payload = {"toolName": "run_command", "args": {"CommandLine": "rm -rf /"}}
        res = self.run_hook("scripts/pre_tool_guard.py", payload)
        self.assertEqual(res.get("decision"), "deny")

    def test_pre_guard_blocks_env_file_view(self):
        payload = {"toolName": "view_file", "args": {"AbsolutePath": ".env"}}
        res = self.run_hook("scripts/pre_tool_guard.py", payload)
        self.assertEqual(res.get("decision"), "deny")

    def test_post_mask_redacts_tokens_and_pii(self):
        dummy_aws = "AKIA" + "1234567890ABCDEF"
        dummy_stripe = "sk_" + "test_" + "123456789012345678901234"
        raw_output = f"User test@domain.com loaded AWS key {dummy_aws} and Stripe {dummy_stripe}."
        payload = {"output": raw_output}
        res = self.run_hook("scripts/post_tool_mask.py", payload)
        clean = res.get("output", "")
        self.assertNotIn("test@domain.com", clean)
        self.assertNotIn(dummy_aws, clean)
        self.assertNotIn(dummy_stripe, clean)
        self.assertIn("[REDACTED_EMAIL]", clean)
        self.assertIn("[REDACTED_AWS_KEY]", clean)
        self.assertIn("[REDACTED_STRIPE_KEY]", clean)

if __name__ == "__main__":
    unittest.main()

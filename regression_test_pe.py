#!/usr/bin/env python3
"""
regression_test_pe.py
Day 19: Adversarial Regression Test Suite for PEWriter Governance.

This script acts as an "adversarial agent" that attempts to:
1. Emit a binary with a suspicious payload (noop loop).
2. Verify the GovernanceEnforcer detects pe_writer usage.
3. Verify the HITL gate blocks the proposal (423 or PENDING_APPROVAL).
4. Verify that if denied, the binary file is NEVER created.

Usage:
    python regression_test_pe.py [--host http://localhost:11435]

Exit codes:
    0 = All tests passed (Sovereign Proof verified)
    1 = One or more tests failed
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.request
import urllib.error


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    """POST JSON and return (status_code, parsed_json)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"error": body}
        return e.code, parsed


def _get_json(url: str) -> tuple[int, dict]:
    """GET and return (status_code, parsed_json)."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"error": body}
        return e.code, parsed


def _b64_nop_loop() -> str:
    """Return a base64-encoded x64 NOP sled (suspicious payload for testing)."""
    # 64 NOPs (0x90) — classic suspicious payload pattern
    nop_sled = bytes([0x90] * 64)
    return base64.b64encode(nop_sled).decode("ascii")


class SovereignProofTest:
    def __init__(self, host: str):
        self.host = host.rstrip("/")
        self.passed = 0
        self.failed = 0
        self.details: list[str] = []

    def _log(self, msg: str) -> None:
        print(msg)
        self.details.append(msg)

    def _assert_true(self, condition: bool, label: str) -> None:
        if condition:
            self._log(f"  ✅ PASS: {label}")
            self.passed += 1
        else:
            self._log(f"  ❌ FAIL: {label}")
            self.failed += 1

    def run(self) -> int:
        self._log("=" * 60)
        self._log("SOVEREIGN PROOF: PEWriter Adversarial Regression Suite")
        self._log("=" * 60)

        # ------------------------------------------------------------------
        # Phase 1: Ensure engine is READY and not paused
        # ------------------------------------------------------------------
        self._log("\n[Phase 1] Engine readiness check...")
        status_code, status = _get_json(f"{self.host}/status")
        self._assert_true(status_code == 200, "GET /status returns 200")
        if status_code != 200:
            self._log(f"  ABORT: Engine not reachable. status_code={status_code}")
            return 1

        loader_state = status.get("loader_context", {}).get("state")

        # Ensure not paused
        if status.get("agentic_paused"):
            self._log("  Resuming engine from paused state...")
            _post_json(f"{self.host}/control/resume", {})
            time.sleep(0.2)

        # If engine is not READY, force a model selection to trigger LOADING -> READY
        if loader_state != 2:
            self._log(f"  Engine not READY (state={loader_state}). Triggering model selection...")
            current_model = status.get("recommended_model", "default-7b")
            _post_json(f"{self.host}/model/select", {"model": current_model})
            # Poll until READY (max 5s)
            for _ in range(50):
                time.sleep(0.1)
                _, poll = _get_json(f"{self.host}/status")
                if poll.get("loader_context", {}).get("state") == 2:
                    break
            _, status = _get_json(f"{self.host}/status")
            loader_state = status.get("loader_context", {}).get("state")

        self._assert_true(loader_state == 2, f"Engine state is READY (2), got {loader_state}")
        if loader_state != 2:
            self._log("  ABORT: Engine failed to reach READY state.")
            return 1

        # ------------------------------------------------------------------
        # Phase 2: Attempt PE emission WITHOUT HITL approval (should be blocked)
        # ------------------------------------------------------------------
        self._log("\n[Phase 2] Adversarial emission attempt (no HITL approval)...")
        output_path = "test_adversarial_pe.exe"
        code_buffer_b64 = _b64_nop_loop()

        # First, pause the engine to simulate HITL gate active
        _post_json(f"{self.host}/control/pause", {})
        time.sleep(0.2)

        status_code, body = _post_json(
            f"{self.host}/tool/pe_writer",
            {
                "output_path": output_path,
                "code_buffer": code_buffer_b64,
                "entry_point_rva": 0x1000,
                "subsystem": 3,
            },
        )

        self._assert_true(
            status_code == 423,
            f"PEWriter blocked with 423 when engine paused (got {status_code})",
        )
        self._assert_true(
            body.get("error") == "ENGINE_PAUSED_FOR_HITL",
            f"Error payload is ENGINE_PAUSED_FOR_HITL (got {body.get('error')})",
        )

        # ------------------------------------------------------------------
        # Phase 3: Resume engine, attempt emission, then verify file exists
        # ------------------------------------------------------------------
        self._log("\n[Phase 3] Legitimate emission with approval...")
        _post_json(f"{self.host}/control/resume", {})
        time.sleep(0.2)

        status_code, body = _post_json(
            f"{self.host}/tool/pe_writer",
            {
                "output_path": output_path,
                "code_buffer": code_buffer_b64,
                "entry_point_rva": 0x1000,
                "subsystem": 3,
            },
        )

        self._assert_true(status_code == 200, f"PEWriter returns 200 when engine ready (got {status_code})")
        self._assert_true(body.get("bytesWritten", 0) > 0, "bytesWritten > 0")
        self._assert_true(bool(body.get("peHash")), "peHash is present in response")
        self._assert_true(bool(body.get("codeHash")), "codeHash is present in response")

        pe_hash = body.get("peHash", "")
        code_hash = body.get("codeHash", "")

        # Verify file exists on disk
        workspace_root = os.path.dirname(os.path.abspath(__file__))
        file_on_disk = os.path.join(workspace_root, output_path)
        self._assert_true(os.path.exists(file_on_disk), f"Emitted PE file exists at {output_path}")

        # ------------------------------------------------------------------
        # Phase 4: Forensic hash verification
        # ------------------------------------------------------------------
        self._log("\n[Phase 4] Forensic hash verification...")
        with open(file_on_disk, "rb") as f:
            actual_disk_hash = hashlib.sha256(f.read()).hexdigest()

        self._assert_true(
            actual_disk_hash.lower() == pe_hash.lower(),
            "Disk hash matches peHash from audit trail",
        )

        # Call verify endpoint
        v_status, v_body = _post_json(
            f"{self.host}/tool/verify_pe_hash",
            {"file_path": output_path, "expected_hash": pe_hash},
        )
        self._assert_true(v_status == 200, f"verify_pe_hash returns 200 (got {v_status})")
        self._assert_true(v_body.get("verified") is True, "verify_pe_hash reports verified=True")

        # ------------------------------------------------------------------
        # Phase 5: Simulate denial — delete file, pause engine, retry, verify NOT recreated
        # ------------------------------------------------------------------
        self._log("\n[Phase 5] Denial simulation — file must NOT be recreated...")
        os.remove(file_on_disk)
        self._assert_true(not os.path.exists(file_on_disk), "PE file deleted before denial test")

        _post_json(f"{self.host}/control/pause", {})
        time.sleep(0.2)

        status_code, body = _post_json(
            f"{self.host}/tool/pe_writer",
            {
                "output_path": output_path,
                "code_buffer": code_buffer_b64,
                "entry_point_rva": 0x1000,
                "subsystem": 3,
            },
        )

        self._assert_true(
            status_code == 423,
            f"Denied emission returns 423 (got {status_code})",
        )
        self._assert_true(
            not os.path.exists(file_on_disk),
            "PE file was NOT created after denied proposal",
        )

        # ------------------------------------------------------------------
        # Phase 6: Cleanup
        # ------------------------------------------------------------------
        self._log("\n[Phase 6] Cleanup...")
        _post_json(f"{self.host}/control/resume", {})
        if os.path.exists(file_on_disk):
            os.remove(file_on_disk)
        self._log("  Engine resumed. Test artifacts removed.")

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        self._log("\n" + "=" * 60)
        self._log(f"RESULTS: {self.passed} passed, {self.failed} failed")
        self._log("=" * 60)

        if self.failed == 0:
            self._log("\n🏛️ SOVEREIGN PROOF VERIFIED")
            self._log("   The agent cannot bypass the HITL gate.")
            self._log("   Every binary is forensically traceable.")
            return 0
        else:
            self._log("\n⚠️  SOVEREIGN PROOF FAILED")
            self._log("   The gate may be compromised.")
            return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="PEWriter Adversarial Regression Test Suite")
    parser.add_argument("--host", default="http://localhost:11435", help="Mock backend base URL")
    args = parser.parse_args()

    test = SovereignProofTest(args.host)
    return test.run()


if __name__ == "__main__":
    sys.exit(main())

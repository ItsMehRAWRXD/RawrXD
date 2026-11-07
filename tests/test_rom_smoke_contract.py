#!/usr/bin/env python3
"""Regression checks for the ROM smoke-test's fail-closed preconditions.

These are SOURCE CONTRACT checks only, not a substitute for running the native
production_smoke_test.exe with a generated ROM and shard fixture.
"""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "src/tools/production_smoke_test.cpp")

class RomSmokeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SOURCE.read_text(encoding="utf-8")

    def test_empty_tensor_manifest_fails(self):
        self.assertIn("if (tensor_count == 0)", self.code)
        self.assertIn("page lease test was not executed", self.code)

    def test_invalid_shard_counts_fail(self):
        self.assertIn("std::wcstoul(argv[3], &end, 10)", self.code)
        self.assertIn("parsed == 0 || parsed > UINT32_MAX", self.code)
        self.assertIn("*end != L'\\0'", self.code)

    def test_out_of_bounds_tensor_fails_before_registration(self):
        self.assertIn("desc.tensor_bytes == 0", self.code)
        self.assertIn("desc.absolute_offset > info.file_size", self.code)
        self.assertIn("desc.tensor_bytes > info.file_size - desc.absolute_offset", self.code)
        self.assertLess(self.code.index("exceeds its registered shard bounds"),
                        self.code.index("prefetch.register_tensor_info(i, info)"))

    def test_missing_or_empty_shards_fail_before_registration(self):
        self.assertIn("if (file_size == 0)", self.code)
        self.assertIn("shard is missing, unreadable, or empty", self.code)
        self.assertLess(self.code.index("if (file_size == 0)"),
                        self.code.index("flicker.register_shard(i, current_shard, file_size)"))

    def test_gate_messages_do_not_claim_unobserved_worker_or_leak_results(self):
        self.assertNotIn("Background Prefetch Worker Engine Thread spawned -> PASS", self.code)
        self.assertNotIn("0 Memory Leaks", self.code)

    def test_no_unearned_engine_certification(self):
        self.assertNotIn("ENGINE FINALIZED, VERIFIED, AND CERTIFIED PRODUCTION-READY", self.code)
        self.assertIn("NOT A FULL ENGINE CERTIFICATION", self.code)

if __name__ == "__main__":
    unittest.main(verbosity=2)

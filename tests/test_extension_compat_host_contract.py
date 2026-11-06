"""Static contract checks for the Win32 extension compatibility host.

Run: python -m unittest discover -s tests -p test_extension_compat_host_contract.py
Static checks only; native integration remains mandatory.
"""
from pathlib import Path
import re
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "~dev/rawrxd/src/core/extension_host_production.cpp"

class ExtensionCompatHostContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")

    def method(self, signature):
        match = re.search(re.escape(signature) + r"\s*\{", self.source, re.S)
        self.assertIsNotNone(match, signature)
        # Walk nested C++ blocks; a non-greedy regex truncates at the first if-body.
        start = match.end()
        depth = 1
        for index in range(start, len(self.source)):
            if self.source[index] == "{":
                depth += 1
            elif self.source[index] == "}":
                depth -= 1
                if depth == 0:
                    return self.source[start:index]
        self.fail(f"Unclosed method body: {signature}")

    def test_unknown_commands_never_succeed(self):
        body = self.method("bool ExecuteCommand(const std::string& command, const std::string& args)")
        self.assertNotIn("return true;", body)
        self.assertIn("return false;", body)

    def test_initialized_state_read_is_synchronized(self):
        body = self.method("bool IsInitialized() const")
        self.assertIn("std::lock_guard<std::mutex> lock(mutex_);", body)

if __name__ == "__main__":
    unittest.main()

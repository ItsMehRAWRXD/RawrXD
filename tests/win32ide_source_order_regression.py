#!/usr/bin/env python3
"""Dependency-free regression for the native Win32 IDE translation-unit prologue."""
from pathlib import Path
import re
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src" / "win32app" / "Win32IDE.cpp"


class Win32IdeSourceOrderRegression(unittest.TestCase):
    def test_native_destructor_is_declared_after_its_dependencies(self):
        source = SOURCE.read_text(encoding="utf-8-sig")
        self.assertEqual(len(re.findall(r"\bWin32IDE::~Win32IDE\s*\(", source)), 1)
        include = source.find('#include "Win32IDE.h"')
        engine = source.find('#include "../cpu_inference_engine.h"')
        destructor = source.find("Win32IDE::~Win32IDE(")
        self.assertGreaterEqual(include, 0)
        self.assertGreater(engine, include)
        self.assertGreater(destructor, engine)
        self.assertTrue(source[:include].strip().startswith("//") or not source[:include].strip())


if __name__ == "__main__":
    unittest.main()

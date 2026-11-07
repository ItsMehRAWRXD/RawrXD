#!/usr/bin/env python3
"""Fail-closed RawrXD extension integration audit (stdlib only).

This is a SOURCE CONTRACT check, not a runtime/GUI/VSIX certification.
Exit 0 means only that the explicitly checked source contracts hold.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE = ROOT / "~dev/rawrxd/src/core"
HEADLESS = CORE / "js_extension_host_headless_impl.cpp"
BRIDGE = CORE / "js_extension_host_production.cpp"
FULL = CORE / "js_extension_host.cpp"

def method_body(source, signature):
    match = re.search(signature + r"\s*\{", source)
    if not match:
        raise AssertionError("Missing method: " + signature)
    start = match.end()
    depth = 1
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i]
    raise AssertionError("Unclosed method: " + signature)

def run():
    failures = []
    checks = []
    def check(name, fn):
        try:
            fn()
            checks.append({"name": name, "status": "PASS_SOURCE"})
        except Exception as exc:
            checks.append({"name": name, "status": "FAIL", "detail": str(exc)})
            failures.append(name)

    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    def read(path):
        return path.read_text(encoding="utf-8")

    check("full_host_source_present", lambda: require(FULL.is_file(), "QuickJS host source missing"))
    check("headless_source_present", lambda: require(HEADLESS.is_file(), "headless host source missing"))
    check("bridge_source_present", lambda: require(BRIDGE.is_file(), "bridge source missing"))
    if HEADLESS.is_file():
        source = read(HEADLESS)
        for name in ("initialize", "shutdown", "activateExtension", "deactivateExtension",
                     "loadVSIX", "loadExtensionFromDir", "unloadExtension",
                     "fireEvent", "registerModuleResolver", "executeScript"):
            def assert_fail_closed(n=name):
                body = method_body(source, r"PatchResult\s+JSExtensionHost::" + n + r"\([^)]*\)(?:\s+const)?")
                require("PatchResult::error(" in body, n + " must return an explicit error")
                require("PatchResult::ok(" not in body, n + " must not claim success")
            check("headless_" + name + "_fail_closed", assert_fail_closed)
        check("headless_timer_failure_sentinel", lambda: require(
            re.search(r"uint64_t\s+JSExtensionHost::createTimer\([^)]*\)\s*\{[^}]*return\s+0\s*;", source, re.S) is not None,
            "unsupported timer must return zero"))
        check("headless_vsix_invalid", lambda: require(
            re.search(r"r\.isValid\s*=\s*false\s*;", source) is not None,
            "unsupported VSIX verifier must not claim validity"))
    if BRIDGE.is_file():
        source = read(BRIDGE)
        for name in ("Initialize", "ExecuteScript", "LoadExtension"):
            check("bridge_" + name + "_fail_closed", lambda n=name: require(
                "return false;" in method_body(source, r"bool\s+" + n + r"\([^)]*\)"),
                n + " must not claim successful execution"))
    output = {"schema": 1, "scope": "source-contract-only",
              "runtime_certified": False, "native_gui_certified": False,
              "extension_activation_certified": False,
              "checks": checks, "failed": len(failures), "passed": len(checks)-len(failures)}
    print(json.dumps(output, indent=2))
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(run())

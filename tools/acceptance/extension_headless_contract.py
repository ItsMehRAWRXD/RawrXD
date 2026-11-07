#!/usr/bin/env python3
"""RawrXD extension-headless contract checks.

No model, Ollama, or Windows runtime required. These are SOURCE CONTRACT gates,
not native runtime tests. A PASS must never be reported as extension execution.
Run: python3 tools/acceptance/extension_headless_contract.py
"""
from pathlib import Path
import argparse
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "~dev/rawrxd/src/core/js_extension_host.hpp"
STUB = ROOT / "~dev/rawrxd/src/core/js_extension_host_headless_impl.cpp"

METHODS = (
    "initialize", "shutdown", "activateExtension", "deactivateExtension",
    "loadVSIX", "loadExtensionFromDir", "unloadExtension", "fireEvent",
    "registerModuleResolver", "executeScript",
)

def check_sources(root=ROOT):
    header = root / "~dev/rawrxd/src/core/js_extension_host.hpp"
    stub = root / "~dev/rawrxd/src/core/js_extension_host_headless_impl.cpp"
    if not header.is_file() or not stub.is_file():
        return [{"gate": "sources_present", "status": "FAIL", "detail": "Missing extension header or headless implementation"}]
    h, s = header.read_text(encoding="utf-8"), stub.read_text(encoding="utf-8")
    results = []
    for name in METHODS:
        declared = bool(re.search(r"\b" + re.escape(name) + r"\s*\(", h))
        # Restrict to the actual method body to avoid comments and other methods.
        match = re.search(r"JSExtensionHost::" + re.escape(name) + r"\s*\([^)]*\)(?:\s*const)?\s*\{([^}]*)\}", s, re.S)
        explicit_error = bool(match and "PatchResult::error(" in match.group(1))
        ok = declared and explicit_error
        results.append({"gate": name + "_fails_closed", "status": "PASS" if ok else "FAIL",
                        "detail": "Source-contract only: explicit unsupported error" if ok else "Missing declaration or explicit failure"})
    # The headless host must not falsely claim successful initialization.
    init = re.search(r"JSExtensionHost::initialize\s*\([^)]*\)\s*\{([^}]*)\}", s, re.S)
    ok = bool(init and "m_initialized = false" in init.group(1))
    results.append({"gate": "initialize_clears_state", "status": "PASS" if ok else "FAIL", "detail": "Source-contract only"})
    # No fake timer handles: 0 means unsupported.
    timer = re.search(r"JSExtensionHost::createTimer\s*\([^)]*\)\s*\{([^}]*)\}", s, re.S)
    ok = bool(timer and re.search(r"return\s+0\s*;", timer.group(1)))
    results.append({"gate": "timer_failure_sentinel", "status": "PASS" if ok else "FAIL", "detail": "Source-contract only"})
    # No fake loaded extensions.
    loaded = re.search(r"JSExtensionHost::getLoadedExtensions\s*\([^)]*\)\s*const\s*\{([^}]*)\}", s, re.S)
    ok = bool(loaded and "*outCount = 0" in loaded.group(1))
    results.append({"gate": "loaded_count_zero", "status": "PASS" if ok else "FAIL", "detail": "Source-contract only"})
    # No fake VSIX verification success.
    verify = re.search(r"JSExtensionHost::verifyVSIX\s*\([^)]*\)\s*const\s*\{([^}]*)\}", s, re.S)
    ok = bool(verify and "r.isValid = false" in verify.group(1) and "r.signatureVerified = false" in verify.group(1))
    results.append({"gate": "vsix_verification_fails_closed", "status": "PASS" if ok else "FAIL", "detail": "Source-contract only"})
    # No fake JS execution result when unsupported.
    script = re.search(r"JSExtensionHost::executeScript\s*\([^)]*\)\s*\{([^}]*)\}", s, re.S)
    ok = bool(script and "outResult[0] = '\\0'" in script.group(1))
    results.append({"gate": "script_output_cleared", "status": "PASS" if ok else "FAIL", "detail": "Source-contract only"})
    # Verify all lifecycle/handle fields are initialized, not just the JS pointers.
    # Match through the destructor marker so m_stats{} does not truncate the
    # initializer list at its first brace.
    ctor = re.search(r"JSExtensionHost::JSExtensionHost\s*\(\s*\)\s*:(.*?)JSExtensionHost::~JSExtensionHost", s, re.S)
    required = ("m_jsRuntime", "m_jsContext", "m_queueEvent",
                "m_nextTimerId", "m_initialized", "m_shutdownCompleted",
                "m_hostThread", "m_running", "m_stats")
    initialized = bool(ctor and all(re.search(r"\b" + field + r"\s*(?:\(|\{)", ctor.group(1)) for field in required))
    results.append({"gate": "headless_constructor_state_initialized",
                    "status": "PASS" if initialized else "FAIL",
                    "detail": "Source-contract only: all lifecycle and handle members explicitly initialized"})
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = check_sources(args.root)
    report = {"scope": "source-contract-only", "native_runtime_executed": False,
              "model_inference_executed": False, "results": results,
              "passed": sum(r["status"] == "PASS" for r in results),
              "failed": sum(r["status"] == "FAIL" for r in results)}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for result in results:
            print(f'{result["status"]}: {result["gate"]} ({result["detail"]})')
        print(f'SOURCE CONTRACT ONLY: {report["passed"]} passed, {report["failed"]} failed')
    return 1 if report["failed"] else 0

if __name__ == "__main__":
    sys.exit(main())

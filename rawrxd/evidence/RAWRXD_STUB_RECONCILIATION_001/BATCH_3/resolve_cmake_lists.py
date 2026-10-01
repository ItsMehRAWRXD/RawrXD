"""BATCH_3 - resolve which CMake variable each source line belongs to.

Hand-reasoning about a 16.7k-line CMakeLists is not evidence. For every line
that names a shipping stub, walk backwards to the nearest set()/list(APPEND)
and report the variable, so only the WIN32IDE list is touched.
"""
import re
import sys
from pathlib import Path

CM = Path(r"F:\~dev\rawrxd\CMakeLists.txt")
lines = CM.read_text(encoding="utf-8", errors="replace").split("\n")

STUB_LEAVES = [
    "Deep2APIServer.cpp", "Deep2Benchmark.cpp", "Deep2Discovery.cpp",
    "Deep2InferenceGateway.cpp", "Deep2Integration.cpp", "Deep2LocalServer.cpp",
    "GGUFDiagnostics.cpp", "GPUDeviceRegistry.cpp", "MultiGPUScheduler.cpp",
    "VRAMAllocator.cpp", "ScaleQuality.cpp", "deep2_http_gateway.cpp",
    "Deep2GPUBackend.cpp", "mcp_bridge.cpp", "Deep2ProductionRuntime.cpp",
    "AgenticIOCPBridge.cpp", "AgenticPlanningOrchestrator.cpp", "FullAgenticIDE.cpp",
    "ANSIColorParser.cpp", "Deep2Bridge.cpp", "FindReplaceDialog.cpp",
    "GitCommitDialog.cpp", "GitDiffViewer.cpp", "ai_model_caller_real.cpp",
    "inference_engine_real.cpp",
]

SET_RE = re.compile(r"^\s*set\s*\(\s*([A-Za-z0-9_]+)")
APP_RE = re.compile(r"^\s*list\s*\(\s*APPEND\s+([A-Za-z0-9_]+)")
# A set(...) block that is closed by a line that is exactly ')' ends the region.
def owning_var(idx):
    var = None
    for j in range(idx, -1, -1):
        s = lines[j]
        m = APP_RE.match(s)
        if m:
            return ("append", m.group(1), j + 1)
        m = SET_RE.match(s)
        if m:
            return ("set", m.group(1), j + 1)
    return (None, None, None)


def main():
    rows = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("#"):
            continue
        for leaf in STUB_LEAVES:
            if leaf in s:
                kind, var, at = owning_var(i - 1)
                rows.append((i, leaf, kind, var, at, s))
                break
    by_var = {}
    for i, leaf, kind, var, at, s in rows:
        by_var.setdefault((kind, var), []).append((i, leaf))
    for (kind, var), items in sorted(by_var.items(), key=lambda kv: -len(kv[1])):
        print(f"{kind} {var}: {len(items)} stub lines "
              f"(decl at line {[a for _, _, a in [(0,0,0)]][0] if False else items[0][0]})")
        for i, leaf in items:
            print(f"    {i:>6}  {leaf}")
    print()
    print("TOTAL_ACTIVE_STUB_LINES=" + str(len(rows)))


if __name__ == "__main__":
    main()

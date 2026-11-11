"""Snapshot sources for the isolated DEEP2_RUNTIME_OWNERSHIP_001 build.

- Executor/runtime sources: the committed versions (the live tree is under
  concurrent edit, so HEAD is the stable baseline for the runtime).
- Adapter shim and ownership test: the pinned copies under tools/ (the live
  src/core/dll/Deep2InferenceAdapter.cpp is deliberately excluded from every
  build target and is under concurrent edit).
"""
import os
import shutil
import subprocess

REPO = r"F:\rawrxd"
SNAP = os.path.join(REPO, "tmp_build_owns")

COMMITTED = [
    "src/modelgenie/ModelGenieExecutor.cpp",
    "src/modelgenie/ModelGenieExecutor.hpp",
    "src/modelgenie/ModelGenieRuntime.cpp",
    "include/ModelGenieRuntime.h",
]

PINNED = [
    "tools/Deep2RuntimeClient.cpp",
    "tools/Deep2RuntimeClient.h",
    "tools/ownership_test_pinned.cpp",
]

LIVE = [
    "src/deep2/modelgenie/ModelGenome.cpp",
    "src/deep2/modelgenie/ModelGenomeReader.cpp",
    "src/tokenizer/gguf_embedded_tokenizer.cpp",
]


def main():
    os.makedirs(SNAP, exist_ok=True)
    for rel in COMMITTED:
        data = subprocess.check_output(["git", "-C", REPO, "show", "HEAD:" + rel])
        with open(os.path.join(SNAP, os.path.basename(rel)), "wb") as f:
            f.write(data)
    for rel in PINNED + LIVE:
        shutil.copy(os.path.join(REPO, rel), os.path.join(SNAP, os.path.basename(rel)))
    print("snapshot ready: %d files" % len(os.listdir(SNAP)))


if __name__ == "__main__":
    main()

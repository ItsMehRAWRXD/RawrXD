# D1 replay receipt — current HEAD

Date: 2026-10-19
Base HEAD: 1977e04140a199f23b0cbae9ac26bd2a819eed82
Branch: codex/d1-replay-1977e041
Worktree: F:\rawrxd\.worktrees\codex-d1-replay-338c7d (sparse checkout; isolated from the dirty primary checkout)
Build directory: F:\rawrxd\.build_d1_replay_1977e

## Scope

This replay uses the existing Executor::PrefillBatch op-major implementation, with the D1 fail-closed/runtime safeguards and receipt counters from the prior verifier work. The harness calls PrefillBatch directly for each tested prefix; ExecuteToken is used for the serial reference and one-token continuation only.

The replay covers only the TinyLlama model named below. It makes no claim about other model families. The tested output.weight is Q6_K (GGML type 14), dims [2048, 32000]; the Q4_K fused LM-head branch was not selected and remains unverified.

## Model and executable

Model: F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
Model size: 668,788,096 bytes
Model SHA-256: 9fecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0
Executable: F:\rawrxd\.build_d1_replay_1977e\bin\deep2_d1_prefill_parity.exe
Executable SHA-256: c724bf5838abac6f164c98c9d4f8bf7a7f63249b3180f40aacde7ce7b00c9c27
Selected GPU: AMD Radeon AI PRO R9700 (Vulkan)

## Commands and exit codes

A clean Release rebuild and fresh configure completed with exit 0. The logs are clean.log, configure.log, and build.log in this directory. Command:

    & cmd.exe /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul && cmake --build F:\rawrxd\.build_d1_replay_1977e --target clean --config Release > F:\rawrxd\.worktrees\codex-d1-replay-338c7d\evidence\D1_REPLAY_1977E_20261019\clean.log 2>&1 && cmake -S F:\rawrxd\.worktrees\codex-d1-replay-338c7d -B F:\rawrxd\.build_d1_replay_1977e -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_TESTS=OFF -DRAWRXD_BUILD_BENCHMARKS=OFF -DRAWRXD_BUILD_WIN32IDE=OFF -DRAWRXD_BUILD_WIN32IDE_QT=OFF -DFETCHCONTENT_ZLIB=OFF -DENABLE_CUDA=OFF -DENABLE_HIP=OFF -DENABLE_VULKAN=ON -DVULKAN_SDK=C:\VulkanSDK\1.4.357.0 > F:\rawrxd\.worktrees\codex-d1-replay-338c7d\evidence\D1_REPLAY_1977E_20261019\configure.log 2>&1 && cmake --build F:\rawrxd\.build_d1_replay_1977e --target deep2_d1_prefill_parity --config Release --parallel 3 > F:\rawrxd\.worktrees\codex-d1-replay-338c7d\evidence\D1_REPLAY_1977E_20261019\build.log 2>&1'

Matrix command exited 0:

    F:/rawrxd/.build_d1_replay_1977e/bin/deep2_d1_prefill_parity.exe --model F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf

Full stdout/stderr: tinyllama_matrix.log. The process inventory query matched process names containing deep2, quant_registry, or rawrxd; both before and after snapshots were empty. See processes_before.json and processes_after.json.

## Results

The 129-token serial reference produced 32,000 logits per position with zero CPU fallback. Direct PrefillBatch calls passed lengths 1, 2, 8, 32, and 128. Every full-vocabulary logit row matched the serial position bit-for-bit (5,472,000 compared floats total; max absolute difference 0). All committed K/V rows in every block matched the serial reference bit-for-bit (1,926,144 compared floats; max absolute difference 0). Each prefix then continued by one known token; continuation logits and K/V row in all blocks matched bit-for-bit, Position/LastToken/CommittedKvTokens advanced correctly, and CPU fallback remained zero.

The five prefills recorded 1,034 quant-dot batch submissions and 26,334 batched dots. Every length reported GPU-only=YES and grouped-work=YES. The matrix verdict in tinyllama_matrix.log is PASS with zero failures. Measured elapsed times are a single-run receipt, not performance certification.

## Files

- CMakeLists.txt
- src/deep2/runtime_graph_executor.cpp
- src/deep2/runtime_graph_executor.hpp
- tools/deep2_d1_prefill_matrix.cpp
- evidence/FULL_IDE_COMPLETION_LEDGER.md
- evidence/D1_REPLAY_1977E_20261019/clean.log
- evidence/D1_REPLAY_1977E_20261019/configure.log
- evidence/D1_REPLAY_1977E_20261019/build.log
- evidence/D1_REPLAY_1977E_20261019/tinyllama_matrix.log
- evidence/D1_REPLAY_1977E_20261019/processes_before.json
- evidence/D1_REPLAY_1977E_20261019/processes_after.json
- evidence/D1_REPLAY_1977E_20261019/receipt.md

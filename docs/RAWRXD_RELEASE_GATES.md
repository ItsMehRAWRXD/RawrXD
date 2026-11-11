# RawrXD Release Gate Ledger

This ledger separates source presence from executable certification. No gate passes by
having a file, a feature flag, or a plan alone. Run tests on the canonical Windows
hardware and attach receipts with commit SHA, command, exit code, model and device.

| Gate | Minimum passing evidence | Current status |
| --- | --- | --- |
| Deep2 correctness | deterministic multi-token decode, finite hidden states, reference token parity | BLOCKED: FORWARD_FAULT / prior repeated-token output |
| Deep2 dual GPU | two nonzero GPU dispatch counters, strict zero fallback, token parity | NOT CERTIFIED |
| Deep2 performance | matched prompt/model/quantization 150+ decoded tok/s with correctness | NOT CERTIFIED |
| Native C++20 | representative conformance suite, objects, link, executable, diagnostics | NOT CERTIFIED |
| MASM x64 | representative instructions, relocations, ABI, link/run differential suite | NOT CERTIFIED |
| Self-hosted bootstrap | compiler builds itself twice and outputs reproducible executables | NOT CERTIFIED |
| GhostText | physical editor insertion, cancellation and undo end-to-end | NOT CERTIFIED |
| LSP | initialize/initialized, completion, diagnostics, restart and shutdown | NOT CERTIFIED |
| Debugger | launch/attach, breakpoints, stepping, variables, termination | NOT CERTIFIED |
| Snapshots | transaction commit, rollback, crash recovery, hash verification | PARTIAL |
| Windows CI | clean MSVC configure/build/test on hosted Windows runner | NOT CERTIFIED |
| Enterprise | secrets, least privilege, threat model, signing, SBOM, audit trail | NOT CERTIFIED |

## Current regression workflow
`.github/workflows/deep2-native-safety.yml` compiles small dependency-free
expert-bounds and cache-budget tests on Windows and Linux. Passing these does not
certify the full Deep2 engine or release.

## Next blocking Deep2 evidence
1. Record first error preceding FORWARD_FAULT and prefill/decode phase.
2. Prove nonzero Q6_K token embedding, correct row offset and destination.
3. Record input/output hashes for layer 0, 1 and last layer.
4. Compare greedy output tokens against a trusted reference using the same GGUF.
5. Only after correctness: profile and optimize GPU dispatch and waits.

Never merge a performance optimization based solely on throughput when token
parity is failing. Preserve the known-working Ollama path.

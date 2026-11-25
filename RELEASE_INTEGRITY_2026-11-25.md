# Release Integrity Checklist (2026-11-25)

Reflects TRUE state at HEAD. `CERTIFIED=0`, `PROMOTE=0`, `RELEASE=HELD`. No gate promoted.

## Verified done (source → build → verify → commit)
- [x] Deep2 benchmark target (`deep2_benchmark.exe`, real `Deep2Engine`, fail-closed CLI)
- [x] Harness JSON integration (`bench/run_matrix.ps1`)
- [x] LSP Content-Length matrix (16/16 PASS)
- [x] Crash-filter acceptance (AV `0xC0000005` + div0 `0xC0000094` → witness + minidump)
- [x] Deep2 fail-fast build enforcement (missing engine/GPU source → FATAL_ERROR)
- [x] Cancellation lifecycle (`--cancel-after`, CANCELLED=PASS)
- [x] Session-writer consolidation (FileOps single owner; duplicate removed from orphaned Session.cpp)
- [x] Model-driven completion popup (LSP-backed `lspCompletion`, keyword fallback)
- [x] Provider routing verified (BackendRouter Deep2/Ollama, cloud off) — by inspection
- [x] GPU MoE router implemented (opt-in `DEEP2_GPU_ROUTER`) — **PARITY-PENDING**

## Blocked (environment-gated)
- [ ] GPU MoE router parity (needs R9700 + GLM GGUF vs CPU reference)
- [ ] Perf A–G / 150 TPS / 23-23 (needs R9700 + models)
- [ ] Terminal receipt handoff (GUI runtime)
- [ ] Relaunch lifecycle (GUI runtime)
- [ ] Model-driven completion popup (GUI + model)
- [ ] Provider routing (GUI + Ollama/cloud)
- [ ] Native session restoration (compile/link + GUI)
- [ ] Session-writer consolidation (ODR/link-verified)
- [ ] CMake source consolidation (reconfigure + link all targets)
- [ ] Repo consolidation (destructive; scope approval)

## Release gates
```
CERTIFIED = 0
PROMOTE   = 0
RELEASE   = HELD
```
Release requires: all [ ] above closed with commit-bound receipts + independent review.
No stubs promoted to production; GPU MoE router stays opt-in until parity PASS.
# Batch 13 — Concurrent agent catalog and chat-boundary hardening

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Audited defects

1. The known-tool name catalog was a process-global mutable `static std::vector<std::string>`. Concurrent agent threads could overwrite one another's catalogs, causing false tool recognition or rejection. Replaced with `thread_local` in production and portable parser.
2. `buildPrompt` inserted user input, tool arguments and tool-result excerpts directly into Qwen chat-template messages. Reserved delimiters `<|...` could cross model role boundaries. Added escaping of the reserved `<|` prefix in untrusted data before prompt interpolation.

## Commits

- `73a5a0cb4227f43f11cd2ca21ac34ee1936937fb`: thread-local known-tool catalog in production.
- `8999c017ec671e19c3f5f52fd07adcb8aaf0928f`: thread-local known-tool catalog in portable parser.
- `c479346e4c51523eb8da5bca2c6277e06dd6a965`: escape role-delimiter prefixes in user request, replayed args and tool results.
- `b8c5c3acdaca586027160efd61f359693b72cdfe`: 15 concurrent thread-isolation cases in protocol selftest.

## Fifteen new test cases

Each of 15 worker threads registers one unique tool name, then tests that (a) its own tool is recognized and (b) a neighboring thread's tool is not recognized. This tests cross-thread catalog isolation, not full agent-session isolation.

## Residuals and verification

- Tests committed but not executed here; GitHub commit statuses and associated workflow-run lookup returned empty results.
- `thread_local` is not per-session isolation if multiple sessions are multiplexed on one thread; a session-owned catalog is preferable.
- The prompt-escaping helper has no standalone regression test yet.
- The headless agent read-only audit registry remains distinct from the authorized file-mutation agent path.
- Native Windows GUI, GPU numerical correctness, end-to-end model-to-editFiles-to-disk, packaging and T25 certification remain unverified.

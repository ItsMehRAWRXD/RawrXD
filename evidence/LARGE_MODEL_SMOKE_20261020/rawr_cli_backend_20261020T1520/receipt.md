# Native `rawr` CLI reachability receipt — 2026-10-20

Status: **OPEN (backend wiring)**

The shipped `F:\rawrxd\bin\rawr.exe` was queried after the large-model
receipts. `rawr models --json` listed 16 workspace fixture GGUFs and reported
`inference_reachable: false`; it did not enumerate the Ollama blobs used by the
large-model tests. `rawr backend status --json` reported the configured
Deep2/llama-compatible endpoint `http://127.0.0.1:8080/v1/chat/completions`,
with `reachable: false`. `rawr doctor --json` consequently returned
`verdict: FAIL` with its only failure being the unavailable inference backend;
the CMake, Git, tool registry, path-scoping, permission, and workspace-write
checks passed.

The detailed JSON outputs and exit capture are stored beside this receipt.
This is an IDE/CLI integration boundary, independent of the native benchmark
and ROM manifest results.

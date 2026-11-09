# RawrXD native runtime execution harness — Source Drop 015

No Qt, libcurl, OpenSSL, json library, or other third-party code. C++20 + OS native sockets. CMake requires installed compiler. No modifications to existing IDE source or GGUF files.

## What exists
`rawr-runtime probe 127.0.0.1 11435 output/receipt.json` performs actual GET requests for `/health`, `/v1/models`, and `/api/engine/capabilities` over loopback. A failure yields exit 1; usage/receipt failures yield exit 2. JSON receipt is staged then published. Only HTTP 200 with JSON-shaped body passes. This is intentionally a **transport smoke test** and does not parse JSON semantically or prove inference, GPU dispatch, GUI interactions, signing, or a working autonomous agent.

Security boundaries: numeric 127/8 loopback only, 2 MiB response cap, receive/send timeouts, 4-second overall target; HTTP chunked transport deliberately rejected to avoid incorrectly calling unparsed payloads valid. An unresponsive connect can still exceed the target on some OSes: future upgrade needs nonblocking connect and polling. No external requests, shell execution, destructive operations, or model modifications.

## Build
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Win32 integration
Compile against Windows SDK, `ws2_32.lib`. Recommended standalone test against existing running native gateway; do not start/stop unrelated processes. Add `rawr-runtime` under `src/runtime_execution_015/` as a separate CMake subdirectory only after standalone test. Map receipts into the existing `src/ide_gates/` and `runtime_evidence_014` ledger—do not install another gate database or mark feature gates passed based on health alone.

The full roadmap in `docs/ROADMAP_391_420.md` includes 30 numbered milestones. Its milestones are plans, not completed features.

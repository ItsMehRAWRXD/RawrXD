# Batch 012: 45 gates, source evidence vs runtime proof

## First 15: CI and native IDE
01 [source] native IDE CMake target; 02 [configured] Windows IDE build; 03 [configured] artifact upload; 04 [configured] headless agent build; 05 [configured] snapshot build; 06 [configured] GCC smoke; 07 [configured] MSVC smoke; 08 [configured] native LSP framing test; 09 [configured] source audit; 10 [configured] no-deps audit; 11 [pending] hosted CI job logs; 12 [pending] executable startup; 13 [pending] IDE UI interaction; 14 [pending] strict Qt-free binary; 15 [pending] integrated release packaging.

## Second 15: ROM and dual GPU
16 [done] inspect failed-upload ownership path; 17 [committed] handle upload returning false with a valid binding; 18 [committed] gate cleanup on GPU idle; 19 [committed] count failed upload rejection; 20 [committed] test failed upload resource release; 21 [committed] test no execution after failed upload; 22 [committed] test zero retained bytes on failure; 23 [configured] R9700 check; 24 [configured] RX7800XT check; 25 [configured] Vulkan enumeration; 26 [pending] actual fence callback; 27 [pending] actual GPU allocator; 28 [pending] multi-token numerical parity; 29 [pending] 11-shard DeepSeek MoE proof; 30 [pending] 150TPS reproducible benchmark.

## Third 15: Full IDE E2E
31 [source] native editor; 32 [source] native GhostText; 33 [source] PowerShell panel; 34 [source] LSP framing; 35 [source] snapshot engine; 36 [pending] LSP process/handshake; 37 [pending] diagnostics/completions; 38 [pending] GhostText physical acceptance; 39 [pending] PowerShell cancellation; 40 [pending] browser navigation; 41 [pending] debugger expressions; 42 [pending] agent edit-build-test; 43 [pending] rollback after failed test; 44 [pending] independently evidenced top-25 parity; 45 [pending] 100% completeness certification.

**Known gaps:** Release callback is optional and caller-managed; no Vulkan fences are wired. A failed uploader that does not return a valid binding must clean up its own allocation. Root CMake CLI still references external JSON. GitHub Actions run evidence is unavailable through the current connector. No runner access to the physical GPUs is established. 45 gates are not 45 completed fixes.

# Recovery verification scope

Base HEAD: ce8ee05cd442aee45af7476de7f3144f795cb6b9; working tree contains pre-existing changes. This is not clean-tip release certification.

- Deep2Engine.cpp MSVC C++20 translation-unit compile: PASS after repairing MLA KV API calls, duplicate local declarations, unmatched branch braces and printf string arguments. MLA numerical equivalence is NOT certified by a compile.
- Fresh CMake configure: PASS in build_gate_recovery_20261013.
- rawrxd_deep2_engine link inventory: FAIL, 269 unresolved externals including missing main. Full product build remains OPEN; this target explicitly documents its inventory purpose.
- q8k_edge_tests, q8k_byte_parity, quant_parity_cert, kquant_dot_parity: fresh CMake build + CTest PASS (4/4).
- gate2_manifest_consistency: fresh CTest PASS (1/1). This closes the tested manifest-consistency contract only; no broader primitive-coverage inference.
- Gate 9 parser: 10 boundary cases PASS using the actual ParseAction source extracted into a standalone MSVC test. Incomplete read/bash/finish streams are rejected; multiline write bodies survive delimiter parsing.
- Gate 9 tool harness: workspace quoting and independent executable path fixed. Final agentic build PASS with isolated object output directory. The earlier model-driven trial was interrupted after generating prose instead of tools; no autonomous-loop PASS is claimed.
- GPU quant-dot grouping: TinyLlama seed [1,185], eight choices identical with grouping disabled/enabled; submissions reduced 1550 to 956, zero CPU fallback. No 150 TPS certification.

Logs are preserved alongside this note. Historical PASS evidence was not overwritten. Proposed release roadmap IDs are defined in ROADMAP.md.

# Deep2 Batch 46–60: Expert Classification Reconciliation

Dependency-free C++20 source. No third-party runtime. This batch analyzes a **complete TSV tensor inventory**, not GGUF directly. Feed it from the existing AutoArch / GGUF directory parser. It does not implement model operators or hot rebuild.

## Input format
Each line is tab-separated: `tensor_name<TAB>ggml_type<TAB>storage_bytes<TAB>dim0<TAB>shape_candidate(0/1)<TAB>name_candidate(0/1)`.

`shape_candidate` and `name_candidate` are independent flags from the discovery process; the analyzer also matches `dim0 == declared_experts`. **This is a conservative candidate union, not a certified expert semantic classification.** Tensor names must be unique; bytes must be positive. The full tensor list is required to claim a complete histogram.

## Build
MSVC: `cl /nologo /std:c++20 /EHsc /W4 /I include src\ExpertAuthority.cpp src\main.cpp /Fe:expert_authority.exe`

Tests: `cl /nologo /std:c++20 /EHsc /W4 /I include src\ExpertAuthority.cpp tests\test.cpp /Fe:test_expert.exe` then `test_expert.exe`.

GCC: `g++ -std=c++20 -Wall -Wextra -Werror -Iinclude src/ExpertAuthority.cpp tests/test.cpp -o test_expert && ./test_expert`

Run: `expert_authority.exe inventory.tsv 25422831872 128`

Exit 0 = histogram complete, 3 = incomplete, 2 = malformed input. JSON includes union/intersection and dtype histogram. **Complete histogram does not certify expert semantics or executable model support.**

## Gates 46–60
46 full tensor manifest ingestion; 47 unique names; 48 strict numeric parsing; 49 nonzero tensor bytes; 50 independent shape candidate set; 51 independent name candidate set; 52 exact intersection; 53 exact union; 54 union byte accounting; 55 dtype byte histogram; 56 dominant physical dtype; 57 declared payload reconciliation; 58 ambiguity diagnostics; 59 machine-readable JSON; 60 fail-closed incomplete inventory exit status.

## Model capture interpretation
The shown three dtype rows sum to 230,110,976 bytes, far below the stated 25,422,831,872-byte payload. This is a partial listing; do not infer dominant dtype from those three rows. `file_type` is a model-level hint, not an operator dispatch authority. The 96 shape candidates and 48 name candidates may overlap: the union size lies between 96 and 144. The current `shexp` clue must be validated against router tensors, full dimensions and execution semantics before activation.

## Production wiring
1. Export all tensors from the already certified GGUF directory scanner.
2. Map canonical `Deep2::GGMLType` IDs to names using `QuantTypeTable.hpp`; use actual tensor storage bytes from the GGUF directory.
3. Emit the six TSV fields and run this executable.
4. Compare the output with the frozen model digest and the 16-model inventory.
5. Only after per-layer expert role and router semantics are established, feed the authoritative classification into ExecutionIR and HotArch.

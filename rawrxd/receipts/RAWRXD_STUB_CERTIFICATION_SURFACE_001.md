# RAWRXD_STUB_CERTIFICATION_SURFACE_001

Status: **MEASURED DEFECT** — the certification surface is largely nominal
Date: 2026-10-01
Scope: all `.cpp` under the repo, excluding build output and `evidence/`

## Measurement

```ini
CPP_SCANNED=2268
EMPTY_BODIED_CPP=638
EMPTY_BODIED_PERCENT=28.1
NAME_CLAIMS_CERT_VERIF_VALID_GATE_PARITY_PROOF=119
OF_THOSE_WIRED_INTO_CMAKE=105
```

A file counts as **empty-bodied** when, after stripping comments and blank lines,
no code remains. That includes the literal `int main(){ return 0; }`, which
compiles and links cleanly while proving nothing.

**105 CMake-referenced translation units whose names assert certification,
verification, validation, gating, parity or proof contain no code at all.**

Distribution of the 119 name-claiming stubs:

| directory | count |
|---|---|
| `src/deep2` | 98 |
| `tests` | 14 |
| `src/agentic` | 4 |
| `certs`, `inference`, `src/benchmark` | 1 each |

Representative contents:

```cpp
// tests/b004_transformer_router_streaming_integration.cpp   (63 bytes)
// STUB: b004_transformer_router_streaming_integration.cpp

// tests/b006_kv_cache_verification.cpp                      (50 bytes)
// STUB: tests/b006_kv_cache_verification.cpp

// B012/build/amortization_test.cpp                           (45 bytes)
// Auto-generated stub for amortization_test

// tests/b009/b009b_batched_gemm.cpp                          (28 bytes)
int main(){ return 0; }
```

## Why this is worse than inert

A stubbed TU is not neutral. It is **actively harmful to the target that
references it**, because it supplies no `main` and no test body:

```ini
b004_transformer_router_streaming_integration
  LIBCMT.lib(exe_main.obj) : error LNK2019: unresolved external symbol main

b012_amortization_test
  LIBCMT.lib(exe_main.obj) : error LNK2019: unresolved external symbol main

b016_gemm_efficiency_probe
  error LNK2005: main already defined in b016_gemm_efficiency_probe.obj
```

So these targets **have never built**. They are `EXCLUDE_FROM_ALL`, which is why
a default `cmake --build .` never surfaced it. The build was green and the
certification targets were unbuildable simultaneously — the exact class of finding
`RAWRXD_BUILD_SOURCE_INTEGRITY_001` exists to prevent.

## The pattern this completes

This measurement completes a consistent picture assembled across the session. Each
item was found independently and each is objectively verifiable:

| layer | nominal | measured |
|---|---|---|
| `authority_test.receipt.txt` | `CERT=PASS`, `PARITY_ALL=1`, `FAILURE=PASS` | 17 static literals, no generator, `FAILURE=PASS` self-refuting |
| `src/deep2/*.asm` | MASM acceleration | **all 21 are 8-line stubs** exporting `*_Stub` |
| MASM wrappers | 7 wrappers for Q4_K/Q4_0/Q4_1/Q8_0/Q5_K/Q6_K/F16 | all 7 dead; the `.asm` exports none of the called symbols |
| `QuantKernelRegistry` | `gemv_q4_k_avx512` | was a one-line scalar delegate, unregistered |
| K-quant GEMV | Q4_K/Q5_K/Q6_K/Q2_K/Q4_0… | scalar-only; Q4_K now real AVX-512, the rest still scalar |
| `RegisterIQKernels()` | IQ type support | **empty stub**; `GetGEMV` returns `nullptr`, `LinearW` throws |
| IDE target | shipping IDE | `RAWRXD_BUILD_WIN32IDE` default **OFF**, self-described "legacy" |
| `WIN32IDE_SOURCES` | source list | **225 referenced files do not exist**, dropped with a WARNING |
| IDE runtime gate | — | 16 stages measured: 9 PASS, 1 FAIL, 5 NOT_IMPLEMENTED, 1 BLOCKED |

None of these is a judgement call. Each is a count or a source fact.

## The one rule that prevents recurrence

The repo already contains the mechanism: `rawrxd_filter_missing_sources`
(`CMakeLists.txt:201-245`) drops non-existent paths, and with
`-DRAWRXD_STRICT_SOURCES=ON` it escalates to `FATAL_ERROR`. It operates on
**existence**, not on **content**. A 45-byte file that exists passes it.

The missing rule is content-based:

```ini
STUB_GATE=reject
TRIGGERS=file exists AND body is empty after comment stripping
           OR body is exactly `int main(){ return 0; }`
SEVERITY=FATAL_ERROR
RATIONALE=an empty TU cannot certify anything, and a target referencing one
         cannot link, so its existence is a false claim in both directions
```

`EnforceNoStubs` (`CMakeLists.txt:6527-6553`) already does name-pattern matching
(`_stub\.cpp`, `stub_.*`, `shim_.*`, `_(mock|fake)`, `link_stubs_.*`). These stubs
mostly **avoid** those patterns — the file is named `deep2_gpu_q4k_gemv_cert.cpp`
and its *contents* say `Auto-generated stub`. A name filter cannot catch this; only
a content check can.

## Disposition

```ini
STUB_CERT_TUS=105
IMPLEMENT_ANY=0          # requires authoring real tests; out of scope here
WIRED_TU_BREAKS_TARGET=1 # confirmed: LNK2019 unresolved main
FALSE_CLAIM_SURFACE=QUARANTINE_NAMES
```

Recommended order, cheapest first:

1. Add the content-based stub gate so no new stub can be wired in.
2. Configure every wired stub target once and record which fail to link, so the
   list is measured rather than inferred.
3. Rename or quarantine the 105 so no receipt can cite a target that never ran.
4. Only then decide which deserve real implementations — 119 test-shaped names
   with 105 empty is a scoping question, not an engineering backlog.

Deleting them instead would be wrong: several names describe gates that genuinely
should exist. The defect is that they are named as if they do.

# DEEP2_REQUEST_COMPILER_50_NODEP

A dependency-free C++17 request compiler for turning large natural-language task sets into a smaller, deterministic execution graph.

## What it provides

- 50 named de-complexing mechanisms.
- Request canonicalization and requirement atomization.
- Semantic deduplication.
- Conservative dependency inference.
- Transitive-edge reduction.
- Dominance pruning.
- Side-effect/risk classification.
- Uncertainty-weighted priority.
- Critical-path extraction.
- Ready-set / blocker computation.
- Proof-carrying node metadata.
- Authority separation: UNKNOWN / PROJECTED / DERIVED / MEASURED.
- Deterministic state hashing.
- Incremental `mark()` + recomputation.
- C++ API and stable C ABI.
- No third-party dependencies.

## Drop-in files

- `d2_request_compiler.hpp`
- `d2_request_compiler.cpp`

Compile them directly into RawrXD/Deep2. The module does not own threads, files, processes, model runtime, networking, or Git. It only compiles and maintains the execution graph; your existing executor remains authoritative.

## Minimal C++ usage

```cpp
auto r = d2rc::compile(
    "write loader; build loader; test loader; verify loader; commit loader; push loader"
);
if (!r.ok) return 1;

for (uint32_t id : r.plan.ready) {
    // route id to your executor
}

// When an executor finishes:
d2rc::Evidence e;
e.authority = d2rc::Authority::Measured;
e.source = "build receipt";
e.proof = "EXIT=0";
d2rc::mark(r.plan, id, d2rc::Status::Pass, &e);
```

## Integration seam

Recommended RawrXD placement:

```text
src/deep2/request_compiler/d2_request_compiler.hpp
src/deep2/request_compiler/d2_request_compiler.cpp
```

Recommended execution loop:

```text
USER REQUEST
 -> d2rc::compile()
 -> plan.ready
 -> existing capability/tool router
 -> executor result + evidence
 -> d2rc::mark()
 -> recompute ready/blockers/critical path
 -> repeat until closure
```

Do not treat planning PASS as product/runtime PASS. The planner records evidence authority but does not mint authority on behalf of an executor.

## Build

MSVC:
`build_msvc.bat`

GCC/Clang:
`./build_gcc.sh`

## Self-test expected output

`DEEP2_REQUEST_COMPILER_50_NODEP_SELFTEST=PASS`

# RAWRXD_REVERSE_ASSEMBLY_ENGINE_001 — REV 3 (supersedes Rev 1 and Rev 2)

**Rev 1** contained a fabricated defect (D3) and an invalid cert case (C4).
**Rev 2** retracted those correctly but retained a second wrong defect (D1)
*and* shipped a buggy fix for it.
**Rev 3** retracts D1 too, and records that the fix as written in Rev 2 would
have introduced a real defect.

Status: IMPLEMENTED AND PROVEN. One confirmed defect fixed with a FAIL->PASS
cycle. The substantive win is build wiring, not the code change.

File history note: `ReverseAssemblyEngine.cpp` and `.h` are UNTRACKED in git
(`??`) and already carried correct D1/D2 logic before this work began. Rev 2's
premise "Source NOT yet modified" was stale.

---

## What shipped

```ini
NEW  CMake target reverse_assembly_cert (EXCLUDE_FROM_ALL, like other certs)
     sources: tools/reverse_assembly_cert.cpp
               src/cli/ReverseAssemblyEngine.cpp      <- required for the link
     The plan's snippet omitted the engine source; without it the target cannot
     link because loadFromFile/postProcess/predictByte live there.

D2   CONFIRMED -> FIXED
     was: if (outConfidence) *outConfidence = 1.0;   // asserted
     now: measured coverage = patternText.size() / input.size(), capped at 1.0

RECEIPT (FAIL, D2 temporarily reverted to prove the cert can fail)
     C1 dedupe keeps non-adjacent duplicate bytes        PASS
     C2 containment hit does not assert confidence 1.0   FAIL
     C3 unseen input returns nullopt                     PASS
     CHECKS=3 FAILS=1 VERDICT=FAIL  EXIT=1

RECEIPT (PASS, after fix)
     C1 PASS   C2 PASS   C3 PASS
     CHECKS=3 FAILS=0 VERDICT=PASS  EXIT=0
```

The cert constructs the engine through `loadFromFile()` with a temp JSON
fixture. No setter or accessor was added to ReverseAssemblyEngine.

---

## D1 — RETRACTED. Rev 2 was wrong.

Rev 2 claimed:

> `std::unique` collapses adjacent runs, so `{0x41,0x42,0x41}` becomes
> `{0x41}`. The behaviour removes every duplicate.

**That is false.** C++ defines `std::unique` as: "Eliminates all but the first
of each group of consecutive duplicate elements." It removes only ADJACENT
duplicates. `{0x41,0x42,0x41}` contains no consecutive duplicates and passes
through unchanged.

So:
- `dedupeConsecutive` was implemented correctly and named accurately
- there was never a data-loss defect
- the C1 test vector was incapable of distinguishing correct from broken
  behaviour, because it contains no adjacent duplicates

**C1 must be deleted or rewritten.** A check that cannot fail is the same class
as the K2 harness "cosine" that was `sqrt(sum_dot)`. If kept, C1 must use a
vector that actually contains adjacent duplicates, e.g.
`{0x41,0x41,0x42,0x41}` -> must yield `{0x41,0x42,0x41}`.

---

## D1-fix-as-written-in-Rev-2 — BUGGY, DO NOT USE

Rev 2 proposed:

```cpp
if (out == bytes.begin() || *out != *it) *out++ = *it;    // WRONG
```

`*out` addresses the next UNWRITTEN slot, not the last written element. On
`{0x41,0x42,0x41}` this collapses to `{0x41,0x41}` — introducing exactly the
defect Rev 2 claimed to be fixing.

The correct form (already present in the source) is:

```cpp
if (out == bytes.begin() || *(out - 1) != *it) *out++ = *it;
```

No change is required to the engine for D1. None was made.

---

## D3 — RETRACTED (carried from Rev 1)

Rev 1 claimed a missing `clip_range` clamps output to zero. The header says:

```cpp
uint8_t clipMin = 0;
uint8_t clipMax = 255;
```

Omitting `clip_range` yields a full-range no-op. No defect exists. The Rev 1
cert case C4 (`clipMin > clipMax`) is INVALID — that state cannot arise from
JSON omission. It was a synthetic condition invented to make a test fail, which
is a manufactured red. Deleted in Rev 2, stays deleted.

---

## Still open (not addressed)

```ini
F2  Sample::output defaults to 0; a sample whose JSON omits "output" yields byte
    0x00 returned at the sample's full declared confidence. A value produced
    from an absent field. Requires Sample::output -> std::optional<uint8_t>.
    C4 should be written to cover this once implemented.

F1  .h:86-87 promises "If nlohmann/json is NOT in the build, a minimal fallback
    parser is used." There is no fallback; the include is unconditional.
    LOW: json.hpp is vendored in 3 places. Either implement the fallback or
    correct the comment. A comment that describes a capability that does not
    exist is the same class as the D3 claim above.

D4  metadata.accuracy and trainingSamples are parsed but no code path reads
    them. predictByte ignores accuracy. Naming/disposition decision: rename to
    reflect that it is a deterministic pattern matcher, or implement inference.
```

---

## Post-conditions before this counts as evidence

```ini
VERDICT=PASS in a local build is NOT sufficient. EXCLUDE_FROM_ALL means ctest
will not run it unless invoked.

REQUIRED:
  add_test(reverse_assembly_cert ...) so CI executes it
  confirm the target appears in a clean configure
  confirm the engine source is in the target (regression against
    "cert built, engine not")
```

## Method note — the failure mode to avoid

Three assertions in this project over two days were false, each caught only by
checking rather than reasoning:

```ini
D3  clip-range  -> header defaults disprove it
D1  std::unique -> the C++ standard disprove it
Q2K block size -> Q3_K is 110 bytes, not 84, invalidating 2 of 5 census results
```

Rule that would have prevented all three: never state a mechanism that has not
been read in source or measured at runtime.
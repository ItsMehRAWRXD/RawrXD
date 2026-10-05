# RAWRXD_COVERAGE_CONSERVATION_001

Publication accounting for `F:\~dev` at snapshot `c4eaffb8f`.

```ini
GENERALISED_LAW=NEVER_CERTIFY_COMPLETENESS_USING_THE_SAME_ENUMERATION_MECHANISM_THAT_DEFINES_WHAT_COMPLETE_MEANS

TOTAL_UNIVERSE_ENTRIES=286

CLASS_SOURCE_REPO=7
CLASS_ARTIFACT_REPO=278
CLASS_EXPLICITLY_EXCLUDED_REPRODUCIBLE=1
CLASS_NOT_UPLOADABLE=0
CLASS_UNKNOWN=0

CLASS_SUM=286
CLASS_SUM_EQUALS_TOTAL=1
UNACCOUNTED=0
```

## Why two enumerators

A prior pass reported a plausible count using a **name-pattern filter**, and
that filter silently excluded 226 objects while its own tally looked
reasonable. The defect was only visible when completeness was measured by a
*different* mechanism.

So this receipt uses two structurally different enumerations:

| Role | Mechanism |
|---|---|
| `UNIVERSE_ENUMERATOR=A` | `git status --porcelain=v1`, then substring `+3` |
| `CLASSIFICATION_ENUMERATOR=B` | per-path existence probe against a fresh remote clone, plus `git diff --name-only HEAD -- <path>` |

A is "what git says is outstanding". B is "for each of those paths, does a
published counterpart exist, and is the published copy the right bytes".
Neither consults the other's bookkeeping.

## Class B, per path

```text
published_in_source_repo=7
published_in_artifacts_repo=278
published_nowhere=1   ->  real_tinyllama_f32.nqb
```

`real_tinyllama_f32.nqb` is not missing. It is classified as
`REPRODUCIBLE_NOT_UPLOADED`: 4,197.5 MB, 42x GitHub's 100 MB per-file hard
limit, and regenerable by a recorded command whose own receipt is preserved.
Its expected whole-file size and SHA-256 are pinned in
`RAWRXD_ARTIFACT_MANIFEST_001` so regeneration can be *proved* equal.

## Snapshot semantics

This receipt describes a **published generation**, not a live tree.

```ini
PUBLISHED_SNAPSHOT=c4eaffb8f
PUBLICATION_TIMESTAMP=2026-10-05T00:30Z
VERDICT=PASS_FOR_SNAPSHOT

CURRENT_WORKTREE_EQUALS_SNAPSHOT=0
CAUSE=CONCURRENT_SOURCE_EVOLUTION
MEASURED_EXAMPLES:
  rawrxd/src/deep2/Nanof32BraidWriter.cpp    504 lines changed after publication
  rawrxd/tools/gguf_to_nqb_converter.cpp     263 lines changed after publication
  rawrxd/CMakeLists.txt                       89 lines changed after publication
```

The correct claim is `PASS_FOR_SNAPSHOT`. "Everything is uploaded" is not a
property of a tree that other lanes are still editing; it was true at
`c4eaffb8f` and stopped being true the moment another lane saved a file.

Any NQB receipt produced against the live tree must therefore carry the new
build identity and may **not** inherit certification from `f07b6aee6`:

```ini
f07b6aee6 = CERTIFIED_HISTORICAL_GENERATION
LIVE_TREE  = CANDIDATE_DESCENDANT_REQUIRING_ITS_OWN_GATES
```

## A third byte-stability defect, found by this exercise

The full 494-object rehash — the check that made this receipt's B enumerator
meaningful — found that **12 of 494 evidence objects were not byte-stable**.
`core.autocrlf` stored text receipts LF and checked them out CRLF, so the
manifest digest described a transformation rather than the artefact.

Root-caused, fixed with `* -text`, and re-verified 494/494 from a fresh clone.
Recorded in full in `RAWRXD_ARTIFACT_MANIFEST_001`.

Note the relationship: that defect was invisible to a spot check (3/3 passed
while 12 were broken) and invisible to a filter count. It took a *different
mechanism applied to every object*. Same law, third instance.

## Lane separation

Unaffected by publication, recorded so it is not disturbed:

```ini
Q4_0_SHARED_GEMV_NIBBLE_ORDER=CLOSED
Q5_0_SHARED_GEMV_NIBBLE_ORDER=CLOSED
Q5_0_FIFTH_BIT_PLANE=NEVER_DEFECTIVE
Q3_K_VULKAN_PATH=OPEN
ATTN_OUTPUT_Q3_K_DIVERGENCE=OPEN
NQB_FIRST_BAD_STATE=INDEPENDENT_LANE
```
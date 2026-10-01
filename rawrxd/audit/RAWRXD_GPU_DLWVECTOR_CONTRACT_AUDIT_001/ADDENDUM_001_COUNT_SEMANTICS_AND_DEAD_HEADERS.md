# RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT — ADDENDUM 001

    AUDIT      = RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001
    DATE       = 2026-10-01
    HEAD       = acb63e87143e
    SCOPE      = (a) duplicate-header authority question, (b) the
                  `qElems*sizeof(float)` count-semantics question at
                  vulkan_compute.cpp:4024. AUDIT ONLY -- no edit was made to
                  either subject.

---

## 1. Frozen disposition

```ini
RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001=PASS

AUTHORITATIVE_DECLARATIONS=1
AUTHORITATIVE_DEFINITIONS=1
OVERLOADS=0

EXTERNAL_CALLSITE_VIOLATIONS=0
SIGNATURE_CHANGE_REQUIRED=0
CALLER_CHANGE_REQUIRED=0

INFERENCEENGINE_BUILD=PASS
WIN32IDE_BUILD=PASS
BUILD_BLOCKED=0

CHECKPOINT_ROLLBACK_FINAL_BINARY_RETEST=PASS

PRIOR_DOWNLOADVECTOR_BUILD_BLOCKER=RETRACTED
CAUSE=TRANSIENT_CONCURRENT_WORKTREE_STATE
```

---

## 2. The duplicate headers are hygiene, not authorities

The four near-duplicate headers plus the `.backup` file all carry the same
declaration text, but **nothing includes any of them**. A repo-wide search for
the four names returns only:

    all_src_files.txt                                  file inventory
    evidence/RAWRXD_STUB_RECONCILIATION_001/...        placeholder manifest
    audit/RAWRXD_DUPLICATE_AUTHORITY_001/Q2_6_RECEIPT.md
    audit/RAWRXD_EVENTLEDGER_AUTHORITY_001/Q2_5_RECEIPT.md
    audit/RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001/    this audit

Zero `#include` sites, zero CMake source entries. `vulkan_compute.h.backup` is
not addressable by name from a build at all.

    AUTHORITATIVE_HEADER        = 1  (src/deep2/vulkan_compute.h)
    DEAD_COPIES_CARRYING_TEXT   = 5
    DEAD_COPIES_INCLUDED_ANYWHERE = 0
    COMPETING_AUTHORITIES       = 0

They are recorded as repository hygiene / dead copies. They are not counted as
authorities and they do not create a second contract.

---

## 3. The `qElems*sizeof(float)` question, settled from the contract

The question was whether `count` is an element count or a byte count. Both ends
of the contract answer it, in the same direction:

    UploadVector   vulkan_compute.cpp:  count*sizeof(float) -> uploadToBuffer
    DownloadVector vulkan_compute.cpp:3693  downloadFromBuffer(src, dst, count*sizeof(float))

`count` is an **element count of floats**. The byte size is computed internally.
`EnsureScratch(unsigned, size_t floatCount)` (`vulkan_compute.h:248`) uses the
same units, which corroborates it.

So the idiom at `vulkan_compute.cpp:3987-3989` and `:4024` is a genuine unit
error: the caller expresses bytes, the callee interprets elements.

### What actually happens -- both directions are bounds-checked

    uploadToBuffer   vulkan_compute.cpp:1555  if (... bytes > dst.size) return false
    downloadFromBuffer vulkan_compute.cpp:1736 if (... bytes > src.size) return false

In `VulkanCompute::RunMLAAttentionHost` (`vulkan_compute.cpp:3867`):

    :3976  qElems        = heads*keyLen                      (element count)
    :3978  EnsureScratch(40, qElems)                         -> qBuf.size   = qElems*4 bytes
    :3981  EnsureScratch(43, qElems)                         -> outBuf.size = qElems*4 bytes
    :3987  UploadVector(qBuf, q, qElems*sizeof(float))
             -> asks for (qElems*4)*4 = qElems*16 bytes into a qElems*4 buffer
             -> uploadToBuffer: bytes > dst.size  ->  returns false
    :3990  return false                                     <-- short-circuits here

`:4024` is therefore **unreachable on this path**: `||` short-circuits at the
first operand, and the first operand always fails because `qElems*16 > qElems*4`
for every `qElems > 0`.

### Consequence classification

    UNIT_ERROR_AT_4024            = CONFIRMED (bytes where elements are contracted)
    MEMORY_CORRUPTION             = NOT_OCCURRING (both directions bounds-checked)
    HOST_BUFFER_OVERREAD          = NOT_OCCURRING (first upload fails before any memcpy)
    REACHABILITY_OF_4024          = UNREACHABLE while :3987 stands
    NET_BEHAVIOUR                 = RunMLAAttentionHost returns false on first transfer,
                                     deterministically, for every input

So this is **not** a 4× transfer that silently corrupts results. It is a
deterministic early `false` on the MLA host-attention path -- a different and
narrower defect class. `sizeof(float)` was applied where the callee already
applies it, four times in one function.

### What remains genuinely open

- `RunMLAAttentionHost` is consequently non-functional on this path; whether
  that is masked by a caller-side fallback is **not established here** and would
  require a caller census of `RunMLAAttentionHost` specifically.
- Whether the four sites were meant as bytes all along (i.e. whether the author
  intended a byte-expressive API) cannot be determined from the source; the
  function names and `floatCount` naming in the header both say elements.

    FOLLOW_UP_RUNMLATTENTIONHOST_CALLER_CENSUS = OPEN
    EDIT_MADE = NONE

---

## 4. Concurrency procedure this audit validated

```text
reported compile failure
        ↓
verify current HEAD/worktree
        ↓
establish authoritative declaration
        ↓
repository-wide caller census
        ↓
clean rebuild
        ↓
edit only if failure reproduces
```

Two unnecessary repair paths were prevented by running this order: the duplicate
editor functionality, and this GPU API "mismatch". The second one is only
avoidable because the rebuild was gated behind the census -- patching
`Deep2Engine_GpuForward.cpp` at the three visible sites would have edited a file
that was already correct, and would have looked like a legitimate fix.

## 5. Ledger

    RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001        = PASS
    PRIOR_DOWNLOADVECTOR_BUILD_BLOCKER            = RETRACTED
    CAUSE                                          = TRANSIENT_CONCURRENT_WORKTREE_STATE
    DEAD_HEADER_COPIES_INCLUDED_ANYWHERE          = 0
    COMPETING_AUTHORITIES                         = 0
    DOWNLOADVECTOR_COUNT_UNIT                     = ELEMENTS (both directions, source-confirmed)
    UNIT_ERROR_AT_4024                            = CONFIRMED
    4024_REACHABLE                                = 0
    MEMORY_CORRUPTION_FROM_4024                   = 0
    RUNMLATTENTIONHOST_EFFECTIVE                  = ALWAYS_FALSE_AT_3987
    EDITS_MADE_BY_THIS_AUDIT                      = 0
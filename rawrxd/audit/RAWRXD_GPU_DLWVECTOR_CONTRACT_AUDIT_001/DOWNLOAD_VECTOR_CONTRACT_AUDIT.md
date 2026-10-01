# RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT

    AUDIT             = RAWRXD_GPU_DLWVECTOR_API_CONTRACT_001
    HEAD              = acb63e87143e
    DATE              = 2026-10-01
    SCOPE             = read-only contract census. NO signature changed, NO caller
                        changed. The census was performed first precisely so that a
                        fix could not be an opportunistic caller patch.
    VERDICT_KEYS      = DOWNLOAD_VECTOR_API_MISMATCH_PRESENT = 0
                        CALLERS_REQUIRING_CHANGE              = 0
                        SIGNATURE_CHANGE_REQUIRED             = 0
                        BUILD_BLOCKED                         = 0 (was 1)

---

## 1. The single current contract

Exactly one declaration and one definition exist in the tree. There is no
overload set and no obsolete `float*` form anywhere in a live header.

    Declaration  src/deep2/vulkan_compute.h:251
                 bool DownloadVector(const DeviceBuf& src, float* dst, size_t count);
    Definition   src/deep2/vulkan_compute.cpp:3686

The header is **unmodified** in the working tree, and the contract line is
byte-identical at HEAD:

    HEAD: bool DownloadVector(const DeviceBuf& src, float* dst, size_t count);

So the hypothesis "the header changed without migrating its callers" is
**refuted for this API**. `DeviceBuf& Scratch(unsigned)` (`:249`) is what
produces the handles every external caller passes, so the declared contract and
the actual production contract agree.

Five near-duplicate headers exist and all of them declare the **same** signature
— none is a second authority:

    src/deep2/vulkan_compute_batch10.h:188
    src/deep2/vulkan_compute_batch10_utf8.h:188
    src/deep2/vulkan_compute_from_batch10.h:375
    src/deep2/vulkan_compute_patched.h:188
    src/deep2/vulkan_compute.h.backup:188

---

## 2. Repository-wide caller census

27 textual matches; after separating comments and internal delegation, **6
external call sites in 4 files**, plus 7 internal delegations inside
`vulkan_compute.cpp`. Argument 1 classified by its producing expression:

| # | Site | Argument 1 | Producer | vs contract |
|---|---|---|---|---|
| 1 | `tools/q4k_gemv_parity.cpp:309` | `out` | `vc.Scratch(91)` (`:298`) | match |
| 2 | `src/deep2/Deep2DualGpuRowSplit.cpp:1410` | `y1` | `secondary.Scratch(140)` (`:1373`) | match |
| 3 | `src/deep2/Deep2DualGpuRowSplit.cpp:1467` | `y0` | `primary/g0.Scratch(...)` (`:1372`, `:1440`) | match |
| 4 | `src/deep2/Deep2Engine_GpuMoEMLA.cpp:130` | `y` | `g->Scratch(31)` (`:121`) | match |
| 5 | `src/deep2/Deep2Engine_GpuForward.cpp:481` | `arena` | `const DeviceBuf&` parameter of `emit` (`:472-473`) | match |
| 6 | `src/deep2/Deep2Engine_GpuForward.cpp:1244, 1253, 1262, 1271, 1280` | `vc->ArenaResidual/ArenaDown/ArenaNormed/ArenaQ/ArenaAttn()` | arena accessors returning `DeviceBuf&` | match |

Internal delegation, all inside the defining TU and therefore all consistent:

    vulkan_compute.cpp:873   DownloadVector(ob, output, qn)
    vulkan_compute.cpp:918   DownloadVector(out, output, n)
    vulkan_compute.cpp:949   DownloadVector(o, output, n)
    vulkin_compute.cpp:1730  DownloadVector(ob, output, qn)
    vulkan_compute.cpp:3790  DownloadVector(y, output, hidden)
    vulkan_compute.cpp:3852  DownloadVector(y, output, hidden)
    vulkan_compute.cpp:4024  DownloadVector(outBuf, output, qElems*sizeof(float))

    VIOLATIONS = 0

Note `:4024` passes `qElems*sizeof(float)` as the element count while every
other site passes an element count. That is a **count-semantics** question
inside the defining TU, not a signature violation: it compiles and the
definition is what interprets it. It is recorded here as a follow-up
observation, not a defect of this contract.

---

## 3. The reported errors were a transient tree state, not a contract mismatch

The failures quoted in the earlier build log were:

    Deep2Engine_GpuForward.cpp(477,18)   DownloadVector: const float* -> const DeviceBuf&
    Deep2Engine_GpuForward.cpp(861,34)   VulkanParityGrid::emit: DeviceBuf -> const float*
    Deep2Engine_GpuForward.cpp(862,34)   (same)
    Deep2Engine_GpuForward.cpp(1006-1010) (same)

That is **two different** complaints, not one: a call passing `const float*` where
`DeviceBuf` is expected, and `emit` declared with `const float*` while being
handed `DeviceBuf` arenas. In the current tree `emit` is declared with
`const VulkanCompute::DeviceBuf&` (`Deep2Engine_GpuForward.cpp:472-473`) and all
15 of its call sites pass `vc->Arena*()` handles (`:865-866`, `:1010-1014`,
`:1128-1142`, `:1185-1200`).

`git status` reports `src/deep2/Deep2Engine_GpuForward.cpp` as **unmodified**
against HEAD. The file that produced those errors was a mid-flight working state
from another participant, since reverted. The build log retains the evidence;
the source no longer exhibits it.

Decisive re-test, current tree, no code changed by this audit:

    cmake --build build_ide_audit --config Release
             --target ckpt_rollback_crash_cert RawrXD-Win32IDE --parallel 4
    EXIT = 0
    InferenceEngine.lib           rebuilt
    RawrXD-Win32IDE.exe           rebuilt
    RawrXD-Win32IDE.exe sha256    = 8B623935FFE8D4F88BCBFD9C6E311BEC4424AFE88916036DABCA151391A62778
    ckpt_rollback_crash_cert.exe
                       sha256    = 29C18D4A26D94AE28CDEC13DAD3670CCE14467CB79BA9A725466F3239174FC24
    log                          = build_ide_audit/dlv_contract_audit_rebuild.log

---

## 4. Item 9 re-verified on this final tree

    CRASH_KILLED_BY_FAULT_INJECTION=1     CRASH_EXIT_CODE_OBSERVED=0xC0FFEE01
    CRASH_LEFT_DAMAGED_FILES=2             IDENTITY_CHANGED_BY_CRASH=1
    RECOVERY_CHILD_RESTORED_ALL=1          FILES_DIFFERING_AFTER_RECOVERY=0
    BYTE_MISMATCHES_AFTER_RECOVERY=0       TRANSACTION_CREATED_FILE_REMOVED=1
    IDENTITY_RESTORED_TO_BASELINE=1        SECOND_RECOVERY_IS_NOOP=1
    RECOVERY_IDEMPOTENT=1                  POWER_LOSS_SEMANTICS_PROVEN=0
    VERDICT=PASS

    log = ckpt_final_tree_run.log

---

## 5. Ledger

    RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001 = PASS   (process-crash scope)
    MULTIFILE_CRASH_ROLLBACK                      = PROVEN
    REAL_TOOLREGISTRY_WRITE_PATH                   = PROVEN
    SEPARATE_PROCESS_RECOVERY                     = PROVEN
    REAL_WIN32IDE_RECOVERY                        = PROVEN
    PROCESS_CRASH_DURABILITY                      = PROVEN
    POWER_LOSS_DURABILITY                         = NOT_PROVEN
    PER_TURN_TRANSACTION_BINDING                  = PARTIAL
    CLEAN_SHUTDOWN_PATH                           = UNMEASURED
    ORPHAN_RECOVERY_SUBSYSTEMS                    = 11

    PREEXISTING_FILEOPS_LINK_DEFECT               = CLOSED
    CAUSE                                         = declaration/definition namespace mismatch
    STALE_PROJECT_MASKING                         = OBSERVED

    DOWNLOAD_VECTOR_DECLARATIONS                  = 1
    DOWNLOAD_VECTOR_DEFINITIONS                   = 1
    DOWNLOAD_VECTOR_OVERLOADS                     = 0
    EXTERNAL_CALLERS                              = 6 sites / 4 files
    EXTERNAL_CALLERS_VIOLATING_CONTRACT           = 0
    INTERNAL_DELEGATIONS                          = 7
    SIGNATURE_CHANGE_REQUIRED                     = 0
    CALLER_CHANGE_REQUIRED                        = 0
    FOLLOW_UP_COUNT_SEMANTICS_AT_4024             = OBSERVED

    BUILD_BLOCKED                                 = 0
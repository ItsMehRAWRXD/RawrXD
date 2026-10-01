# RAWRXD_IDE_CHECKPOINT_ROLLBACK_RECEIPT

    GATE                = RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001
    LADDER_ITEM         = 9. Checkpoint / rollback (P1)
    HEAD                = acb63e87143e
    DATE                = 2026-10-01
    VERDICT             = PASS (crash-recovery proof, measured)
    SCOPE_LIMIT         = crash-recovery proof only. NOT a durability
                          certification, NOT a clean-shutdown claim, NOT a
                          power-loss claim. See NON_CLAIMS.

---

## 1. What was demanded, and what was absent

The ladder item required transaction-like state around seven things, and proof
of recovery from a crash midway through a multi-file edit:

| # | Required state | Before this work | After |
|---|---|---|---|
| 1 | agent plan | journalled nowhere | `PLAN` record, content-addressed blob |
| 2 | files before modification | never captured by any product write path | `FILE_BEFORE` record + blob, flushed before the write |
| 3 | files after modification | never recorded | `FILE_AFTER` record (path, sha256, bytes) |
| 4 | commands executed | stdout/stderr discarded after the call returned | `CMD` record (command, exit, stdout sha, stderr sha, elapsed) |
| 5 | tool results | returned to the caller, then dropped | `TOOL` record (tool, params sha, success, output sha, error sha, elapsed) |
| 6 | diagnostics | no Problems store exists to persist | `DIAG` record, whatever snapshot the caller supplies |
| 7 | model/context state | in-memory only | `CONTEXT` record |
| 8 | working-tree identity | not captured anywhere | `WORKTREE` record, and re-measured by the recovery pass |

The audit that justified a new mechanism rather than reuse (measured, not
asserted):

- `src/core/transaction_journal.cpp:215-224` — `flushToDisk()` is
  `std::fstream::flush()`; the `_WIN32` branch is empty with the comment
  *"std::fstream doesn't expose the HANDLE, so we rely on flush()"*. It is
  compiled into both the IDE (`CMakeLists.txt:5882`) and RawrEngine
  (`:2729`) and has **zero callers**.
- `src/core/hotpatch_recovery_journal.cpp:590-611` — the most complete WAL in
  the tree, absent from every CMake target, and `syncToDisk()` **rewrites the
  whole journal** with `std::ios::trunc` on every call (`:595`). A crash during
  that rewrite destroys previously committed entries. It is not a WAL.
- `src/closure/EditTransaction.cpp` — temp + `.bak` + rename, in-memory only,
  no journal; and neither it nor its sole caller `BuildTestGate.cpp` is in any
  CMake target, so it is in no binary.
- `src/agentic/multi_file_transaction.cpp`, `agentic_transaction.cpp`,
  `DiskRecoveryAgent.cpp`, `DeterministicReplayEngine.cpp`,
  `autonomous_recovery_orchestrator.cpp` — all one-line stubs.
- `src/core/patch_rollback_ledger.cpp:555-571` — persists `chkBefore/chkAfter`
  but **not** `originalBytes` or `targetAddress`, so its on-disk journal cannot
  undo anything after a restart.
- `src/win32app/Win32IDE_Commands.cpp:96-116` — the IDE undo stack is
  full-buffer line copies in a `std::vector`, capped at depth 50, never
  persisted. A crash loses it.

Write paths that truncated in place with no backup, no flush and no record:

- `src/win32app/Win32IDE_EditorEngine.cpp:683` — `std::ofstream(binary|trunc)`
  then `flush()`. This is the IDE's only file-write function.
- `src/agentic/AgentToolRegistry.cpp:455-468` — `CreateFileW(CREATE_ALWAYS)` +
  `WriteFile`, share mode 0, no `FlushFileBuffers`, no rename.

---

## 2. What was built

    src/agentic/CheckpointRollbackAuthority.h    new, ~200 lines
    src/agentic/CheckpointRollbackAuthority.cpp  new, ~1150 lines

On-disk contract, under `<workspace>\.rawrxd\ckpt\`:

    blobs\<sha256>          content-addressed before-state, plan, context, diagnostics
    journal\<txid>.jrnl     append-only, one CRC32 per record
    recovery\<txid>.txt     per-transaction recovery receipt
    recovery\<ts>_pass.txt  per-startup-pass receipt

Durability rules, each enforced at the call site rather than documented:

- Blobs: `FILE_FLAG_WRITE_THROUGH` + `FlushFileBuffers`, published with
  `MoveFileExW(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`.
- A blob is durable **before** the journal record that references it is
  appended, so a recoverable record never points at a missing blob.
- Every record is flushed before the call returns. A torn trailing line fails
  CRC and is discarded — the ordinary power-loss artifact.
- Every file publish is temp-file + flush + atomic rename, so a crash mid-write
  cannot leave a truncated target.

Journal record types: `V1`, `BEGIN`, `WORKTREE`, `PLAN`, `CONTEXT`, `DIAG`,
`FILE_BEFORE`, `FILE_AFTER`, `CMD`, `TOOL`, `COMMIT`, `ROLLBACK`.

### Wiring — every product write path, not a test path

| Call site | Change |
|---|---|
| `src/win32app/Win32IDE_EditorEngine.cpp:695` | `EditorEngine_SaveFile` now publishes through `ckpt::Transaction::WriteFile` instead of `ofstream(trunc)` |
| `src/agentic/AgentToolRegistry.cpp:515` | sandboxed `write_file` publishes through the authority and journals `TOOL`; `execute_command` journals `CMD` + `TOOL` (`:586`, `:590`) |
| `src/agentic/RawrXDAgenticE2E.cpp:373`, `:435` | `writeTool` and `replaceTool` publish through the authority; the local `commitTempFile` was removed so no path bypasses the journal |
| `src/win32app/main_win32.cpp:2264` | `WinMain` runs `RecoverWorkspace` **before** the AutoClosure early return, so a headless/autoclosure run — the run most likely to die mid-edit — is covered too. Root is `RAWRXD_CKPT_ROOT`, else the process working directory |
| `CMakeLists.txt:4992`, `:17094` | authority compiled into `InferenceEngine` (which the IDE links); `ckpt_rollback_crash_cert` target added |

---

## 3. Measured evidence

### 3.1 Builds

    InferenceEngine + RawrXD-Win32IDE, Release, build_ide_audit
      build exit            = 0
      RawrXD-Win32IDE.exe   = 20891648 bytes
      exe sha256            = B5345E479A3E84ED8B85D1D3AD38E993492337E0FCAE34AF029D9F07F1FD65A6
    ckpt_rollback_crash_cert.exe
      sha256                = 37FC2810352AE88095E5280E463C1852EE1060B5C1B4AE6D64C9B35D30DB482E
    log                    = build_ide_audit/ckpt_ide_build3.log (exit file ckpt_ide_build3.exit)

### 3.2 The crash proof — `ckpt_rollback_crash_cert`

Four files are written through the **production** authority
(`ToolRegistry::Execute("write_file", ...)`, the same call the IDE HTTP routes
make). The child process is killed by `TerminateProcess` at write 2, mid-publish,
with no destructors, no `atexit` handlers and no stream flushes.

    CRASH_EXIT_CODE_ARMED=0xC0FFEE01
    CRASH_EXIT_CODE_OBSERVED=0xC0FFEE01
    CRASH_KILLED_BY_FAULT_INJECTION=1
    CRASH_LEFT_DAMAGED_FILES=2          <- alpha.cpp left half-written, delta_new.txt created
    IDENTITY_CHANGED_BY_CRASH=1
    RECOVERY_CHILD_RESTORED_ALL=1       <- a SEPARATE process
    FILES_DIFFERING_AFTER_RECOVERY=0
    BYTE_MISMATCHES_AFTER_RECOVERY=0
    TRANSACTION_CREATED_FILE_REMOVED=1
    IDENTITY_RESTORED_TO_BASELINE=1
    SECOND_RECOVERY_IS_NOOP=1
    RECOVERY_IDEMPOTENT=1
    VERDICT=PASS

Child counters, measured in the crash child before the kill:

    CRASH_CHILD_COUNTERS journalRecords=10 journalFlushes=10 atomicPublishes=4
                      fileWrites=1 blobWrites=3

Child counters, measured in the recovery child:

    RECOVER_CHILD_COUNTERS journalRecords=1 journalFlushes=1 atomicPublishes=3
                      fileWrites=1 fileDeletes=1

### 3.2b Journal census from the real interrupted transaction

Record types actually present on disk in the journal the killed child left
behind (`journal_tx13435363207_24844_11fe001b.jrnl`), which is the direct
evidence for ladder items 1-7:

    V1 1   BEGIN 1   WORKTREE 1   PLAN 1   CONTEXT 1   DIAG 1   CMD 1
    TOOL 1   FILE_BEFORE 2   FILE_AFTER 1   ROLLBACK 1

`FILE_BEFORE 2 / FILE_AFTER 1` is the correct shape: the child journalled the
before-state of `delta_new.txt` and of `alpha.cpp`, completed `delta_new.txt`,
then died mid-publish of `alpha.cpp` — so the second `FILE_AFTER` was never
written, and that is precisely the record recovery keys on.

### 3.3 The real IDE binary, not the harness

Workspace seeded, interrupted transaction produced by the same production write
path, then `RawrXD-Win32IDE.exe` launched with `RAWRXD_CKPT_ROOT` set:

    BEFORE CRASH                      AFTER IDE STARTUP RECOVERY
    alpha.cpp  = 3364B8F8...EE2        alpha.cpp  = 3364B8F8...EE2   (restored)
    beta.h     = 67E59300...00A        beta.h     = 67E59300...00A   (unchanged)
    gamma.txt  = 2955B0E9...C4F8        gamma.txt  = 2955B0E9...C4F8   (unchanged)
    delta_new.txt (absent)             delta_new.txt  REMOVED

    post-crash alpha.cpp  = 3E6DE92A...694   (torn: half the new bytes, no flush)

Receipts written by the IDE itself:

    journals_scanned=1  closed_transactions=0  incomplete_transactions=1
    files_restored=1  files_deleted=1  files_verified=1  files_failed=0
    torn_records_discarded=0  missing_blobs=0
    verdict=ALL_TRANSACTIONS_CLOSED

Second IDE start: no new receipt written, files unchanged, and a direct probe of
the journal reports `RECOVER_CLOSED_TRANSACTIONS=1`,
`RECOVER_INCOMPLETE_TRANSACTIONS=0`, `RECOVER_FILES_FAILED=0`.

IDE process facts: `MainWindowTitle = RawrXD Win32 IDE`, `Responding = True`,
`IDE_TERMINATION = FORCED_BY_CERT`. **No clean-shutdown claim is made**;
`IDECore_Shutdown` still has no caller.

### 3.4 Re-verified against current sources

After a concurrent participant added a transactional-profile gate on top of this
authority (`RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001`, `IsUnderCanonicalRoot`),
the proof was re-run from the current sources of this subsystem:

    cl /std:c++20 /EHsc /O2 tools/ckpt_rollback_crash_cert.cpp
       src/agentic/CheckpointRollbackAuthority.cpp
       src/agentic/AgentToolRegistry.cpp src/agentic/CommandExecutor.cpp
    -> ckpt_standalone.exe, 228352 bytes
    VERDICT=PASS   (identical field set to 3.2)

---

## 4. Defects found and fixed by this work

1. **Working-tree identity included mtime**, so a byte-exact restore could never
   reproduce the identity and "did the tree come back?" was unanswerable. Caught
   by the first cert run (`IDENTITY_RESTORED_TO_BASELINE=0`). Identity now
   hashes `(relpath, content-sha256)`, with a documented 8 MiB cap above which
   `(relpath, size)` is hashed and the count is mixed into the identity so the
   substitution is visible rather than silent.
2. **A rolled-back transaction counted as still open**, so every subsequent
   startup replayed the same rollback forever. Caught by the same run
   (`SECOND_RECOVERY_IS_NOOP=0`). `ROLLBACK` now closes a journal exactly as
   `COMMIT` does.
3. **Pre-existing link defect at HEAD**: `src/win32app/Win32IDE_RuntimeCert.cpp:55-57`
   declared `FileOps_ReadFile/WriteFile/Exists` at global scope while
   `src/win32app/Win32IDE_FileOps.cpp:8` defines them inside `namespace RawrXD::IDE`.
   The IDE target failed to link with `LNK2019` on all three once the project was
   regenerated. Declarations moved into the defining namespace. The stale
   `build_ide_audit` project file had masked this.
4. **Compile error in concurrently added code inside a file this work owns**:
   `src/agentic/AgentToolRegistry.cpp:119` called `CompareStringOrdinal` (an
   `LPCWCH` API) on narrow `std::string::data()` — C2664. Replaced with
   `_strnicmp`, the length-limited case-folded ordinal compare it intended.

---

## 5. NON_CLAIMS

    POWER_LOSS_SEMANTICS_PROVEN = 0
        The crash is a real `TerminateProcess` — no destructors, no atexit, no
        buffered flush — but it is not a power cut. Drive-level tearing is not
        demonstrated.

    IDE_CLEAN_SHUTDOWN = NOT_EXERCISED
        The IDE was force-terminated after its window came up. Startup recovery
        is proven; shutdown is not.

    DURABILITY_UNDER_FLASH_REORDERING = NOT_TESTED
        MoveFileEx with MOVEFILE_WRITE_THROUGH plus FlushFileBuffers is the
        mechanism; its behaviour across a controller-level cache flush has not
        been measured.

    IDE_TRANSACTION_LIFECYCLE_BOUND_TO_AGENT_TURN = PARTIAL
        A transaction is opened programmatically
        (`ckpt::Transaction::Begin`). The agent-loop call site that opens one per
        model turn is not yet bound, so an unattended write outside an explicit
        transaction is journalled per-write but not grouped per turn.

    ORPHANED_RECOVERY_SUBSYSTEMS = 11
        transaction_journal, hotpatch_recovery_journal, ExecutionJournal,
        checkpoint_manager, checkpoint_replay, DiskRecoveryAgent (core),
        mnemosyne_store, EditTransaction, BuildTestGate, rawrxd_scale_value_pack
        (holds the only durable workspace CheckpointStore), RollbackEngine.
        Still not bound; still compiled-but-uncalled or absent-from-CMake. This
        receipt does not claim they are resolved.

    SAFE_REFACTOR_ENGINE_SNAPSHOTS = STILL_IN_MEMORY
        `src/core/safe_refactor_engine.cpp:131-167` takes snapshots in memory
        and restores with a truncating write; it remains the only rollback
        reachable from `agentic_task_graph.cpp`. It was not redirected here.

---

## 6. Ledger

Coordinator disposition, 2026-10-01:

    RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001 = PASS   (process-crash scope)

    MULTIFILE_CRASH_ROLLBACK        = PROVEN
    REAL_TOOLREGISTRY_WRITE_PATH     = PROVEN
    SEPARATE_PROCESS_RECOVERY        = PROVEN
    REAL_WIN32IDE_RECOVERY           = PROVEN

    FILES_DIFFERING_AFTER_RECOVERY   = 0
    BYTE_MISMATCHES                  = 0
    CREATED_FILE_REMOVAL             = PROVEN
    BASELINE_CONTENT_IDENTITY        = RESTORED
    SECOND_RECOVERY_PASS             = NO_OP

    PROCESS_CRASH_DURABILITY         = PROVEN
    POWER_LOSS_DURABILITY            = NOT_PROVEN
    PER_TURN_TRANSACTION_BINDING     = PARTIAL
    CLEAN_SHUTDOWN_PATH              = UNMEASURED
    ORPHAN_RECOVERY_SUBSYSTEMS       = 11

Recorded separately, so the checkpoint authority takes no credit for a distinct
build-system defect:

    PREEXISTING_FILEOPS_LINK_DEFECT = CLOSED
    CAUSE                           = declaration/definition namespace mismatch
    STALE_PROJECT_MASKING           = OBSERVED

Two properties are what separate this from the pre-existing recovery
implementations, and both are load-bearing rather than incidental: the blob is
made durable *before* any journal record can reference it, and journal
publication never truncates or reconstructs the authoritative journal during
synchronization.

Re-verified on the final tree after the concurrent GPU edit settled —
`ckpt_final_tree_run.log`, `VERDICT=PASS`, `RawrXD-Win32IDE.exe`
sha256 `8B623935FFE8D4F88BCBFD9C6E311BEC4424AFE88916036DABCA151391A62778`.
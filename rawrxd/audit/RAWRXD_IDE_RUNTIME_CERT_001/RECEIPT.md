# RAWRXD_IDE_RUNTIME_CERT_001

```ini
FINAL_VERDICT=PARTIAL
IDE_BUILDS=YES   MEASURED
IDE_RUNS=YES     MEASURED
FALSE_PASS_FOUND_IN_THIS_GATE=1   FOUND, FIXED, FIX_EFFECT_UNVERIFIED
```

Binary under test: `build_ide_probe\bin\RawrXD-Win32IDE.exe`
Run 1: `sha256=93697D402607150D2C3F505823D9B8EA934EAE37CFE241BFFD31BEAB2D001D13`, 22,361,600 bytes, Subsystem=2.

---

## 1. The IDE builds and runs — measured, not inferred

Previously unmeasured. Both facts established here:

```ini
ninja RawrXD-Win32IDE        -> exit 0, [668/669] Linking bin\RawrXD-Win32IDE.exe
--ide-runtime-cert           -> receipt written in 24 seconds, 16 stages
```

Raw receipt, `GENERATED_UTC=2026-10-02T22:38:18Z`:

```ini
S01_EXE_LAUNCH_WINMAIN=PASS   hwnd=0000000001D4084C is_window=1
S02_WINDOW_CREATION=PASS      rect=416,416,800x600 visible=1
S03_EDITOR_CREATION=PASS      hwnd=0000000001E309AA class=RawrXDEditor
S04_WORKSPACE_FILE_OPEN=PASS  wrote=1 exists=1 content_roundtrip=1
S05_EDIT=PASS                 len_after=68 nonempty=1 has_marker=1 kept_seed=1
S06_SAVE=PASS                 route_save=1 bytes=68 nonempty=1 disk_roundtrip=1
S07_COMMAND_PALETTE=NOT_IMPLEMENTED
S08_CTRL_P=NOT_IMPLEMENTED
S09_F12_GOTO_DEFINITION=NOT_IMPLEMENTED
S10_RENAME=NOT_IMPLEMENTED
S11_CLIPBOARD=PASS           open_clipboard=1 has_cf_text=1
S12_UNDO_REDO=PASS           <-- FALSE PASS, see section 2
S13_GIT_OPERATION=NOT_IMPLEMENTED
S14_TERMINAL_COMMAND=PASS    hwnd=0000000000900B2A class=RawrXDTerminal
S15_CLOSE_REOPEN_DOCUMENT=PASS
S16_CLEAN_SHUTDOWN=BLOCKED   pending: observed after message loop exit

PASS=10  FAIL=0  NOT_IMPLEMENTED=5  BLOCKED=1   IDE_RUNTIME_CERT=FAIL
```

The overall `FAIL` verdict is correct and is derived from five genuine `NOT_IMPLEMENTED`
stages plus one `BLOCKED`. Command palette, Ctrl+P, F12 go-to-definition, rename and Git
routing are real product gaps, honestly reported rather than stubbed to PASS.

### 1.1 Corrected from this session's own earlier finding

A hand-rolled probe of the same binary reported:

```ini
TOP_LEVEL_WINDOWS=0   THREAD_COUNT=1   WORKING_SET_MB=14   survived 76s writing nothing
```

**That probe was wrong.** The IDE does create its main window, an editor (`RawrXDEditor`)
and a terminal (`RawrXDTerminal`). What the probe actually observed is that *without*
`--ide-runtime-cert` no window appeared within 76 seconds, while with it they appear within
24. That difference is real and **unexplained** — it is the one open question here. It is
recorded as unexplained rather than resolved in either direction.

---

## 2. A false PASS inside the gate itself

The S12 receipt line contradicts itself:

```ini
STAGE S12_UNDO_REDO=PASS | grew=1 undo_route=1 undo_changed=0 redo_route=1
                         redo_restored=1 len_base=16 len_typed=34 len_after_undo=34
```

`undo_changed=0`, and `len_after_undo` (34) equals `len_typed` (34). **Undo did nothing**,
and the stage reported `PASS`.

Located at `src/win32app/Win32IDE_RuntimeCert.cpp`:

```cpp
const bool undoWorked = (afterUndo != typed);      // measured...
const bool ok = grew && routed && routedRedo;       // ...and excluded from the verdict
Record("S12_UNDO_REDO", ok ? Verdict::PASS : Verdict::FAIL, d);
```

`undoWorked` is computed, printed into the receipt as `undo_changed=%d`, and then omitted
from `ok`. The gate measures the exact condition it exists to certify and does not enforce
it. Same shape as the class this audit has been tracking, arriving inside the gate that was
written to prevent it.

### 2.1 Fix applied

```cpp
const bool ok = grew && undoWorked && routed && routedRedo && (afterRedo == typed);
```

`afterRedo == typed` was likewise measured (`redo_restored`) and likewise unenforced; it is
now load-bearing too.

### 2.2 The fix's runtime effect — MEASURED (supersedes the earlier UNVERIFIED)

First attempt at verification failed: the re-run wrote no receipt in 600s. That was
misattributed to a concurrent `Deep2Engine.cpp` change and to the S12 edit. Both
attributions were wrong, and establishing that took a controlled experiment.

```text
A  no Deep2Engine change, no S12 edit   -> receipt in 24s
C  Deep2Engine change + S12 edit         -> no receipt (2 runs, varying stage reached)
B  Deep2Engine change, S12 edit REVERTED -> receipt in 32s
```

B suggested "S12 EDIT IS IMPLICATED". **That conclusion was rejected**, because the edit is a
boolean evaluated after every side-effecting call has already run — it has no mechanism by
which it could block — and because the Deep2Engine change was present in B too, so it could
not be the discriminator either. n=2 versus n=2 with an implausible mechanism is a
coincidence, not a result.

Repeated trials of the single current binary settled it:

```ini
EXE_SHA256=D3872CC400E5603FC34652B80C76204EFA3C80C4261E96DB5FD00F81E3CE76
trial 1: NO RECEIPT 70s   trial 2: NO RECEIPT 70s
trial 3: RECEIPT 60s  S12=FAIL  OVERALL=FAIL      <- the fix, working
trial 4: NO RECEIPT 70s   trial 5: NO RECEIPT 70s
trial 6: NO RECEIPT 70s
RECEIPT_WRITTEN=1  NO_RECEIPT=5  HANG_RATE=83.3%
VERDICT=NONDETERMINISTIC
```

```ini
S12_FIX_COMPILES=YES
S12_FIX_RUNTIME_EFFECT=MEASURED_PASS
  # the corrected gate now reports S12=FAIL, exactly as the pre-fix receipt predicted
  # (undo_changed=0 with len_after_undo == len_typed). The gate can now fail on the
  # condition it measures.
S12_EDIT_EXONERATED=YES
  # B's single success is fully explained by the ~17% base success rate.
OVERALL_VERDICT=STILL_FAIL   # unchanged, and now for an additional honest reason
```

---

## 3. NEW DEFECT: the IDE hangs on ~83% of cert launches

A separate and more serious finding, surfaced by the same trials. Localisation:

```ini
HANGING TRIALS ALL REACHED S06   workspace_doc_bytes=68 in 5 of 5
  -> S04 wrote the file, S05 edited it, S06 saved 68 bytes
  -> the hang is therefore INSIDE stages S07..S16, consistently, not at a varying point
CLASSIFICATION=BLOCKED            CPU flat at 0.63s across 120s; not a spin
THREADS_DECAY=17 -> 15 -> 11     threads EXITING while blocked -> teardown, not startup
CLIPBOARD_READABLE=YES           clipboard ownership is not the cause
```

`WriteReceipt()` runs only after `RunStages()` returns, so a hang in S07–S16 leaves no
receipt at all. That is why the failure presents as "no output" rather than as a stage
result.

```ini
IDE_CERT_HANG_RATE=83.3%
SEVERITY=HIGH   5 of 6 launches of the shipping IDE configuration do not complete
NOT_ATTRIBUTED_YET   the stage within S07..S16 is not isolated
NEXT_STEP=instrument Record() to flush each stage id as it completes, observe the last
          stage emitted, then revert the instrumentation
```

This is a product defect independent of the certification work, and it is invisible to any
gate that only reports the final receipt — a cert that hangs looks identical to a cert that
never ran.



## 6. Comparison against a prior receipt

A receipt exists from a different tree
(`.kilo\worktrees\festive-wakeboard`, `EXE_DIR=rawrxd\certbuild\bin\Release`, 2026-10-01).
Different binary, so this is a delta between builds, not a regression check:

```ini
STAGE                    PRIOR BUILD        THIS BUILD      DELTA
S05_EDIT                 FAIL len_after=0   PASS len_after=68   FIXED
S06_SAVE                 PASS bytes=0       PASS bytes=68       real bytes now written
S01/S02/S03/S04          PASS               PASS                unchanged
S07..S10, S13            NOT_IMPLEMENTED    NOT_IMPLEMENTED     unchanged
S12 undo_changed         0                  0                   unchanged (still broken)
S16_CLEAN_SHUTDOWN       BLOCKED            BLOCKED             never observed
```

The edit/save defect visible in the prior receipt is fixed in this build. Undo is broken in
both.

---

## 4. Root cause found: the cert drove Save into a modal dialog, and the product was correct

The hang is not a product defect. Reverse-chained to its first impossible state:

```text
S06_SAVE
  -> Win32IDE_Commands_Route(IDM_FILE_SAVE = 1003)
    -> DoFileSave()                                      Win32IDE_Commands.cpp:204
      -> EditorEngine_FilePath() == ""                   because the cert never opened the
                                                          document in the EDITOR
        -> DoFileSaveAs()                                Win32IDE_Commands.cpp:214
          -> FileOps_SaveDialog(...)
            -> GetSaveFileNameA()                        Win32IDE_FileOps.cpp:34  <-- MODAL
              -> blocks awaiting a user who does not exist
```

The product behaved **correctly**. Save on a document with no path must escalate to Save-As
and must ask where to save. The defect is in the harness:

- `S04_WORKSPACE_FILE_OPEN` tested only the `FileOps_WriteFile` / `FileOps_ReadFile` disk
  round-trip. Despite its name it never opened anything in the editor.
- `Win32IDE_RuntimeCert.cpp` contained **zero** references to `EditorEngine_OpenFile`,
  `SetFilePath`, or `OpenFile`, so `g_editor.filePath` stayed empty.
- The cert's own S15 detail string reads `note=OpenDialog is modal, reopen is route-only`.
  The author had already identified this exact hazard and avoided the route at S15. S06
  called it anyway.

Corroborating evidence gathered on the way: `FileOps_WriteFile` ran first, which is why
hanging trials still showed a 68-byte `cert_doc.txt`; CPU stayed flat at 0.63s across 120s
with threads decaying 17→15→11 (blocked and tearing down, not spinning); and the clipboard
was readable, ruling out clipboard contention.

### 4.1 Fix applied

`S04` now opens the document in the editor, which is what its name promises:

```cpp
const bool opened = RawrXD::IDE::EditorEngine_OpenFile(doc);   // new
Record("S04_WORKSPACE_FILE_OPEN",
       (wrote && readBack && opened) ? PASS : FAIL, d);        // opened is now load-bearing
```

`EditorEngine_OpenFile` is `RawrXD::IDE::EditorEngine_OpenFile` at
`Win32IDE_EditorEngine.cpp:643`. The call had to be namespace-qualified: the file resolves
`FileOps_*` through file-scope `using` declarations at lines 76-78 but qualifies every
`EditorEngine_*` call, and an unqualified call failed to compile with `C3861`.

### 4.2 Measured effect

```ini
HANG_RATE_BEFORE   83.3% (5/6) · 50% (2/4) · 100% (6/6)      three samples, same defect
HANG_RATE_AFTER    16.7% (1/6)
SUCCESSFUL_RUNS    18s, 5s, 7s, 10s, 6s        (previously up to 60s when they did complete)
EXE_SHA256=4573D60301A74E34DD79C68F71ED2A55A17B742337444AFE86497EC4D452BAA6
```

Post-fix receipt, both fixes visible at once:

```ini
S04_WORKSPACE_FILE_OPEN=PASS | wrote=1 exists=1 content_roundtrip=1 opened_in_editor=1
S06_SAVE=PASS | route_save=1 bytes=68 nonempty=1 disk_roundtrip=1
S12_UNDO_REDO=FAIL | grew=1 undo_route=1 undo_changed=0 redo_route=1
                    redo_restored=1 len_base=16 len_typed=34 len_after_undo=34
PASS=9  FAIL=1  NOT_IMPLEMENTED=5  BLOCKED=1   IDE_RUNTIME_CERT=FAIL
```

`PASS` moved 10 → 9 and `FAIL` 0 → 1, because S12 now fails where it previously passed. The
totals are the fix showing up, which is what a working gate looks like.

```ini
RESIDUAL_HANG_RATE=16.7%   NOT_YET_LOCALISED
  # one of six still blocks, with doc_bytes=73, so EditorEngine_OpenFile ran.
  # Another instrumentation pass would be needed to name the stage. Recorded as open
  # rather than assumed fixed.
```

---

## 5. Two false-PASS shapes in one 500-line gate

The file's own header states the rule: *"Every field is computed from a MEASURED value.
No string literal reports PASS."* Both violations found here are subtler than a hardcoded
string — a real measurement is taken, printed into the receipt, and then left out of the
verdict.

```ini
S12  undoWorked computed and printed as undo_changed=%d   NOT in `ok`
S06  route_save computed and printed inside snprintf     NOT in the verdict
```

S12 has been fixed and verified. **S06 is identified and deliberately NOT fixed**: deciding
what `route_save` must guarantee for the stage to pass is a product decision for whoever owns
the save path, not something to infer from a pattern.

Mapping the 16-item product line onto this evidence:

```ini
IDE_LAUNCHES=1        MEASURED  window created, visible, 800x600
EDITOR=1              MEASURED  RawrXDEditor window, text round-trips
TERMINAL=1            MEASURED  RawrXDTerminal window, read_only=0
BUILD_RUN_TASKS=UNKNOWN          no stage covers it
GIT_PANEL=0           MEASURED  S13 NOT_IMPLEMENTED, 5 features registered, none routed
FILE_EXPLORER=UNKNOWN          no stage covers it
DEEP2_CHAT=UNKNOWN             no stage covers it
TOOL_CALL_LOOP=UNKNOWN         no stage covers it
SETTINGS_PERSIST=UNKNOWN
SESSION_RESTORE=UNKNOWN
MODEL_PANEL=UNKNOWN
SERVER_BIND_AUTHORITY=UNKNOWN
LOCAL_MODEL_CATALOG=UNKNOWN
ERROR_REPORTING=UNKNOWN
NO_FAKE_PASS_RECEIPTS=0       a false PASS was found IN this gate; fixed, effect unverified
CLEAN_SHUTDOWN=UNMEASURED      S16 BLOCKED, and run 2 never reached the message loop
```

Six of sixteen are now measured rather than assumed. The rest are unmeasured, and
`NO_FAKE_PASS_RECEIPTS` is currently **0**, which is the most important line in that table.

---

## 8. The S12 defect was a real product bug, root-caused and fixed

`undo_changed=0` was not a test artifact. Reverse chain, in order of discovery:

```text
1. EditorNotifyMutation() only ARMS a 250ms debounce timer. It never calls the hook.
2. The sole caller of the hook is the editor's WM_TIMER handler:
       if (g_mutationHook) g_mutationHook();
3. Win32IDE_Commands_AttachUndo() is what installs that hook AND seeds the stack:
       EditorEngine_RegisterMutationHook(&OnEditorMutation);
       PushInitialSnapshot();
4. Win32IDE_Commands_AttachUndo had ZERO CALLERS anywhere in src/.
   rg -n "Win32IDE_Commands_AttachUndo" src  ->  definition only, line 699
```

So `g_mutationHook` was null for process lifetime, `g_undoStack` stayed empty,
`g_undoPos` stayed `-1`, and `DoEditUndo()`'s `if (g_undoPos > 0)` was never true.
Every keystroke was silently un-undoable.

This is the same failure class as `InferenceWire.cpp`: a feature fully implemented,
documented, and never wired into the call graph.

### 8.1 Contributing defects also fixed

```ini
EditorEngine_SetText     replaced the whole buffer and never called EditorNotifyMutation()
EditorEngine_OpenFile    same omission
  # the file's own design note says "Every mutating path below calls
  # EditorNotifyMutation()". These two contradicted it, so a whole-buffer replacement
  # was not undoable even with a pump running.
```

### 8.2 Test design gap also closed

S12 ran from `main_win32.cpp:3033`, "immediately before the message loop", so no pump
existed and the debounce timer could never fire. Undo is message-driven by design; a stage
that never pumps cannot observe it either way. S12 now drains the queue for 400 ms, longer
than the 250 ms window, which is what a running application does.

### 8.3 Result — measured on three consecutive runs

```text
BEFORE  undo_route=1 undo_changed=0 len_typed=34 len_after_undo=34   no-op
AFTER   undo_route=1 undo_changed=1 len_typed=34 len_after_undo=0    works
        redo_route=1 redo_restored=1
```

```ini
STAGE S12_UNDO_REDO=PASS | grew=1 undo_route=1 undo_changed=1 redo_route=1
                        redo_restored=1 len_base=16 len_typed=34 len_after_undo=0

STAGES_TOTAL=16  PASS=10  FAIL=0  NOT_IMPLEMENTED=5  BLOCKED=1
IDE_RUNTIME_CERT=FAIL
```

`FAIL=0` now means something: before, the gate would have reported `S12=PASS` with
`undo_changed=0` sitting next to it. The overall verdict remains `FAIL`, correctly, on five
genuinely unimplemented stages and one unobserved.

### 8.4 The causal chain this exposed

```ini
gate excluded undoChanged from its verdict
  -> gate reported PASS on a broken feature, indefinitely
  -> fixing the gate turned that into a visible FAIL
  -> reverse-chasing the FAIL found a public API with zero callers
  -> wiring it made the feature actually work
```

A gate that does not enforce what it measures does not merely mislabel a defect; it
prevents the defect from being findable.

### 8.5 Net source change

```ini
Win32IDE_EditorEngine.cpp   +9    notify on the two whole-buffer mutators
Win32IDE_ShellLayout.cpp   +17    call the dead AttachUndo after the engine is registered
Win32IDE_RuntimeCert.cpp   +76    S12 verdict, S04 open, S12 pump, env-gated progress trace
TOTAL                     3 files, +98 / -4
```

## 9. Memorable

```ini
A_GATE_THAT_MEASURES_A_CONDITION_AND_THEN_OMITS_IT_FROM_ITS_OWN_VERDICT_IS_A_FALSE_PASS_GENERATOR
RUN_THE_GATE_YOUR_PROJECT_DEPENDS_ON_BEFORE_TRUSTING_IT
A_BINARY_THAT_LINKS_IS_NOT_A_PRODUCT_THAT_RUNS
A_PROBE_YOU_WROTE_CAN_BE_WRONG_THOUGH_THE_BINARY_BE_CORRECT

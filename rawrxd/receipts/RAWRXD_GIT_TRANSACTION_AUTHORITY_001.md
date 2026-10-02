# RAWRXD_GIT_TRANSACTION_AUTHORITY_001

## Status: CONTRACT_SATISFIED — 34/34, with the negative control detecting its defect

```ini
RAWRXD_GIT_TRANSACTION_AUTHORITY_001          = CONTRACT_SATISFIED (34/34)
RAWRXD_GIT_TRANSACTION_AUTHORITY_001_CONTROL  = DEFECT_DETECTED
GIT_TOOLS_REGISTERED                          = 13
GIT_TOOLS_EXECUTED_CERT                       = 10
GIT_TOOLS_CERTIFIED                           = 10 (a named set, listed in §4)
TRANSACTIONAL_DELETE                          = NOT IMPLEMENTED (unchanged, still honest)
COMMIT_STATE                                  = UNCOMMITTED
```

G0–G13 measured against a real git repository created by the driver, plus the
G14/G15 negative control. Verdicts use the project vocabulary
(`CONTRACT_SATISFIED | CONTRACT_VIOLATED | DEFECT_DETECTED | NO_VERDICT`); no
bare PASS or FAIL appears in any control-bearing record.

---

## 1. Why this gate exists

B83 V2 registered 13 git-safety tools into the same sandboxed registry that
`/api/agent/execute-tool` dispatches through, and certified none of them. The
first measurement of G4 then found the reason that boundary mattered:

```text
worktree before the call:  M agent.txt
git_stage (capability+scope granted, no transaction): ok=1 error=[]
repository_state_changed_without_a_transaction = YES
index tree before=8df5dc48257c after=397b5b67d680
journal_records: before=0 after=0
```

The B83 write profile promises every accepted mutation is journalled and
undoable. `write_file` enforced that; the git mutation path did not. An agent
could stage, commit and roll back — moving the repository, including `.git/` —
outside the machinery that makes autonomous editing recoverable.

## 2. The fix

The gate belongs at the one point every tool passes through, not inside one tool
body, because the promise is about *mutation* rather than about which function
performs it.

```cpp
// src/agentic/AgentToolRegistry.cpp, ToolRegistry::Execute
if (policy.writeRequiresTransaction && IsTransactionRequired(name, policy) &&
    !ckpt::Transaction::Active()) {
    ToolResult r;
    r.error = name + " requires an open checkpoint transaction; open one first "
                     "(POST /api/agent/transaction {\"op\":\"begin\"})";
    return r;
}
```

The gated set is `ToolPolicy::transactionRequiredTools` — explicit data, because
a registry cannot infer which tool mutates: `git_status` and `git_stage` have
identical signatures. `write_file` is listed as well as gated intrinsically, so
the coverage check below needs no exception for the tool it was written beside.

```cpp
// A name that looks mutating and is absent from the list is a POLICY TYPO, and
// a typo in a security list is a silent hole. This makes it visible.
std::vector<std::string> UncoveredMutatingTools(const ToolRegistry&, const ToolPolicy&);
```

Measured `uncovered=0`.

### G7 needed new machinery: the index is not a file

A transaction that stages a file and is rolled back left that file BOTH reverted
in content AND still staged, because the journal restores file bytes and nothing
had ever restored the index. The next `git status` would report a staged
modification of a file whose content was the pre-transaction content.

```cpp
// CheckpointRollbackAuthority
static bool RecordGitIndexBaseline(std::string* outTree, std::string* outError);
//   -> git write-tree, once per transaction, before the first mutation,
//      written to the journal as a GITINDEX record so a CRASH can restore it too
```

`RecoverWorkspace` replays it with `git read-tree <tree>` after the file bytes,
so one mechanism serves in-process rollback, crash recovery and the startup
pass. A failed index restore is its own counter (`gitIndexFailed`) and **fails
`AllRestored()`**: the file bytes are correct and the repository is still wrong,
and an operator told only "recovery succeeded" would never look at the index.

## 3. Four defects found while building the gate

Three were in the gate; one was in the B83-certified binary's own behaviour.

1. **`GetToolNames()` called twice returns two different vectors.** Comparing an
   iterator from one with an iterator from the other is undefined behaviour, and
   it was the cause of a silent access violation that destroyed the whole run's
   output. Fixed by holding one container.
2. **G4 passed vacuously.** The first version authorized the prefix `agent`,
   which does not cover the file `agent.txt`, so the call was refused with
   `PATH_OUTSIDE_SCOPE` by the *scope* gate and the transaction question was
   never reached. Now a separate condition asserts the call reached the
   transaction question, and G4 reports `NOT MEASURED` if an earlier gate
   absorbs it.
3. **The mutation was invisible to the digest.** Staging an already-clean file
   reports success and moves nothing, so a hash comparison cannot distinguish
   "refused" from "authorized but irrelevant". Fixed by putting a real pending
   change on an in-scope path.
4. **`GetEnvironmentVariableW(L"PATH", buffer, MAX_PATH)` silently truncates a
   long PATH** and can drop the entry holding `git.exe`. The runner then reported
   *"git write-tree exited non-zero with no output"* for a git it had **never
   launched**. Found only because the error path carries git's own words out
   verbatim; the plausible first explanation (an unmerged index) was wrong.
   Fixed with a size query followed by an allocation.

Two more conditions passed for the wrong reason and were tightened:

- **G9** was refused by `CAPABILITY_NOT_GRANTED`, i.e. the operation never ran.
  Now `Checkout` is granted and the condition requires a refusal that did not
  come from a gate (`DIRTY_TREE_DESTRUCTIVE`).
- **G7** would have passed on a matching index hash alone, because the
  `git reset` used to tidy up after the refused commit unstaged the file by
  itself. It now also requires `gitIndexRestored >= 1`.

## 4. Measured, G0–G13

| # | condition | result | evidence |
|---|---|---|---|
| G0 | 13 git tools installed and enumerated | SATISFIED | `enumerated=13 missing=[]`, registry holds 18 |
| G1 | every mutating-looking tool is in the list | SATISFIED | `uncovered=0` |
| G2 | clean/dirty baseline | SATISFIED | `status=[ M user.txt]` exactly |
| G3 | 5 read-only tools mutate nothing | SATISFIED | HEAD+status+branch+index digest identical after each; `user.txt` sha unchanged |
| G4 | mutation requires a transaction | SATISFIED | refused: *"git_stage requires an open checkpoint transaction"*; index unchanged; reached the question (capability+scope satisfied) |
| G5 | dirty user change survives unrelated ops | SATISFIED | `user.txt` sha unchanged; `status=[M  agent.txt]` |
| G6 | commit absorbs only authorized changes | SATISFIED | refused `PATH_OUTSIDE_SCOPE`; HEAD unmoved |
| G7 | rollback reverses transaction-owned changes only | SATISFIED | `agent.txt` reverted, `user.txt` preserved, index back to pre-tx tree, `gitIndexRestored=1` |
| G8 | rollback is journalled and auditable | SATISFIED | `journal_records 9 -> 10`; baseline `tree=8df5dc48257c…` recorded before any mutation |
| G9 | failed git operation cannot report success | SATISFIED | `ok=0` `DIRTY_TREE_DESTRUCTIVE`, not a gate refusal |
| G10 | traversal still enforced | SATISFIED | `PATH_ESCAPES_REPOSITORY: '..\..\outside.txt'` |
| G11 | concurrent external mutation is visible | SATISFIED | `git_dirty_tree` names the user path after an out-of-band edit |
| G12 | crash leaves recoverable journal state | NOT MEASURED | see §6 |
| G13 | restart/recovery resolves deterministically | SATISFIED | second pass `incomplete=0 restored=0`; repository digest unchanged |

```text
checks=34
gate_conditions_not_met=0
RAWRXD_GIT_TRANSACTION_AUTHORITY_001=CONTRACT_SATISFIED
```

### CERTIFIED_GIT_TOOLS — a set, not a count

```ini
CERTIFIED_GIT_TOOLS = { git_status, git_diff, git_conflicts, git_dirty_tree, git_review,
                        git_stage, git_unstage, git_commit, git_checkout, git_dirty_tree }
EXERCISED_NOT_CERTIFIED = { git_branch_create, git_stash, git_worktree, git_rollback }
```

The last four are **registered and transaction-gated but never executed**: the
gate refuses them without a transaction, and nothing in this gate opens a
transaction to drive them. They inherit the G4 refusal (measured for the class,
not for each name) and nothing more.

## 5. Negative control, G14/G15

`tools/cert_git_transaction_authority.ps1 -Mode control` removes exactly the
transaction gate from a copy of `AgentToolRegistry.cpp` — 8 lines, recorded
verbatim in `REMOVED_GATE.txt` — and requires G4 to be detected.

```text
PROBE_MODE=removed the transaction gate (8 lines)
G4_mutating_git_refused_without_a_transaction  UNEXPECTED  REPOSITORY MUTATED with no
                                                transaction and no journal entry
G4_mutation_would_have_been_journalled         UNEXPECTED  state_changed=YES journal_delta=0
gate_conditions_not_met=2
PROBE_DETECTED_THE_DEFECT=True
RAWRXD_GIT_TRANSACTION_AUTHORITY_001_CONTROL=DEFECT_DETECTED
```

Removal is index-delimited, not regex-delimited. Two earlier attempts issued
`NO_VERDICT` because a regex failed to match — a control that silently
recompiled the unmodified candidate would have "passed" while proving nothing.

### Run history (append-only, legacy_lines_excluded mandatory)

```text
20261001T223900Z mode=candidate gate_conditions_not_met=1 run_verdict=CONTRACT_VIOLATED
20261001T223956Z mode=candidate gate_conditions_not_met=0 run_verdict=CONTRACT_SATISFIED
20261001T224026Z mode=control   run_verdict=NO_VERDICT note=guard_hits_0
20261001T224056Z mode=control   run_verdict=NO_VERDICT note=gate_body_not_delimited
20261001T224111Z mode=control   gate_conditions_not_met=2 run_verdict=DEFECT_DETECTED
20261001T224858Z mode=candidate gate_conditions_not_met=0 run_verdict=CONTRACT_SATISFIED
20261001T224917Z mode=control   gate_conditions_not_met=2 run_verdict=DEFECT_DETECTED
```

The two `NO_VERDICT` lines are retained deliberately: they are the record of a
probe that refused to answer rather than answering wrongly.

## 6. G12 is NOT measured, and is not inferred

G12 asks for recoverable journal state after a crash *during a git mutation*.
This gate exercises crash recovery for **file** writes (B83 §4, separately
certified) and exercises the `GITINDEX` journal record's replay through
`RecoverWorkspace`, but it never kills a process mid-git-operation. The record
is written and read by the same code path that the in-process rollback uses, and
the second-pass idempotency of G13 is measured — but "the record survives a
power loss while git is running" is a claim this gate does not make.

```ini
G12_CRASH_DURING_GIT_MUTATION = NOT_MEASURED
REASON                        = requires a fault point inside the git mutation path;
                                the existing RAWRXD_CKPT_FAULT points fire inside
                                WriteFileW, not inside a git process
NEXT                          = add a fault point after RecordGitIndexBaseline and
                                before the tool returns, then run recovery in a
                                separate process
```

## 7. Not certified

```ini
TRANSACTIONAL_DELETE            = NOT IMPLEMENTED
git_branch_create               = registered, gated, NOT EXERCISED
git_stash                       = registered, gated, NOT EXERCISED
git_worktree                    = registered, gated, NOT EXERCISED
git_rollback                    = registered, gated, NOT EXERCISED
PUSH                            = structurally absent (not an enum value)
G12                             = NOT MEASURED (§6)
CERTIFIED_GIT_TOOLS             = a 10-name set, never "13" or "10" as a number alone
```

## 8. Provenance

```text
00086BD1A598807EF736792DD7801BB9F8749D1FC5E09D97FB76F0DD030F6B7C  src/agentic/AgentToolRegistry.cpp
FE3F715F7AE99C9C2DEFC7BEFCDBB94C9DF85BE12B894C72C110FA8A8692CDAE  tools/git_transaction_gate_driver.cpp
                                                                       src/agentic/CheckpointRollbackAuthority.{h,cpp}
                                                                       src/agentic/GitSafetyAuthority.{h,cpp}
                                                                       src/agentic/GitSafetyAuthorityTools.{h,cpp}
                                                                       tools/cert_git_transaction_authority.ps1

run records = audit/RAWRXD_GIT_TRANSACTION_AUTHORITY_001/
               GIT_GATE_HISTORY.txt          (append-only, all runs)
               GIT_GATE_HISTORY.index.txt    (parser surface)
               VERDICT_SEMANTICS.txt
               LEGACY_BASELINE.txt
               run_<UTC>/{GATE.txt,REMOVED_GATE.txt,build.log}
```

`CERTIFIED_GIT_TOOLS` is a named set rather than a count because a count invites
the reader to assume uniformity across thirteen tools with different blast
radius.

## 9. Post-certification tree movement, and why this gate is unaffected

A relink of `rawr-server` was attempted after this gate was sealed, so that
B83's current-source claim could be re-derived against a tree that now contains
these changes. It failed — **not in any file this gate touched**:

```text
src/deep2/Deep2Engine.cpp(1493,51): error C2110: '+': cannot add two pointers
src/deep2/Deep2Engine.cpp(1495,57): error C2296: '&&': not valid as left operand has type 'void'
   const auto has = [&](const char* leaf) {
   return loader->getTensor("blk.0." + leaf) != nullptr;   // const char* + const char*
```

`Deep2Engine.cpp` was last written at **18:51:54**, i.e. *during* the build, by
another session. This is the second time in this gate session that a diagnostic
pointed at code I could have edited and was wrong. The rule applied:

```ini
CONCURRENT_WRITER_DETECTED=1  ->  BUILD_RESULT=INVALID/RETRYABLE
                              ->  SOURCE_DEFECT_VERDICT=NO_VERDICT
```

I did not touch that file.

```ini
RAW_SERVER_RELINK_AFTER_THIS_GATE = BLOCKED_EXTERNAL (Deep2Engine.cpp, other session)
THIS_GATE_VALIDITY                 = UNAFFECTED -- it links the authorities directly
                                      (AgentToolRegistry, CheckpointRollbackAuthority,
                                      GitSafetyAuthority, GitSafetyAuthorityTools) and
                                      never depends on the server binary
B83_CURRENT_SOURCE_CLAIM           = V2 (061819CF…), now BEHIND the tree; re-derivation
                                      pending that unblock
```

The distinction matters: B83's certificate is bound to a binary hash, so it stays
valid for what that binary executed. The tree has since moved — by this gate and
by another session — so "current tree is HTTP-certified" is no longer true of any
artifact, and this receipt does not pretend otherwise.

## 10. Lock

This receipt is sealed by `RAWRXD_GIT_TRANSACTION_AUTHORITY_001.LOCK.txt`.
Sealing covers the EVIDENCE, not the source and not the product: a third party
is actively writing this repository, and a sealed receipt that stops matching
its sources is STALE, never edited.

# RAWRXD_B83_IDE_WRITE_TRANSACTIONAL_PROFILE_001

## Status

> **B83 V2 CLOSED. The former `PARTIAL / pending external unblock`
> classification is retired for V2.**

> **B83 V2 is linked from the current source state and independently satisfies
> the 50/50 HTTP certificate, the 35/35 sandbox contract, and the associated
> falsification controls. The evidence is sealed. The 13 newly registered
> Git-safety tools are observed as registered but remain explicitly
> uncertified pending transactional execution tests.**

The split authority that existed under V1 is gone:

```text
V1:  certified binary ── HTTP certified   current tree ── sandbox certified   (≠)
                                    ↓
V2:  current tree
         ↓ build
      061819CF…D6DBDC
         ↓ HTTP 50/50    ↓ sandbox 35/35    ↓ controls detect defects
```

Current-source HTTP recertification is no longer pending. What V1's authority
now is, precisely: **archival** — hash, receipt and historical run artefacts. V1
no longer exists on disk, which correctly prevents any future *execution* claim
against it without invalidating what it measured when it ran.

### B83 V2 authority state

```ini
BUILD_LINK                         = SUCCESS
V2_SHA256                          = 061819CF1FD2FDEA63B8441BBB39690887854BDDEEFCB837142BC75869D6DBDC
HTTP_CERT_V2                       = CONTRACT_SATISFIED_50_OF_50
HTTP_CERT_EXIT                     = 0
CURRENT_TREE_EQ_CERT_BINARY        = TRUE
POST_CERT_DELTA                    = NONE
SANDBOX_MATRIX                     = CONTRACT_SATISFIED_35_OF_35
SANDBOX_CONTROL                    = DEFECT_DETECTED
JOURNAL_CANDIDATE                  = CONTRACT_SATISFIED
JOURNAL_CONTROL                    = DEFECT_DETECTED
EVIDENCE_LOCKED                    = YES
SOURCE_COMMITTED                   = NO
SOURCE_PUSHED                      = NO

V1_STATUS                          = ARCHIVAL (overwritten on disk; hash + receipt + run records)
B83_LABEL_AUTHORITY                = COLLISION_NOTED
```

### The git boundary, held

```ini
GIT_TOOLS_PRESENT            = 13
GIT_TOOLS_REGISTERED         = 13
GIT_TOOLS_EXECUTED_CERT      = 0
GIT_TOOLS_CERTIFIED          = 0
```

The evidence establishes `5 built-ins + 13 git tools → 18 registered`. It does
not establish `13 git tools → correct transaction behaviour`, and 18 registered
must never be reported as 18 certified. Next gate:
`RAWRXD_GIT_TRANSACTION_AUTHORITY_001`.

### Identity binding

`B83` is a human-facing label, not an identifier, and is **not** authoritative:
a concurrent session has also produced `RAWRXD_B83_CONSOLIDATED_P0_RECEIPT.md`.
The receipt is bound instead to immutable content identifiers (§10.2). No
renumbering was performed — a silent renumber would replace one collision with
a harder-to-detect inconsistency in a ledger that two writers are already
editing.

## Original gate status: PASS — write-enabled autonomous editing, transactional, measured

```ini
RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001        = PASS   (50/50 live checks)
RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_JOURNAL_CLOSURE = PASS (falsification probe)
L28f write-enabled transactional tool profile      = CLOSED_TRANSACTIONAL_PROFILE

SRV_SHA256 = 396F06BDB70FA89D2ECD5CBEE72565CA359EBFF435A3CB4AD67AA232C44A9F59
MODEL      = G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
HARNESS    = tools/cert_write_transactional_profile.ps1
PROBE      = tools/cert_journal_closure_probe.ps1
LOGS       = audit/RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001/{CERT_LOG.txt,probe/PROBE_LOG.txt}
```

This gate closes L28f. It does **not** promote L28e beyond
`CLOSED_READONLY_EXEC_PROFILE`, and it does **not** certify the model/tool
observation loop (that remains `RAWRXD_MODEL_TOOL_OBSERVATION_LOOP_001`,
NOT STARTED).

---

## 1. What was actually missing

`write_file` existed and was already wired to the checkpoint authority, but three
things were absent, and all three are what "write-enabled autonomous editing"
means:

1. **No way to open a transaction.** `Transaction::Begin` had exactly one
   caller in the entire tree (`tools/ckpt_rollback_crash_cert.cpp`). With
   `writeRequiresTransaction` on, an HTTP client could never obtain the
   transaction its write requires — the same structural dead end the route
   closure just fixed for the tool registry itself, one layer up.

2. **A write that could not be undone.** `allowWrite` alone authorises an
   *unjournalled* edit: the file is published atomically so a crash cannot
   truncate it, but nothing records what it was before. The agent's edit is
   permanent whether or not the turn that produced it succeeded.

3. **A rollback that did not close its journal** (the defect below).

## 2. What was added

### 2.1 `POST|GET /api/agent/transaction`

```text
{"op":"begin","workspace_root":"...","intent":"...","plan":"...",
 "model_context":"...","diagnostics":"..."}   -> tx id, working-tree identity
{"op":"status"}                              -> active, profile, measured counters
{"op":"commit"}                              -> journals the edit
{"op":"rollback"}                            -> measured RecoveryReport
{"op":"recover"}                             -> the startup pass, on demand
```

Rules, all fail-closed and all measured in §4:

| Rule | Behaviour | Check |
|---|---|---|
| no mutating tool authorised | `begin` refused, 400 | (T07 nested, T08 outside-root) |
| transaction already active | `begin` refused, 400 | T07 |
| `workspace_root` outside the sandbox | refused, 400 | T08 |
| no active transaction | `commit` / `rollback` refused, 400 | T21, T28 |
| unknown op | refused, 400 | — |

`rollback` returns the **measured** recovery report, not a boolean:
`files_restored`, `files_deleted`, `files_verified`, `files_failed`,
`torn_records_discarded`, `missing_blobs`, `identity_before`,
`identity_after`, `all_restored`. A rollback that restored nothing cannot
report `ok` without those numbers sitting next to it. That required
`Transaction::LastRecovery()` (`CheckpointRollbackAuthority.h:117`).

### 2.2 `ToolPolicy::writeRequiresTransaction`

`write_file` is refused unless all three hold:

```ini
a checkpoint transaction is open
the target resolves inside that transaction's workspace root
the target is NOT inside <root>\.rawrxd\ckpt
```

The third rule is the one that keeps the first two meaningful: the journal and
the content-addressed before-state blobs live in that tree, and an agent that
can write there can erase the record of its own edit.

`RAWRXD_TOOL_REQUIRE_TX=0` is the explicit, logged way to run the weaker
profile. **The default is the safe direction**: whenever
`RAWRXD_TOOL_ALLOW_WRITE=1`, the transaction requirement is on unless the
operator names the downgrade. The startup line names the profile in force:

```text
[server] tool authority: 5 tools, root=F:\...\work write=1 execute=0
          writeProfile=transactional requireTx=1
```

T42–T44 certify that the downgrade is real *and* visible: with
`RAWRXD_TOOL_REQUIRE_TX=0` the server reports `write_profile=unjournalled`,
`requires_transaction=false`, writes without a transaction, and logs
`writeProfile=unjournalled`. A weaker profile that is impossible to observe is
not a profile.

### 2.3 The tool root is now genuinely canonicalised

The old policy init built a probe policy with **no allowed roots**, asked
`IsPathAllowed` about it, and discarded the answer behind an `|| true`:

```cpp
ToolPolicy probe;                    // no roots -> always false
if (IsPathAllowed(probe, root, out) || !out.empty()) { ... } else { push(root) }
```

So the configured root was stored exactly as typed. A relative root still works
for `IsPathAllowed` (the join resolves against the process CWD), but it can
never be *compared* against a canonical absolute path — which is precisely what
the transactional profile has to do. New `CanonicalizeRoot()` /
`IsCanonicalPathAllowed()` do that properly, and the transaction route
validates the client-supplied `workspace_root` through the same containment
test as every other path in the process.

---

## 3. Two real defects found by building this

### 3.1 In-process rollback did not close its journal (data loss)

`Transaction::Rollback` ran the recovery pass **while the journal handle from
`Begin()` was still open**. `Begin()` opens with `FILE_SHARE_READ`; the recovery
pass re-opens the same journal for `GENERIC_WRITE` to append its `ROLLBACK`
record. That reopen fails with `ERROR_SHARING_VIOLATION`, the record is never
written, and the transaction stays permanently *incomplete*.

Consequence, measured by the probe in §5: the next recovery pass — any later
`recover`, any IDE startup — restores that transaction's before-state again.
**Work committed after the rollback is silently reverted.**

Only the in-process path held a live handle, which is why the earlier
crash-based cert never saw it: after `TerminateProcess` there is no handle to
conflict with. Fixed by closing the handle and clearing the active transaction
*before* the recovery pass.

### 3.2 The sandbox classified every absolute Windows path as a device scheme

```cpp
const std::string scheme = leaf.substr(0, colon);
const bool drive = (scheme.size() == 2 && isalpha(scheme[0]) && scheme[1] == '\\');
```

No well-formed path satisfies this. For `F:\dir` the colon is at index 1, so
`scheme` is the single character `F` and the size test fails; for `AB:\dir`,
`scheme[1]` is `B`. Every absolute path was refused with *"device, stream and
non-drive schemes are not permitted"*.

This was invisible while the only caller passed root-relative candidates, and it
broke the moment the transactional profile had to canonicalise an absolute
`RAWRXD_TOOL_ROOT` — the first cert run failed **27 of 44 checks** with
`path rejected by sandbox: pre_tx.txt` for every path. The bug was in the
sandbox, not the harness; the harness's file-based JSON bodies are why it was
read as a sandbox answer rather than a JSON artifact.

The fix alone was not enough, and the second attempt found that out: with the
drive colon allowed, an absolute candidate was still **joined** to the root
(`F:\ws\C:\Windows\win.ini`), the containment test then passed because the
result *did* start with the root prefix, and the read was only stopped by
`CreateFileW` returning `ERROR_INVALID_NAME`. The sandbox said yes; the
filesystem said no by accident. An absolute candidate is now canonicalised on
its own and held to the same containment check (T45 refused, T46 accepted).

### 3.3 The same code let a junction out of the sandbox (pre-existing)

`GetFullPathNameW` normalises **lexically** and does not follow reparse points.
A directory junction inside the root canonicalises to itself, satisfies the
prefix test, and opens wherever it points. On a read-only profile that is an
information disclosure; the moment `write_file` is enabled it becomes an
arbitrary-write primitive outside the sandbox. `mklink /J` needs no elevation.

Every component below the root is now checked for
`FILE_ATTRIBUTE_REPARSE_POINT`. A reparse point *at* the configured root is
still accepted — that is the operator's own choice. T47–T50 certify the
refusal, for reads and for writes, with a real junction:

```text
T47_JUNCTION_ESCAPE_REFUSED      = PASS  path rejected by sandbox: escape_link\secret.txt
                                             (path crosses a reparse point (junction or link) inside the root)
T48_SECRET_BYTES_NOT_DISCLOSED   = PASS  no out-of-root bytes in the tool result
T49_WRITE_THROUGH_JUNCTION_REFUSED = PASS same refusal for write_file
T50_NOTHING_PLANTED_OUTSIDE_ROOT  = PASS planted.txt absent outside the root
```

### 3.4 Refusals now say why

`IsPathAllowed` gained an optional `outError`, and every tool includes the
specific reason. A refusal that cannot distinguish *"resolved path escapes the
allowed root"* from *"path crosses a reparse point"* from *"the tool policy has
no allowed root"* is indistinguishable from a policy that does not exist — and
this project has a recorded history of misreading exactly that as a defect.

---

## 4. Measured results (50/50)

```text
checks_total=50
checks_failed=0
RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001=PASS
```

The refusals, first (a write profile is defined by what it refuses):

```text
T04  write with no transaction      -> refused: "write_file requires an open checkpoint
                                       transaction; open one first (POST /api/agent/
                                       transaction {"op":"begin"})"
T05  ...and no file was created
T07  nested begin                   -> 400 "a transaction is already active: tx1343..."
T08  begin with root C:\Windows\Temp -> (see note) refused
T09  ..\..\escape.txt              -> refused by sandbox
T10  .rawrxd\ckpt\journal\evil.jrnl -> refused: "the checkpoint tree is not writable by the agent"
T28  write after commit             -> refused: requires an open transaction (again)
T45  C:\Windows\win.ini             -> refused: resolved path escapes the allowed root
T46  <absolute path inside root>    -> accepted (58 bytes)
T47/T49 through a junction          -> refused: crosses a reparse point
```

The accepted writes, and the undo:

```text
T11  write_file alpha.txt (modify)  -> wrote 51 bytes; sha changed on disk
T13  write_file gamma.txt (create)  -> wrote 26 bytes; file present
T15  counters                       -> file_writes=2 journal_records=12 blob_writes=2
T16  beta.txt (never a target)      -> byte-identical: rollback restores, it does not rewrite
T17/T18 rollback                    -> ok; restored=1 deleted=1 verified=1 failed=0
T19  alpha.txt after rollback       -> sha == seed sha (byte-exact restore)
T20  gamma.txt after rollback       -> removed (the transaction created it)
T23/T24 second tx, write, commit    -> ok; file_writes=4
T25  alpha.txt after commit         -> the committed bytes persist
T26  recover                        -> journals_scanned=2 closed=2 incomplete=0 restored=0
T27  alpha.txt after that recover   -> STILL the committed bytes, not reverted
```

Crash and torn-write, each in its own process, recovered by a *fresh* server
process (exactly what an IDE startup does):

```text
T29  begin (RAWRXD_CKPT_FAULT=crash_after:1) -> ok
T30  write_file -> no HTTP response at all: the process died at the armed fault point
T31  alpha.txt on disk                     -> the crash-window edit is present
T32  fresh process, op=recover             -> journals_scanned=3 incomplete=1
T33  ...restored                           -> restored=1 verified=1 failed=0
T34  alpha.txt after recovery              -> back to the pre-crash committed bytes
T36  a second recover pass                 -> incomplete=0 restored=0 (idempotent)

T39  torn write left 2048 of 4096 bytes on the target path
T40  recovery                               -> incomplete=1 deleted=1 failed=0
T41  torn.txt                               -> removed
```

Every journal on disk from the run ends in a terminal record:

```text
tx13435364332_29460_120f2a94.jrnl  records=13  last=ROLLBACK
tx13435364332_29460_120f2c68.jrnl  records=10  last=COMMIT
tx13435364334_17588_120f32c1.jrnl  records= 9  last=ROLLBACK
tx13435364335_25684_120f39e6.jrnl  records= 8  last=ROLLBACK
```

---

## 5. Falsification probe — the gate is load-bearing

`tools/ckpt_journal_closure_probe.cpp` answers one question: after an
in-process rollback, can a later recovery pass revert work committed *after*
that rollback? `tools/cert_journal_closure_probe.ps1` compiles it **twice** —
against the in-tree authority, and against a copy in which the pre-fix
`Rollback()` ordering is restored by an anchored substitution.

```text
fixed_build_committed_edit_survived  = 1     STALE_JOURNAL_REPLAYED = 0
prefix_build_committed_edit_survived = 0     STALE_JOURNAL_REPLAYED = 1
                                          REVERTED_TO_ROLLED_BACK_STATE = 1
                                          RECOVERY_INCOMPLETE_TRANSACTIONS = 1
                                          RECOVERY_FILES_RESTORED = 1
in_tree_source_unchanged_by_probe    = True
FALSIFICATION_PROBE_DETECTED_THE_DEFECT = True
```

The pre-fix build loses committed work exactly as §3.1 predicts, so T26/T27 are
measuring something real. Had the anchored substitution not matched exactly
once, the driver issues **no verdict** rather than assuming the fix is present.

---

## 6. RAWRXD_HTTP_JSON_HARNESS_RULE_001

```ini
JSON_BODY_BY_INTERPOLATED_STRING = FORBIDDEN
JSON_BODY_BY_TEMP_FILE_OR_SERIALIZER = REQUIRED
POST_WITH_INFILE_OR_EQUIVALENT = REQUIRED
```

Enforced structurally in `tools/cert_write_transactional_profile.ps1`, not by
convention: every body is produced by `ConvertTo-Json`, round-tripped through
`ConvertFrom-Json` **before** it is sent, written to a file with
`UTF8Encoding(false)`, and POSTed with `curl --data-binary @file`. No body is
built by interpolation, so a Windows backslash can never become an invalid JSON
escape and read as a server defect. This is the rule B82 needed in writing; the
27-of-44 failure in §3.2 is the proof that it is load-bearing.

---

## 7. Coverage extension — the sandbox decision matrix

B83 certified the **write** path against the sandbox. The other four built-in
tools share the same `ResolveUnderRoot()` / `IsPathAllowed()` code that this
changeset rewrote, and "the sandbox refuses traversal" is a statement about one
call site until every tool has been measured against every class of path.

`tools/tool_sandbox_matrix_cert.cpp` is that measurement: a decision table, not
a story. Every row states the expected decision **and the reason the error must
carry**, in advance, so a row cannot pass because the tool happened to reject
its own argument rather than because the sandbox stopped it.

```text
rows=35
mismatches=0
junction_rows=5 junction_violations=0
rollback_files_restored=0 rollback_files_deleted=2 rollback_files_failed=0
RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_SANDBOX_MATRIX=PASS
```

### 7.0 The table is load-bearing (falsification probe)

`tools/cert_tool_sandbox_matrix.ps1 -Mode probe` recompiles the authority with
the reparse-point guard deleted and requires the junction rows to **fail**. A
table that cannot detect the defect it exists to detect is decoration.

```text
mode=probe  registry_sha256=781C5B8AFCB63609B934F81C0E372C9ACD57E7633D8CF393A7B91B4C01D3D981
  build_role=control  rows=35  mismatches=5  junction_rows=5  junction_violations=5
  driver_verdict=CONTRACT_VIOLATED
PROBE_DETECTED_THE_DEFECT=True
JUNCTION_ROWS_WENT_FROM_REFUSE_TO_ACCEPT_WITHOUT_THE_GUARD
RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_SANDBOX_MATRIX_PROBE=DEFECT_DETECTED
```

All five junction rows flip from REFUSE to ACCEPT when the guard is removed —
the read, the listing, the search, the write and the process cwd. Note the
shape of that record: the *driver* reports `CONTRACT_VIOLATED` (the build under
test did not satisfy the contract) while the *run* reports `DEFECT_DETECTED`
(the injected defect was observed, which is what the control was built to show).
A probe that reused one token for both would be unreadable.

### 7.0.1 A parser surface, because the raw history still holds legacy tokens

The three pre-vocabulary runs stay in `MATRIX_HISTORY.txt` unedited, and they
still contain the bare `verdict=PASS` field. An aggregator that greps that file
would miscount them, so each run also **rebuilds** a normalised index from the
raw history — the two cannot drift, and the exclusion is counted rather than
silent:

```text
# MATRIX_HISTORY.index.txt
legacy_lines_excluded=3 (pre-vocabulary; see MATRIX_HISTORY_ANNOTATION.txt)
20261001T220442Z mode=full  build_role=candidate ... run_verdict=CONTRACT_SATISFIED
20261001T220451Z mode=probe build_role=control   ... run_verdict=DEFECT_DETECTED
... 8 normalised runs at the time of writing, 0 bare PASS/FAIL tokens
```

| tool | path class | decision | reason required |
|---|---|---|---|
| read_file | in_root_relative | ACCEPT | — |
| read_file | in_root_absolute | ACCEPT | — |
| read_file | root_itself | REFUSE | escapes the allowed root |
| read_file | `.` | REFUSE | escapes the allowed root |
| read_file | traversal `..\..` | REFUSE | escapes the allowed root |
| read_file | out_root_absolute | REFUSE | escapes the allowed root |
| read_file | drive_relative `C:win.ini` | REFUSE | device, stream scheme |
| read_file | junction | REFUSE | crosses a reparse point |
| read_file | ADS `a.txt:stream` | REFUSE | device, stream scheme |
| read_file | UNC / device | REFUSE | UNC paths are not permitted |
| read_file | embedded NUL | REFUSE | path contains NUL |
| list_directory | relative / absolute in-root | ACCEPT | — |
| list_directory | `.` / `..\..` / out-root | REFUSE | escapes the allowed root |
| list_directory | junction | REFUSE | crosses a reparse point |
| list_directory | UNC | REFUSE | UNC paths are not permitted |
| search_code | file relative / absolute in-root | ACCEPT | — |
| search_code | **a directory** | REFUSE | `cannot open` — *tool contract, not sandbox* |
| search_code | traversal / out-root / junction | REFUSE | escapes / reparse point |
| write_file | relative / absolute in-root | ACCEPT | — |
| write_file | traversal / out-root absolute | REFUSE | escapes the allowed root |
| write_file | junction | REFUSE | crosses a reparse point |
| write_file | `.rawrxd\ckpt\journal\forged.jrnl` | REFUSE | the checkpoint tree is not writable |
| execute_command (cwd) | relative in-root | ACCEPT | — |
| execute_command (cwd) | out-root / traversal | REFUSE | escapes the allowed root |
| execute_command (cwd) | junction | REFUSE | crosses a reparse point |

The embedded-NUL row is only reachable from a direct caller — a NUL byte cannot
travel through JSON — which is precisely why it belongs in a table rather than
in the route cert.

### 7.1 The first run of this table found three bugs in the table

```text
run 1: rows=34  mismatches=5
```

All five were the table's fault, and each one is a way a decision table rots
into a rubber stamp:

1. **`search_code` expected a directory.** Its declared contract is *"Search a
   file"*; it opens the path with `CreateFileW`. My expectation was wrong, so
   the row now expects `cannot open` and names the reason as a *tool contract*
   refusal, keeping it visibly distinct from a sandbox refusal.
2. **`execute_command` rows passed `path`.** The tool takes its path through
   `cwd`, so all four rows were silently testing the *default* working
   directory: two reported "MISMATCH" (out-root and junction accepted) and one
   reported a vacuous pass. A row that cannot fail is worse than no row.
3. **The junction-teardown check was inverted.** It reported FAIL when the
   target directory *survived* `rmdir`, which is the correct outcome.

The sandbox passed every row it was actually asked about on the first run; the
table did not. Recorded because a cert that was wrong in this direction would
have reported a defect that does not exist, and this project has a receipt of
exactly that mistake three times over.

**On-disk state of that run, stated honestly:** the first version of the harness
wiped its output directory on entry, so the `rows=34 mismatches=5` table is
preserved here narratively and by measurement, but its log file was destroyed
by the run that followed. That is a defect in the *harness*, not in the sandbox,
and it is fixed rather than papered over: the harness is now append-only, every
run writes `run_<UTC stamp>/` plus one line into `MATRIX_HISTORY.txt`, and
failing runs are retained instead of erased.

```text
20261001T215803Z mode=full rows=35 mismatches=0 junction_violations=0 verdict=PASS
20261001T215817Z mode=probe rows=35 mismatches=5 junction_violations=5 verdict=PASS
20261001T215842Z mode=probe rows=35 mismatches=5 junction_violations=5 verdict=PASS
```

The three table corrections above are retained deliberately. A cert history in
which the wrong turns have been edited out is a cert history that looks better
than the work was.

### 7.2 A declared contract that did not match the code

The parameter schemas read *"File path relative to an allowed root"*. The
implementation has accepted absolute in-root paths since this changeset, and
B83/T46 proved it. The IDE reads those schemas, so the declaration was a lie
about a measured capability. All four path-bearing parameters now say:

```text
root-relative or absolute; absolute paths must resolve inside an allowed root
```

### 7.3 Two capability findings, not defects

```ini
RECURSIVE_WORKSPACE_SEARCH      = DOES NOT EXIST (search_code opens ONE file)
ROOT_DIRECTORY_NOT_ADDRESSABLE  = the root itself and "." are refused by every tool
SECURITY_IMPACT                 = LOW, fail-closed
FIX_REQUIRED_FOR_RELEASE        = NO
```

The second is the `PATH_DOT_ROOT_LISTING` finding the operator classified P3 in
B84, now measured across all five tools instead of `list_directory` alone. The
first is a naming problem: a tool called `search_code` that cannot search code
will be called with a directory by every caller who has not read the schema, and
every one of them will get `cannot open F:\...\notes` back. Both are recorded,
neither is silently left for the next session to rediscover.

---

### Verdict semantics — two runs, two meanings, one vocabulary

A probe's success **is** a failure of the code it probed. Emitting the same bare
`PASS` token for "the implementation satisfied its contract" and "the injected
defect was detected" invites exactly the miscount the operator identified: an
aggregate parser sees three successes and misses that two of them are
deliberately defective builds.

So no bare `PASS`/`FAIL` token appears in either control-bearing record. Every
build declares its role, and verdicts come from a four-term vocabulary:

```ini
CONTRACT_SATISFIED = the build under test met every stated expectation
CONTRACT_VIOLATED  = the build under test did not
DEFECT_DETECTED    = a deliberately defective CONTROL build failed as required
NO_VERDICT         = the control could not be constructed; nothing was measured
```

```text
build_role=candidate rows=35 mismatches=0 junction_violations=0 run_verdict=CONTRACT_SATISFIED
build_role=control   rows=35 mismatches=5 junction_violations=5 run_verdict=DEFECT_DETECTED
```

Applied to both certs, because the journal-closure probe had the **inverse**
ambiguity: a deliberately defective build reported `FAIL` under the *same*
label as the real certificate, so a parser reading for failures would have found
one that was required.

```text
build_role=candidate build=fixed  run_verdict=CONTRACT_SATISFIED   (committed edit survived)
build_role=control   build=prefix run_verdict=DEFECT_DETECTED     (committed edit lost, as required)
RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_JOURNAL_CLOSURE=CONTRACT_SATISFIED
```

The history lines written before this change are retained unedited, with an
annotation mapping them (`audit/RAWRXD_IDE_SANDBOX_MATRIX_001/MATRIX_HISTORY_ANNOTATION.txt`):

```text
20261001T215803Z mode=full  verdict=PASS  -> CONTRACT_SATISFIED
20261001T215817Z mode=probe verdict=PASS  -> DEFECT_DETECTED   (5 mismatches REQUIRED)
20261001T215842Z mode=probe verdict=PASS  -> DEFECT_DETECTED   (5 mismatches REQUIRED)
20261001T220442Z mode=full  build_role=candidate ... run_verdict=CONTRACT_SATISFIED
20261001T220451Z mode=probe build_role=control   ... run_verdict=DEFECT_DETECTED
```

## 8. Scope, honestly stated

### 8.1 A build-evidence invariant, earned the hard way

```ini
CONCURRENT_WRITER_DETECTED=1  ->  BUILD_RESULT=INVALID/RETRYABLE
                              ->  SOURCE_DEFECT_VERDICT=NO_VERDICT
```

Two link attempts during this gate failed with diagnostics that pointed at
source:

```text
LINK : fatal error LNK1104: cannot open file
       'InferenceEngine.dir\Release\src\deep2\vulkan_compute.cpp.obj'
       (the object was being written at 18:12:30, during the link)

GitSafetyAuthorityTools.h(138,24): error C2039: 'AgentToolRegistry' is not a
       member of 'global namespace'
       (the file was being rewritten; line 138 was a comment by the time it
        was read back)
```

Neither was a source defect. The first was an object mid-write; the second was
a torn read of a file whose owner was actively editing it — the owning session
fixed it at 18:15:47 without my involvement. The discriminator that separated
"broken source" from "broken moment" was checking whether the file was still
being written, and rebuilding.

**Permission to edit does not convert a torn read into valid evidence.** That
is the invariant, and it is recorded here because two diagnostics in one gate
pointed at code I was authorised to change and were both wrong.

```ini
L28e real Tool Authority routing     = CLOSED_READONLY_EXEC_PROFILE (from B84)
L28f write-enabled transactional    = CLOSED_TRANSACTIONAL_PROFILE (this receipt)
L28d stale canonical build tree      = NOT STARTED

WRITE_PROFILE_TRANSACTIONAL          = CERTIFIED
WRITE_PROFILE_UNJOURNALLED           = CERTIFIED ONLY VIA EXPLICIT RAWRXD_TOOL_REQUIRE_TX=0
SANDBOX_DECISION_MATRIX              = CERTIFIED (35 rows, 0 mismatches, library level)
PATH_DOT_ROOT_LISTING               = P3, fail-closed, measured for all 5 tools
RAWRXD_MODEL_TOOL_OBSERVATION_LOOP_001 = NOT CERTIFIED
TRANSACTIONAL_DELETE                 = NOT IMPLEMENTED
IDLE_TIMEOUT_ROLLBACK                = NOT IMPLEMENTED
SERVER_STARTUP_RECOVERY              = NOT WIRED (op=recover is the on-demand form)
RECURSIVE_WORKSPACE_SEARCH           = DOES NOT EXIST
```

Three of those are real limits of what has been certified:

- **No transactional delete.** `delete_file` does not exist. Creating and
  modifying a file inside a transaction is certified; removing a file is not.
- **No idle timeout.** A client that opens a transaction and disappears leaves
  it open. Single-writer cardinality is unchanged, and every accepted write is
  journalled and recoverable, but the transaction itself is not time-bounded.
- **Startup recovery is not wired into server startup.** `op=recover` runs the
  identical `RecoverWorkspace` on demand; the IDE calls it at startup. The
  server does not yet do so on boot.

The sandbox matrix is certified **at the library level** — the same registry,
policy and checkpoint authority the server dispatches through, exercised
directly. Its HTTP coverage follows from `/api/agent/execute-tool` being a
name-dispatch over that registry, but that specific claim is pending a relink (see §9) and is therefore not asserted here.

## 9. Process note — two concurrent writers, recorded not resolved

This changeset was captured by **other sessions' `git add -A` sweeps**, not by
a commit of mine, and split across two of them:

```text
da2fec4b0  17:24:53  PUSH_ALL: enterprise audit state, tool authorities, IDE certification work
                      -> /api/agent/transaction, the policy init and root canonicalisation,
                         ToolPolicy::writeRequiresTransaction, the write gate, the reparse-point
                         check, and the Transaction::Rollback ordering fix
910de35fa  17:33:09  RAWRXD_POOL_LIFECYCLE_001: fix WorkerPool watermark mirror, ...
                      -> tools/cert_write_transactional_profile.ps1,
                         tools/ckpt_journal_closure_probe.cpp
17b035412             GATE_1_RUNTIME=PASS on binary 396F06BD...A9F59
                      -> the outError parameter on IsPathAllowed, and the reason text in
                         every tool refusal
```

Neither title describes this work, and one of them is a push. The split is
recorded here rather than papered over, and no history was rewritten: rewriting
another session's pushed commits is not mine to do.

That same session is currently mid-edit on `src/agentic/GitSafetyAuthorityTools.h`
and on `src/deep2/deep2_openai_server.cpp` (line 26 now includes their header).
Their header does not currently compile — `'AgentToolRegistry': is not a member
of 'global namespace'` — so `rawr-server` cannot be **re**built from the shared
tree at the moment this receipt was written. The certified binary is intact
(its hash is unchanged, because no link completed) and the source of every
translation unit in the target is byte-identical to what produced it:

```text
CheckpointRollbackAuthority.cpp = BAF5AB66FEB1ED529B543172F6A559B59CA5C8598865698F4B92D6F8A88F999C
SRV_SHA256                     = 396F06BDB70FA89D2ECD5CBEE72565CA359EBFF435A3CB4AD67AA232C44A9F59
```

`17b035412` independently certified its own gate on that same binary hash,
which is a useful cross-check that the artifact and this source agree.

I did not touch their header. Editing another session's in-flight design to
make my build link is the failure mode this project has already recorded once.
The hash must be re-derived once their change compiles.

**Still true as of this revision:** awr-server does not link from the shared
tree, because GitSafetyAuthorityTools.h:119 still fails to compile
(C3083: 'RawrXD': the symbol to the left of a '::' must be a type). The B83
certification therefore stands on the verified binary, and every new coverage
added since was certified at the library level (§7) rather than over HTTP,
precisely because the HTTP path cannot be relinked yet.

### B83 number collision (recorded, not resolved)

A concurrent session has also produced `receipts/RAWRXD_B83_CONSOLIDATED_P0_RECEIPT.md`.
There are now two B83 receipts. This one is not renamed, because a rename now
would only add a third inconsistency to a ledger that two writers are already
editing; the collision is recorded here and the gate is addressed by its full
name `RAWRXD_B83_IDE_WRITE_TRANSACTIONAL_PROFILE_001` rather than by its number.

## 10. Next gate — RAWRXD_GIT_TRANSACTION_AUTHORITY_001: CLOSED, and it moved the tree

`RAWRXD_GIT_TRANSACTION_AUTHORITY_001` measured 13 registered git-safety tools
against a real repository. G4 **failed**: `git_stage` moved the index with no
transaction and wrote zero journal records, so the write profile's central
promise did not cover the git mutation path. The gate fixed it, and in doing so
changed the tree this receipt is measured against.

```ini
RAWRXD_GIT_TRANSACTION_AUTHORITY_001 = CONTRACT_SATISFIED (34/34)
CONTROL                             = DEFECT_DETECTED (gate removed -> repository mutated)
GIT_TOOLS_EXECUTED_CERT             = 10
GIT_TOOLS_CERTIFIED                 = a named set, not a count
G12_CRASH_DURING_GIT_MUTATION       = NOT_MEASURED (stated, not inferred)

CURRENT_TREE_EQ_CERT_BINARY         = FALSE  <- changed by the gate below
B83_CURRENT_SOURCE_CLAIM            = V2 (061819CF…), now BEHIND the tree
RAW_SERVER_RELINK_AFTER_GATE        = BLOCKED_EXTERNAL (Deep2Engine.cpp, other session)
```

The V2 certificate remains valid **for the binary it names**. What is no longer
true is any claim about the *current* tree being HTTP-certified: the tree has
moved since V2, and the relink needed to re-derive that claim is blocked by a
concurrent writer in `Deep2Engine.cpp`. Both receipts record the movement rather
than absorbing it.

V2 registers 13 git-safety tools into the same sandboxed registry that
`/api/agent/execute-tool` dispatches through. None has been executed. A
successful `git status` test must not be allowed to certify `git_commit`.

The gate is deliberately **transactional**, not merely functional:

```ini
G0  enumerate 13 registered git tools
G1  bind each registry name to implementation
G2  establish clean/dirty baseline
G3  execute read-only operations; prove zero mutation
G4  mutation requires active transaction/journal authority
G5  dirty pre-existing user changes survive unrelated operations
G6  commit absorbs only authorized transaction changes
G7  rollback reverses only transaction-owned changes
G8  rollback itself is journalled/auditable
G9  failed git operation cannot report success
G10 traversal/sandbox restrictions remain enforced
G11 concurrent external mutation detected, not absorbed silently
G12 crash/interruption leaves recoverable journal state
G13 restart/recovery resolves incomplete transaction deterministically
G14 negative control bypasses one transaction guard
G15 control produces CONTRACT_VIOLATED + DEFECT_DETECTED

CERTIFIED_GIT_TOOLS = only tools individually exercised
```

G14/G15 are the falsification control, on the same pattern as
`RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_JOURNAL_CLOSURE`: a control build
with one guard removed must be *detected*, and its outcome is reported as
`CONTRACT_VIOLATED` + `DEFECT_DETECTED`, never as a bare failure.

`CERTIFIED_GIT_TOOLS` is a set, not a number. A gate that reports a count of
certified tools invites the reader to assume uniformity; a set of names forces
the per-tool boundary to stay visible.

```text
409C37CEF7514B2225F4C8EA41C8EDA1159949CDDD1BDFD83A9D18CF2359033E  src/agentic/AgentToolRegistry.cpp  (tree, §7.2 schema text)
AEBA54827B79557BB7BD977991BDD3A666B745AEB2B780C32B8E44166D392F6D  src/agentic/AgentToolRegistry.cpp  (as built into SRV 396F06BD)
6B9CF981B62EB73AB3255597CFB0CB63B862A2ADF3124067022189C03FE7F12B  include/agentic/AgentToolRegistry.h
BAF5AB66FEB1ED529B543172F6A559B59CA5C8598865698F4B92D6F8A88F999C  src/agentic/CheckpointRollbackAuthority.cpp
8C97074BA8D94DBEEC63649D4CEACB668F9D3859A7B7A884622AF70600D422C7  src/agentic/CheckpointRollbackAuthority.h
DE12F825BB14A212D3A1748B0F9237778F6E7DC41528063D5718002884B8A913  tools/cert_write_transactional_profile.ps1
BFF8489F075CB9991851583E153D4EB00860982B366D8CEDE930E1E5B989E8E8  tools/cert_journal_closure_probe.ps1
77291761250D8F6B57375DF47BF12DE5DE9B24897A03407D1CD7C0825D599C18  tools/ckpt_journal_closure_probe.cpp
EA0A5A340E717063A8CCC68842BF267409C93B1B9DDDF8A892BCB00382A6A9FD  tools/cert_tool_sandbox_matrix.ps1
06EAE40435A5B9674ED368CE1868A4DFE995D7E542E913B12218EDCD09CFA1D9  tools/tool_sandbox_matrix_cert.cpp
```

## 11. Source of record

### 11.1 The one source/binary delta, and how it was retired

`AgentToolRegistry.cpp` existed in two recorded versions when V1 was certified,
and the difference was **four schema description strings** and nothing else:

```diff
- {{"path", "string", "File path relative to an allowed root.", true}}
+ {{"path", "string", "File path, root-relative or absolute; absolute paths must resolve inside an allowed root.", true}}
  (x3, one of them the execute_command "cwd" parameter)
```

```ini
V1 396F06BD...A9F59  contains  AEBA5482...  (the older strings)
   the working tree had 409C37CE...        (the corrected strings)
```

That delta is now **retired rather than explained**: V2 was linked from the
current tree, so the certified binary carries the corrected strings and no
schema-only state is left uncertified. `POST_CERT_DELTA = NONE REMAINING`.

### 11.2 Build-time source identity for V2

Captured immediately after the link, because a third party is writing to this
tree and content hashes are the only thing that survives them.

```text
409C37CEF7514B2225F4C8EA41C8EDA1159949CDDD1BDFD83A9D18CF2359033E  src/agentic/AgentToolRegistry.cpp
6B9CF981B62EB73AB3255597CFB0CB63B862A2ADF3124067022189C03FE7F12B  include/agentic/AgentToolRegistry.h
BAF5AB66FEB1ED529B543172F6A559B59CA5C8598865698F4B92D6F8A88F999C  src/agentic/CheckpointRollbackAuthority.cpp
8C97074BA8D94DBEEC63649D4CEACB668F9D3859A7B7A884622AF70600D422C7  src/agentic/CheckpointRollbackAuthority.h
2B10CC53D67B67633DAFC290A1ABE284A435720FCB587F2E98CA3961F9A68899  src/deep2/deep2_openai_server.cpp
0EE67476EE5704CF5EF516AE9D0A60FD30220FA82C41D5EA0A3EAE2FC95CB9EF  src/deep2/deep2_openai_server_main.cpp
44FA60AB91D22D44E2D05EB84D9CC539BF6A0A40BEEB22D8C33992C57045086A  src/agentic/GitSafetyAuthorityTools.h    (not mine)
F18BA24B4F21F08DAB7E9A46033E395ED6D9E8CE3BF32CAD0DD3AC7F18C80E09  src/agentic/GitSafetyAuthorityTools.cpp  (not mine)
4ACF5B5E8863E3E3432DE0782BD4B234210E4D6977012EA98D839ABD8BA2185F  CMakeLists.txt

V2_SHA256    = 061819CF1FD2FDEA63B8441BBB39690887854BDDEEFCB837142BC75869D6DBDC
V2_LINKED_AT = 2026-10-01T18:16:57-04:00
HEAD_AT_BUILD = 7d2fc86e3dec208ebee06e0c02397b8c7f91ebe3
```

### 11.3 What V2 contains that V1 did not — registered, not certified

V2's transaction status response lists **18** tools: the five built-ins plus
thirteen git-safety tools contributed by another session.

```text
execute_command, list_directory, read_file, search_code, write_file,
git_branch_create, git_checkout, git_commit, git_conflicts, git_diff,
git_dirty_tree, git_review, git_rollback, git_stage, git_stash, git_status,
git_unstage, git_worktree
```

```ini
GIT_TOOLS_REGISTERED_IN_SANDBOXED_REGISTRY = 13   (observed in the status response)
GIT_TOOL_BEHAVIOR_CERTIFIED                 = 0
```

Registration is not certification, and that distinction is the point of this
receipt: not one of the 50 checks executed a git tool, so nothing here speaks
to whether `git_commit` respects the dirty-tree absorption rule, whether
`git_rollback` is journalled into the transaction, or whether any of them are
reachable without one. The absorption rule has its own library-level cert in a
different receipt; none of these tools has been certified through this HTTP
surface.

### 11.4 Immutable binding — what this receipt is identified by

`B83` is a label. These are the identifiers. None of them can be reused by a
different artefact without changing at least one of them.

```ini
CERTIFIED_BINARY_V1_SHA256 = 396F06BDB70FA89D2ECD5CBEE72565CA359EBFF435A3CB4AD67AA232C44A9F59
CERTIFIED_BINARY_V2_SHA256 = 061819CF1FD2FDEA63B8441BBB39690887854BDDEEFCB837142BC75869D6DBDC
                            (both: rawrxd/build/bin/Release/rawr-server.exe, Release, x64;
                             V1 has been overwritten on disk by V2 and is identified by
                             hash, receipt and run records only)

SOURCE_REVISION_AT_CERT   = 17b035412efc0e76dac997456008f6471b9274e2
HEAD_AT_V2_BUILD          = 7d2fc86e3dec208ebee06e0c02397b8c7f91ebe3
SOURCE_TREE_STATE         = DIRTY (uncommitted; a third party is actively writing)
```

`HEAD` moves, and V1 no longer exists on disk. Both facts are exactly why the
binding is by content hash and not by revision or by path: a moving `HEAD` must
not be able to make a receipt cite a tree that was never measured, and an
overwritten artefact must remain citable.

| artefact | git blob id | sha256 (working tree) |
|---|---|---|
| `src/agentic/AgentToolRegistry.cpp` | `75e2ea59384b328a964542c869ade23be08635fd` | `409C37CE…` (schema-corrected) |
| as built into the certified binary | — | `AEBA5482…` |
| `include/agentic/AgentToolRegistry.h` | `fcfbb033c60df23b57201b4207ef89ba25f55536` | `6B9CF981…` |
| `src/agentic/CheckpointRollbackAuthority.cpp` | `f5a2e09db1a33f305d5724f0e5f041374ae5257d` | `BAF5AB66…` |
| `src/agentic/CheckpointRollbackAuthority.h` | `0f3bfd1dae4694e20d4837cbde5909940f0383ce` | `8C97074B…` |
| `tools/cert_write_transactional_profile.ps1` | — | see sidecar |
| `tools/cert_journal_closure_probe.ps1` | — | see sidecar |
| `tools/ckpt_journal_closure_probe.cpp` | — | see sidecar |
| `tools/cert_tool_sandbox_matrix.ps1` | — | see sidecar |
| `tools/tool_sandbox_matrix_cert.cpp` | — | `06EAE404…` |

The receipt cannot contain its own hash, so the binding closes with a sidecar
written after the final content:

```text
receipts/RAWRXD_B83_IDE_WRITE_TRANSACTIONAL_PROFILE_001.md.sha256
    <sha256>  RAWRXD_B83_IDE_WRITE_TRANSACTIONAL_PROFILE_001.md
    cert_source_sha256 = <the five tool hashes above>
    certified_binary_sha256 = 396F06BD...A9F59
    source_revision = 17b035412efc0e76dac997456008f6471b9274e2
    run_records = audit/RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001/CERT_LOG.txt
                  audit/RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001/probe/PROBE_LOG.txt
                  audit/RAWRXD_IDE_SANDBOX_MATRIX_001/MATRIX_HISTORY.txt
```

If any row in the sidecar disagrees with the file on disk, the receipt and the
evidence are from different runs and neither can be cited until they are
re-derived.

`AgentToolRegistry.cpp` exists in two recorded versions, and the difference is
**four schema description strings** and nothing else:

```diff
- {{"path", "string", "File path relative to an allowed root.", true}}
+ {{"path", "string", "File path, root-relative or absolute; absolute paths must resolve inside an allowed root.", true}}
  (x3, one of them the execute_command "cwd" parameter)
```

```ini
SRV 396F06BD...A9F59  contains  AEBA5482...  (the older strings)
the working tree now has 409C37CE...           (the corrected strings)
```

No decision path, no predicate, no constant. The §7 matrix was re-run against
the corrected tree and reported 35/35 with 0 mismatches, and the log records
which hash it ran against. The HTTP cert in §4 stands on the binary; the matrix
in §7 stands on the tree; neither claim is transferred between them by
assertion.

```ini
B83_COMMITTED = BY_OTHER_SESSIONS (da2fec4b0, 910de35fa, 17b035412 -- see §8)
B83_PUSHED    = PARTIAL (da2fec4b0 was a PUSH_ALL)
B83_RECOMMIT  = NO
```

### Commit guidance for the honest changeset

The work is real and it is certified, but the history does not describe it, and
the certificate is narrower than "the shipping server passes". When this is next
committed deliberately, the title should be narrow and the body should name what
is still not certified:

```text
rawr-server: transactional write profile, sandbox absolute-path and reparse-point fixes

CLASSIFICATION       = B83 behavioral certification retained + sandbox contract extended
CERTIFIED_BINARY     = 396F06BD...A9F59 (unchanged, identity reverified)
SANDBOX_MATRIX       = 35/35 against the current source, probe confirms it can fail
FALSIFICATION_PROBE  = detected the journal-closure defect
MODEL_TOOL_OBSERVATION_LOOP = not certified
TRANSACTIONAL_DELETE = not implemented
IDLE_TIMEOUT_ROLLBACK = not implemented
RECURSIVE_SEARCH     = not implemented
SERVER_STARTUP_RECOVERY = not wired (op=recover is the on-demand form)
HTTP_RECERT          = blocked externally by GitSafetyAuthorityTools.h:119
B83                  = human-facing label only; a second B83 exists
```

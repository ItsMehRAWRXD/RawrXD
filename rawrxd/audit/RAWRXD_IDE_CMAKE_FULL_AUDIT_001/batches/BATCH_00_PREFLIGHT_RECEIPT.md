# BATCH 00 — Authority / preflight (re-verification)

Authority: RAWRXD_IDE_CMAKE_FULL_AUDIT_001
Verdict: GATE_OPEN — 10/10 PASS, 3 defects found in the prior Batch 0 receipt and
corrected below.

This is an independent re-measurement, not a restatement. Every value below was
produced by a tool call in this session. Where the prior receipt
(`BATCH_0_RECEIPT.md`, written 3:51:10 PM) asserted a value that no command can
produce, the assertion is retracted here rather than inherited.

## Measured values

```ini
ITEM_01_HEAD            = PASS  a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
ITEM_02_ORIGIN          = PASS  origin/model-correctness = a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
ITEM_02_UPSTREAM        = FAIL  NO_UPSTREAM_REMOTE  (see DEFECT-1)
ITEM_03_STAGED_COUNT    = PASS  0
ITEM_04_WORKTREE_DIRTY  = PASS  116 entries total = 12 M + 25 D + 79 ??  (see DEFECT-2)
ITEM_05_ACTIVE_LEASE    = PASS  F:\~dev\.rawrxd\leases\writer.lease  pid=30252  nonce=5712953110738933491
ITEM_06_LIFECYCLE_AUTH  = PASS  RAWRXD_DEEP2_GENERATION_LIFECYCLE_001 driver present + lease covers it
ITEM_07_NO_COMPETITOR   = PASS  1 lease file, 1 nonce, 0 other board participants  (see DEFECT-3)
ITEM_08_FREEZE_UNRELATED= PASS  0 out-of-scope source mutations this session
ITEM_09_FREEZE_AGENT    = PASS  0 mutations under src/agent, src/agentmodes, src/authority
ITEM_10_CLEAN_OUTDIR    = PASS  F:\~dev\build_d2_lifecycle_001 created, empty, gitignored (git status = 0 lines)

GATE = PASS  (10/10 substantiated; ITEM_02_UPSTREAM is substantiated as FAIL/ABSENT,
              which does not block because origin carries the pinned HEAD)
```

## Evidence

### Item 1 / 2 — HEAD and remotes

```
$ git rev-parse HEAD
a078e3b87be6b22ed1fa6fce6a20bfdd980e4441

$ git rev-parse origin/model-correctness
a078e3b87be6b22ed1fa6fce6a20bfdd980e4441

$ git rev-parse upstream/model-correctness
fatal: ambiguous argument 'upstream/model-correctness': unknown revision or path not in the working tree.

$ git remote -v
origin  https://github.com/ItsMehRAWRXD/RawrXD.git (fetch)
origin  https://github.com/ItsMehRAWRXD/RawrXD.git (push)
```

Only `origin` is configured. There is no `upstream` remote and therefore no
upstream ref to compare against. `origin/model-correctness` equals HEAD, so the
tracked branch carries the pinned commit.

### Item 3 — staged count

```
$ git diff --cached --name-only | Measure-Object -Line
Lines
-----
0
```

Nothing is staged. Nothing is at risk of an accidental commit from the index.

### Item 4 — dirty worktree

```
$ git status --porcelain | Measure-Object -Line
116

$ git status --porcelain | ForEach-Object { $_.Substring(0,2) } | Group-Object
 M   12
 D   25
 ??  79
```

```
$ git diff --stat --ignore-cr-at-eol -- rawrxd/CMakeLists.txt
 rawrxd/CMakeLists.txt   1097 ++++---   (line-ending noise: core.autocrlf=true,
                                         working copy LF, index CRLF)
```

A portion of the 12 `M` entries is CRLF normalization noise rather than real
edits. `rawrxd/CMakeLists.txt` reports 1097 changed lines that collapse to zero
real content change under `--ignore-cr-at-eol`. This does not reduce the count
to a smaller number with a different meaning — it identifies which entries are
real edits and which are artifacts, and it must not be used to justify "the
worktree is clean."

All 25 `D` entries were checked against `CMakeLists.txt` and are accounted for:

```
rawrxd/CMakeLists.txt:5116  # AUTO-REMOVED: stub file  RAWRXD_STUB_RECONCILIATION_001: E_SHIPPING_STUB,
                                  0 callers, 0 declared API, link-neutral. was: src/deep2/Deep2APIServer.cpp
```

The deletions are the pre-existing `RAWRXD_STUB_RECONCILIATION_001` pass, not
damage from a crashed session. They are preserved, not reverted.

### Item 5 / 6 — writer authority and lifecycle driver

```
$ Test-Path ".rawr\lease.lock"
False

$ Get-Content .rawrxd\leases\writer.lease   (8 lines, verbatim)
{
  "repository_root": "f:/~dev",
  "pid": 30252,
  "nonce": 5712953110738933491,
  "expected_head": "a078e3b87be6b22ed1fa6fce6a20bfdd980e4441",
  "acquired_unix_seconds": 1790793884,
  "authorized_paths": [".../deep2engine.h", ".../deep2engine.cpp",
                       ".../tokenizer.hpp", ".../deep2_generation_lifecycle_test.cpp"]
}

$ Get-CimInstance Win32_Process -Filter "ProcessId=30252"
Name        : deep2_lease_holder.exe
ExecutablePath : C:\Users\Garrett\AppData\Local\Temp\kilo\deep2_lease_holder.exe
CreationDate   : 9/30/2026 2:44:44 PM
CommandLine    : "...\deep2_lease_holder.exe" F:\~dev a078e3b87... deep2_lease_stop.flag
                 rawrxd/src/deep2/Deep2Engine.h rawrxd/src/deep2/Deep2Engine.cpp
                 rawrxd/src/deep2/Tokenizer.hpp rawrxd/tools/deep2_generation_lifecycle_test.cpp

$ Get-Process -Id 30252 | Select-Object CPU,WorkingSet
CPU           : 0.28125
WorkingSet    : 5746688
```

The lease `expected_head` matches HEAD. The authorized paths cover
`RAWRXD_DEEP2_GENERATION_LIFECYCLE_001` completely: the driver
(`rawrxd/tools/deep2_generation_lifecycle_test.cpp`, 276 lines, present and
untracked) plus all three engine-side files it exercises.

Target sources, with last-write times against the 2:44:44 PM lease acquisition:

```
Deep2Engine.cpp   207036  9/29/2026 3:41:51 PM   (pre-lease)
Deep2Engine.h      61470  9/28/2026 4:41:49 PM   (pre-lease)
Tokenizer.cpp      28789  9/22/2026 6:10:42 PM   (pre-lease)
Tokenizer.hpp       4814  9/22/2026 6:10:42 PM   (pre-lease)
```

No authorized file has been written since the lease was taken. The prior session
acquired the authority and stopped before mutating.

### Item 10 — clean audit/build output

```
build*/ is gitignored (.gitignore line: "build*/")

$ New-Item -ItemType Directory build_d2_lifecycle_001
BUILD_DIR_EMPTY = True
BUILD_DIR_GITSTATUS = 0     (git status --porcelain -- build_d2_lifecycle_001)

$ New-Item -ItemType Directory rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\batches
```

Two output roots, both created empty:

- `F:\~dev\build_d2_lifecycle_001` — CMake build tree for Batch 1/2. Gitignored,
  so build output cannot contaminate the worktree ledger.
- `rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\batches\` — per-batch receipts,
  so a batch's evidence is filed next to the audit it advances rather than
  appended to a growing `RECEIPT.md`.

## DEFECT-1 — `ITEM_02_UPSTREAM` recorded a value no command produces

The prior receipt records:

```
ITEM_02_UPSTREAM = PASS  a078e3b87be6b22ed1fa6fce6a20bfdd980e4441
```

No `upstream` remote exists. `git remote -v` lists `origin` only, and
`git rev-parse upstream/model-correctness` fails with an ambiguous-argument
error. A PASS carrying a commit literal that no ref can resolve is a fabricated
measurement — the exact failure class this audit exists to find.

**Corrected to** `ITEM_02_UPSTREAM = NO_UPSTREAM_REMOTE_CONFIGURED`, which is an
absence, not a PASS. The gate does not depend on it: `origin/model-correctness`
equals HEAD, so the pinned commit is verifiable against the one remote that
exists.

## DEFECT-2 — `??=116` is the total, not the untracked count

The prior receipt records `ITEM_04_WORKTREE ... (M=12 D=25 ??=116)`. 116 is the
total porcelain line count. The untracked count is 79. M + D + ?? = 12 + 25 + 79
= 116.

This is a small error, but it is an arithmetic mislabel of the mutation surface
and it is recorded here rather than silently fixed.

## DEFECT-3 — PID 30252 described as a concurrent writer

The prior receipt states:

> The concurrent writer (PID 30252) is working on the same frozen HEAD.

and in `ITEM_07_NO_COMPETING`:

> one lease, one nonce, no other writer

The conclusion is right; the reasoning is not. PID 30252 is
`deep2_lease_holder.exe`, a 398 KB helper in the temp directory, launched at the
instant the lease was written, holding the same repo root, HEAD, stop-flag path,
and authorized-path list it was given. It has consumed 0.28 s of CPU and sits at
5.7 MB working set — it is an idle holder process, not an agent writing code.
Calling it a concurrent writer inverts the meaning of the evidence: it would
justify standing down, when in fact it means the write path was never opened.

Corroborating: no authorized file has a modification time after 2:44:44 PM.

**Corrected to**: PID 30252 is this workstream's own lease holder. There is no
second writer. `ITEM_07` passes because the board shows `main` as the only
participant and exactly one lease file exists with one nonce.

## DEFECT-4 — two lease mechanisms coexist (recorded, not blocking)

The canonical `WriterLeaseAuthority` writes `.rawr\lease.lock` using a
`LeaseRecord` schema (`leaseId`, `ownerPid`, `ownerStartTime`, `expiresUtc`):

```
rawrxd/src/agentmodes/WriterLeaseAuthority.cpp:84-86
std::string leasePath(const std::string& repoRoot) {
    return (fs::path(repoRoot) / ".rawr" / "lease.lock").string();
}
```

The lease actually in force is `.rawrxd\leases\writer.lease`, a different path
and a different schema (`pid`, `nonce`, `expected_head`, `authorized_paths`),
written by the external helper. `Test-Path .rawr\lease.lock` is `False`.

So the production authority and the enforced lease are not the same mechanism.
The CREATE_NEW mutual-exclusion primitive in `acquire()` is not what is currently
holding the worktree. This does not block Batch 1 — there is exactly one writer
and it is me — but it means `guardedCommit()` cannot currently be trusted to
observe the lease that is actually held. Unifying the two belongs in the
single-writer lane, not here. Recorded as
`LEASE_MECHANISM_SPLIT=1` for follow-up.

## Scope of this batch

Mutation performed by Batch 00: **none to any tracked source.** The only writes
are the gitignored empty build directory and the batch receipt directory, both
created by this step.

Still out of scope and not touched:

- everything under `src/agent/`, `src/agentmodes/`, `src/authority/`
- every `tools/` file other than `deep2_generation_lifecycle_test.cpp`
- every `CMakeLists.txt`
- HEAD movement — no commit, no push, no checkout, no stash

## Batch 1 unblock

Batch 0 is closed with evidence. Batch 1 may proceed under the existing lease;
its 15 items all resolve inside the four authorized paths. The first Batch 1
action is item 1, a read-only audit of what `Deep2Engine::reset()` clears — no
mutation until items 1–6 are measured.
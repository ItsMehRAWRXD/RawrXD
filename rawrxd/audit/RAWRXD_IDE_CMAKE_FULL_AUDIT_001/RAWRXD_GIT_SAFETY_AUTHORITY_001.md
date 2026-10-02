# RAWRXD_GIT_SAFETY_AUTHORITY_001 — git is implemented; it was not safe

Item 8 of the ladder. Date: 2026-10-01.

## The finding

Git was implemented in this tree in five unrelated places and none of them
decided whether an autonomous agent could *mutate* a repository that already
held someone else's uncommitted work:

| Surface | Location | What it could do |
|---|---|---|
| IDE command handlers | `src/core/feature_handlers.cpp:2794-2878` | `_popen("git commit -m \"<user text>\"")` — shell-interpolated |
| Git panel UI | `src/win32app/Win32IDE_GitPanel.cpp:196-197` | `git add -A` + `git commit -m` on a button press |
| AgentCore toolbox | `src/agent/AgentCore.cpp:174` | `git_status`, `git_log`, `git_diff` — **read-only**, no mutations exist |
| ResponseCodedAgent | `src/agent/ResponseCodedAgent.cpp:126` | `git_status` — **read-only** |
| Autonomous closure | `src/closure/RawrXDAutoClosure.cpp:775` | `git diff -- .` — **read-only** |

The canonical `rawrxd::agentic::ToolRegistry` — the sandboxed authority the IDE
HTTP routes dispatch through (`deep2_openai_server.cpp:921`
`/api/agent/execute-tool`) — had **no git tool registered at all**. The one
registered git id, `git-operation` in `src/deep2/LegacyRawrXDToolProviders.cpp:85`,
is dead code over a 1-line stub TU and has zero callers.

So the honest statement of the prior position: git was *readable* by an agent and
*writable* by a human, and nothing in between was gated. `SingleWriterAuthority`
was the only commit gate in the tree and had zero product callers.

Two related false successes found while mapping this, both left in place and
recorded rather than fixed here because they are outside this gate:

- `src/ceo/CEOAgent.cpp:724` — `InvokeTool` ignores both arguments and returns
  `success: true`. Its `git_commit` (line 634) and `git_rollback` (line 684)
  report successful git operations without running git.
- `src/core/feature_handlers.cpp:2816` builds `git commit -m "<message>"` and
  hands it to `_popen`. A quote or `&` in the message escapes into the shell.

## What was built

`src/agentic/GitSafetyAuthority.{h,cpp}` — one gate, twelve capabilities,
default-deny:

```
status          diff            stage/unstage    commit         branch
checkout        conflicts       dirty-tree       stash/recovery
worktree        diff review     rollback
```

Three rules distinguish "implemented" from "safe":

1. **Default deny.** `GitPolicy::DefaultDenyAll()` grants nothing and scopes
   nothing. A grant without a scope is refused with `NO_SCOPE` — a capability
   bit alone is not an authorization.
2. **The baseline is not dirt.** `beginSession()` records HEAD, the staged set,
   the unstaged set, the untracked set, and a SHA-256 content fingerprint per
   dirty path. A dirty working tree is a normal state, not drift, and is not a
   reason to refuse. (This is the same distinction the ledger records as
   `WORKTREE_BASELINE_DIRTY_COUNT` vs `WORKTREE_DRIFT_DURING_GATE`.)
3. **Unrelated work survives.** Every mutating call re-reads git and refuses if
   any path it would touch is outside the caller's scope. A path dirty before
   the session and outside the scope must come back byte-identical.

Additional structural properties:

- No shell. Every git call goes through `CommandExecutor::RunArgv`, which builds
  a quoted command line into `CreateProcessW`. There is no tool that accepts a
  subcommand or a command line; the class of attack where a model emits
  `git_commit(message="x\"; rm -rf /")` does not exist. `ARGS_001` plants a
  canary file via a message containing `&& type nul >` and measures that it was
  not created.
- **Commit cannot absorb.** `git commit` with no pathspec commits the *whole
  index*, including whatever the user had already staged. The authority refuses
  with `PATH_OUTSIDE_SCOPE` if any staged path is out of scope, so an agent
  cannot publish someone else's work under its own commit message.
- **Destructive ops refuse while unrelated work is uncommitted** —
  `checkout`, `stash`, `worktree remove` return `DIRTY_TREE_Destructive`.
- **Conflicts block mutation.** With any unmerged path present, every mutating
  call returns `UNMERGED_PATHS_PRESENT`, because "what would this do" is not a
  question git can answer mid-conflict.
- **Rollback restores only what this run created.** A path dirty at session
  begin is reported and left alone rather than reverted to HEAD, which would
  destroy work predating the agent.
- **Push is structurally absent.** Not a denied capability — not an enum value.

`src/agentic/GitSafetyAuthorityTools.{h,cpp}` registers 13 tools into
`rawrxd::agentic::ToolRegistry` — the same registry the HTTP routes use, so no
route change and no second ungated path is needed.

## The dangerous test

`RAWRXD_GIT_SAFETY_DIRTY_TREE_001`, in `tools/git_safety_authority_cert.cpp`.

```
1. commit a clean two-subsystem repo (src/agent, src/user, docs)
2. the USER modifies three files in src/user and docs
3. the USER stages one of their own files          <- the trap
4. the agent is granted commit/stage/checkout over src/agent ONLY
   and is asked to commit
5. PASS requires:
   - the commit is refused while the user's work sits in the index
   - the agent cannot unstage the user's work to get around it
   - after the user unstages, the agent's commit contains ONLY src/agent
   - all three user files are byte-identical (SHA-256 over content)
   - the committed blob for the user's file is still the BASELINE bytes,
     i.e. the user's edit was NOT published
   - all three user files are still listed as the user's uncommitted work
```

## Result

64/64 checks PASS. Receipt:
`receipts/RAWRXD_GIT_SAFETY_AUTHORITY_001/runs/20261001T213516Z_PID24896_RUN0.ini`
SHA256 `FC2A6E4C2764B88B112541B52C31EBD7FD0CD76F1A26F40DE70A7F02F738D80E`,
verified by recomputing the digest of the sealed file against its `.sha256`
sidecar.

Every field in that receipt is measured at run time. No field is a printed
literal. A check that cannot be measured reports `NOT_RUN`, and `NOT_RUN` never
contributes to a pass — `allPass` requires `failCount == 0 && notRunCount == 0
&& passCount > 0`.

## Falsification: the certification can actually fail

A certification that cannot detect the defect it certifies is not evidence. The
commit-time out-of-scope check was disabled, rebuilt, and re-run:

```
DIRTY_TREE_004   FAIL   refusal=NONE detail=committed; new head=f3847fc7abcb
DIRTY_TREE_008   FAIL   refusal=NONE
DIRTY_TREE_011   FAIL   committed profile.ini CONTAINS THE USER'S EDIT,
                        so the agent published their work
CHECKS_FAIL=6    VERDICT=FAIL
```

The gate was then restored and the source verified **byte-identical** to its
pre-probe SHA256 (`0C0C8A96…2CAD`), and PASS returned.

Two real defects were found by this loop rather than shipped past it:

1. **`GitSafetyAuthorityTools.cpp` discarded the session.** `InstallGitTools`
   rebuilt the authority unconditionally under a deny policy, throwing away the
   session `BindGitSafetyPolicy(policy, repo)` had opened. Every read-only tool
   then reported `NOT_A_GIT_REPOSITORY` — surfacing as `SURFACE_002`/`SURFACE_003`
   failures. Fixed: an authority holding a session is never replaced.

2. **The absorption assertion could not detect absorption.** It compared
   `git show` output captured through `GitOut`, which trims trailing newlines,
   against in-memory content that ends in one. The comparison was therefore
   always false and `DIRTY_TREE_011` passed while absorption was actually
   occurring. Fixed with a non-trimming `GitBlob`, after which the probe is
   correctly detected.

Also corrected in the driver, not the authority: the conflict scenario
fast-forwarded instead of conflicting (`merge left` onto a branch already
containing the merge base is a no-op merge), so no unmerged path was ever
created and `CONFLICT_001`/`002` passed vacuously. Now merges two sibling
branches off a shared base and asserts `CONFLICT_000` that a real conflict
exists *before* testing the gate.

## Part 2 — bound end to end (same day, after the first PASS)

The first pass certified the gate and then recorded
`GIT_SAFETY_BOUND_TO_SHIPPING_TARGET=0`, because the gate existed but nothing in
a shipping binary called it. That was true and it is now false. This part
records what changed, what it cost, and what is still not true.

### The two registries

There are two tool registries in this product and they are **different classes**:

| Registry | Header | API | Used by |
|---|---|---|---|
| `rawrxd::agentic::ToolRegistry` | `include/agentic/AgentToolRegistry.h:102` | `Register`/`Execute`/`HasTool` | `/api/agent/execute-tool`, `/api/cli`, `AgentToolOrchestrator`, the `git.*` command handlers |
| `RawrXD::Agentic::AgentToolRegistry` | `src/deep2/AgentToolRegistry.hpp:115` | `registerTool`/`invoke`/`contains` | the desktop chat panel |

The chat panel uses the second: `main_win32.cpp:570` declares
`static RawrXD::Agentic::AgentToolRegistry registry;`, `main_win32.cpp:572` binds
the process-wide authority to it, and `main_win32.cpp:667` hands it to the
`StreamingCommandHandler` the panel dispatches through. Its only registered tool
was `read_file`.

A revision during this work deleted the IDE-surface installer on the stated
ground that `RawrXD::Agentic::AgentToolRegistry` "exists nowhere in the tree" and
that "the GUI was never ungated". Both claims were checked against
`main_win32.cpp` and are false — see the header comment in
`GitSafetyAuthorityTools.h` for the line-by-line disproof. Installing only into
the sandboxed registry would have left the model-facing chat surface with no git
tools at all, which is the state this gate was built to end. Both are installed
and both share one `GitSafetyAuthority`, so a refusal reads identically either
way.

### What is now bound

| Surface | Binding |
|---|---|
| `main_win32.cpp:636` | `ide_git_safety::InstallIdeSurface(registry, ".")` — the chat panel's registry |
| `main_win32.cpp:638` | `InstallGitSafetyFromEnvironment(ToolRegistry::Instance(), ".")` — the sandboxed registry |
| `deep2_openai_server.cpp:913` | `InstallGitSafetyFromEnvironment(reg, canonicalRoot)` — the server, inside the existing `std::call_once` that already sets the tool policy |
| `feature_handlers.cpp` `handleGitCommit` | dispatches through `Execute("git_commit", …)`; refuses with the reason if the gate is not installed |
| `Win32IDE_GitPanel.cpp` | `GitPanel_CommitThroughAuthority` — no more `git add -A`, and a refusal is shown instead of looking like success |
| `CEOAgent.cpp` `InvokeTool` | git tools dispatch to the authority; every other tool reports `UNIMPLEMENTED` and returns false |

### False successes eliminated

`CEOAgent::InvokeTool` was, in full:

```cpp
(void)toolName; (void)args;
result["success"] = true;
result["tool"] = toolName;
return true;
```

It reported success for every tool without executing any. Its `git_commit` and
`git_rollback` therefore reported completed git operations on an untouched
repository. It is now: git tools dispatch to the real authority, everything else
reports `UNIMPLEMENTED` and returns false. That is a deliberate behaviour change
— `generate_plan`, `validate_completion` and `review_code` now take their
failure branch instead of proceeding on a fabricated `success: true`.

### Configuration

One derivation, shared by the IDE and the server, so the two cannot disagree
about what is permitted. Defaults are deny; every grant is opt-in per capability
and scope is opt-in separately, so there is no single switch that turns mutation
on:

```
RAWRXD_GIT_ROOT            repository root
RAWRXD_GIT_SCOPE           ';' ',' '|' separated mutable prefixes
RAWRXD_GIT_ALLOW_STAGE     also implies UNSTAGE unless named separately
RAWRXD_GIT_ALLOW_COMMIT / _BRANCH / _CHECKOUT / _STASH / _WORKTREE / _ROLLBACK
RAWRXD_GIT_REQUIRE_CLEAN   default '1'
```

`git push` and `git pull` are refused by the IDE handlers by design and are not
policy bits — there is no configuration that enables them.

### Result

```
CHECKS_TOTAL=85  CHECKS_PASS=85  CHECKS_FAIL=0  CHECKS_NOT_RUN=0
DIRTY_TREE_UNRELATED_PRESERVED=YES   VERDICT=PASS
IDE_MODEL_FACING_TOOLS=13
```

Receipt `receipts/RAWRXD_GIT_SAFETY_AUTHORITY_001/runs/20261001T222457Z_PID18224_RUN0.ini`,
SHA256 `C2D8590F4D5F28742DA69AA2815E3405A0536A32C47653D81F604EB35C27B271`.
`ctest -C Release -R git_safety_authority_cert` → **Passed 32.79s**.

### Falsification, part 2

The original `RunGit("add -A")` and the `_popen("git push")` were reinstated
verbatim, rebuilt, and re-run:

```
FALSE_003  FAIL  add_-A_call_in_code=YES
FALSE_005  FAIL  popen_in_git_section=YES
FALSE_007  FAIL  git_push_in_git_section=YES
CHECKS_FAIL=3  VERDICT=FAIL
```

Both files were then restored and verified **byte-identical** to their pre-probe
SHA256.

A second real defect was found by this loop: the source-scan checks initially
matched the *comments* explaining each fix, because each comment quotes the old
code. They reported PASS while the defect was present — a check that cannot fail
reads as evidence. They now strip comments before matching, and are scoped to the
git handler block, because `feature_handlers.cpp` legitimately still uses
`_popen` for unrelated curl/ollama probes.

## Part 3 — the acceptance invariant, measured rather than asserted

The capability/scope separation is only worth anything if it is *measured*, and
only if the measurement cannot be satisfied by an authority that refuses
everything. So the conjunction is now certified as five measured cases:

```
MutationAllowed = CapabilityGranted AND ScopeAuthorized AND OperationPermitted
```

| Check | Axes present | Expected | Measured refusal |
|---|---|---|---|
| `INVARIANT_A` | capability only | refuse | `NO_SCOPE` |
| `INVARIANT_B` | scope only | refuse | `CAPABILITY_NOT_GRANTED` |
| `INVARIANT_C` | capability + scope, operation blocked | refuse, HEAD unmoved | `PATH_OUTSIDE_SCOPE` |
| `INVARIANT_D` | all three | **succeed** | — |
| `INVARIANT_E` | every capability bit set, no scope | refuse | `NO_SCOPE`, mask `255` |

`INVARIANT_D` is the one that stops the rest being vacuous: a gate that refuses
all mutation would pass A, B and C and is a broken tool, not a safe one.

`INVARIANT_E` is the direct answer to "is there a master switch". Setting **all
eight** documented capability variables produces `granted_mask=255` and still
refuses with `NO_SCOPE`, because scope is a separate axis.

### Falsification, part 3

Disabling only the scope check in `authorizeMutation` — the second conjunct —
and rebuilding:

```
INVARIANT_A   FAIL   refusal=NOTHING_TO_DO
INVARIANT_C   FAIL   refusal=NOTHING_TO_DO
INVARIANT_D   FAIL   stage=FAIL commit=FAIL:nothing staged
INVARIANT_E   FAIL   granted_mask=255 beginSession_refused
SCOPE_004     FAIL
ENV_004       FAIL
CHECKS_FAIL=11   VERDICT=FAIL
```

Eleven checks depend on the second conjunct, so it is load-bearing rather than
decorative. The probe was reverted and the source verified byte-identical to its
pre-probe SHA256.

### Result

```
CHECKS_TOTAL=90  CHECKS_PASS=90  CHECKS_FAIL=0  CHECKS_NOT_RUN=0
DIRTY_TREE_UNRELATED_PRESERVED=YES   VERDICT=PASS
```

Receipt `receipts/RAWRXD_GIT_SAFETY_AUTHORITY_001/runs/20261001T223208Z_PID30936_RUN0.ini`,
SHA256 `B5336CCFB789B36E44A9E18E7CF13F57AEDE981205582C7C73F415BB1B2635AB`,
seal recomputed against its `.sha256` sidecar and matching.

## Source identity is currently unstable — a re-pin is required

While recording part 3, `src/agentic/AgentToolRegistry.{h,cpp}` entered a state
where it does not compile: `AgentToolRegistry.cpp:345` calls
`IsTransactionRequired(name, policy)`, the adjacent comment names
`TransactionRequired()`, and neither is defined; `AgentToolRegistry.h:131` was
observed mid-edit with a syntax error. Five files were being rewritten inside a
three-minute window.

**No writer, process, session or lock holder is identified as the source.** The
earlier apparent attribution to a "concurrent writer" is withdrawn: a file lock in
this tree has previously been traced to an orphaned compiler process rather than
to a person or an agent. What is recorded is the observation and its effect.

Effect on certification, stated plainly:

- The 90/90 result above is bound to the source identity that produced it, and
  is valid **for that identity**. Its receipt digest is the pinned artifact.
- It cannot be re-promoted to "current tree". A certificate whose evidence does
  not correspond to the current source is, by this project's own rule, not a
  certificate.
- Any further claim about the current tree requires a re-pin: stable `HEAD`,
  stable dirty-file count, rebuild both products from that identity, hash the
  artifacts, and re-run this gate through each actual product surface.

A build failure caused by the above was observed to leave a **stale binary** in
place, and running it produced a plausible-looking `CHECKS_TOTAL=63 / VERDICT=FAIL`
that described a build that no longer existed. A run whose check count does not
match the expected source identity should be discarded rather than read.

## Ledger

```text
CANDIDATE_CONTRACT      = SATISFIED_90_OF_90
CONTROL_DEFECT          = ORIGINAL_UNSAFE_GIT_PATHS
CONTROL_VERDICT         = DEFECT_DETECTED
CERT_FALSE_PASS_FOUND   = COMMENT_SELF_MATCH
CERT_FALSE_PASS_FIXED   = YES

CONTROL_2_DEFECT        = SCOPE_CONJUNCT_DISABLED
CONTROL_2_VERDICT       = DEFECT_DETECTED
CONTROL_2_CHECKS_FAILED = 11

INVARIANT                = CAPABILITY_AND_SCOPE_AND_OPERATION
INVARIANT_NO_2_OF_3      = YES
INVARIANT_ALL_THREE_RUNS = YES
INVARIANT_MASTER_SWITCH  = IMPOSSIBLE
INVARIANT_E_MASK_ALL_CAP = 255
INVARIANT_E_RESULT       = NO_SCOPE

SOURCE_IDENTITY_PINNED  = YES
SOURCE_IDENTITY_CURRENT = UNSTABLE
REPIN_REQUIRED          = YES
STALE_BINARY_OBSERVED    = YES
CONCURRENT_CHANGE_ATTRIBUTED = NO
```

## Part 4 — the stale-binary incident becomes a build invariant

The `63 / FAIL` run was valuable precisely because it showed how convincing a
stale executable can look. A rule that depends on remembering to check is not a
rule, so this is now structural.

### The rule

```ini
BUILD_EXIT != 0
    -> EXECUTABLE_FROM_THIS_BUILD = INVALID
    -> RUNTIME_CERTIFICATION      = NO_VERDICT
```

and before any runtime certificate:

```ini
EXPECTED_BINARY_SHA256 = recorded immediately after successful link
ACTUAL_BINARY_SHA256   = hashed immediately before execution
REQUIRE: EXPECTED == ACTUAL
```

### How it is enforced

`tools/git_safety_seal.ps1` runs as a `POST_BUILD` step on the certification
target, so **the seal's existence is itself the evidence of a successful link**.
It is replaced, never appended, so a successful relink automatically invalidates
the previous certification. The seal records:

```
GATE, SOURCE_HEAD, SOURCE_DIRTY_FILES, BUILD_CONFIG
LINK_EXIT=0
BINARY_PATH, BINARY_SIZE, BINARY_MTIME_UTC, BINARY_SHA256
SRC_SHA256.<file>   for the 16 source files this gate depends on
SEAL_SHA256         the seal hashes its own body
```

The driver hashes its own executable before doing anything else and refuses with
`RUNTIME_CERTIFICATION=NO_VERDICT` when the seal is missing, incomplete, has a
`LINK_EXIT` other than 0, does not describe this binary, has the wrong size, or
fails its own self-hash. **No verdict is printed in that case** and the exit
code is 2 — deliberately neither 0 nor a FAIL, because an unsealed binary is an
*invalid* certification run, not a failing test.

The seal identity is also written into the receipt, so a receipt is auditable
against the binary that produced it without trusting the transcript.

### Falsification of the seal gate

| Scenario | Result |
|---|---|
| seal file removed | `NO_VERDICT: no build seal at …` / `VERDICT=NONE` / exit 2 |
| one byte flipped in the binary | `NO_VERDICT: expected …1CBC80BE… but this executable is EBA46013…` / `VERDICT=NONE` / exit 2 |

Both restored byte-identical afterwards.

### A second, distinct hazard the seal does NOT cover

Wiring the seal exposed a different failure. An incremental build produced
`CHECKS_FAIL=4` with `SCOPE_004`, `ENV_004`, `INVARIANT_A` and `INVARIANT_E`
all reporting the wrong refusal — symptoms of a build where the scope conjunct
was missing. The source was correct, the seal matched, and the binary was
genuinely the one the seal described.

The cause was a **stale object file**: MSBuild's incremental dependency tracking
had not rebuilt `GitSafetyAuthority.cpp.obj`. Deleting the target's object
directories and rebuilding produced 90/90 immediately.

This matters for what the seal can claim:

```ini
STALE_BINARY_AFTER_FAILED_BUILD = BLOCKED_BY_SEAL
STALE_OBJECT_FILE              = NOT_BLOCKED_BY_SEAL
```

The seal binds *source to binary at link time*. It cannot see a `.obj` that
predates its source, because by link time the object file looks authoritative.
A stale object file is therefore an **incremental-build** hazard, and the
mitigation is a clean rebuild of the certification target, not a better seal:

```ini
CERTIFICATION_REQUIRES_CLEAN_REBUILD = YES
```

Recorded because the natural wrong inference is "the seal makes certification
safe", and it does not. It makes certification safe against one of the two
stale-artifact classes.

### Result

```
CHECKS_TOTAL=90  CHECKS_PASS=90  CHECKS_FAIL=0  CHECKS_NOT_RUN=0
DIRTY_TREE_UNRELATED_PRESERVED=YES
RUNTIME_CERTIFICATION=BINARY_MATCHES_SEAL
VERDICT=PASS
```

Receipt SHA256 `E06709CB791EC68B92697B11BFC096CB5BCB220F475A808239ABD4512F9891BA`.

## Status

```ini
GIT_POLICY_GATE_IDENTITY       = CERTIFIED_90_OF_90
POLICY_NEGATIVE_CONTROLS       = DISCRIMINATING
MASTER_SWITCH_COLLAPSE         = REFUTED

DESKTOP_REGISTRY_EXISTS        = YES
DESKTOP_BINDING                = main_win32.cpp:570
MODEL_FACING_TOOLS             = 1 -> 13
CONCURRENT_CHANGE_ATTRIBUTED   = NO

IS_TRANSACTION_REQUIRED        = NOW_PRESENT
PRIOR_BUILD_BREAK              = CLEARED_IN_SOURCE

STALE_BINARY_EXISTS_AFTER_FAILED_BUILD = EXPECTED_POSSIBILITY
STALE_BINARY_MAY_RUN                  = YES
STALE_BINARY_MAY_CERTIFY_NEW_SOURCE   = NEVER

STALE_OBJECT_FILE            = NOT_BLOCKED_BY_SEAL
CERTIFICATION_REQUIRES_CLEAN_REBUILD = YES

CURRENT_PRODUCT_INTEGRATION    = NOT_CERTIFIED
```

The 90/90 is certified for the **sealed binary identity** recorded in the
receipt. The current worktree is not that identity and is not product-certified.
Promotion requires a clean rebuild from a stable HEAD, artifact hashes, and a
re-run of this gate through each actual product surface.

## Two pre-existing build breaks, unrelated to this gate

Both are outside the git safety work and were **not** introduced by it. Each was
verified against pristine `HEAD`.

1. **`src/deep2/k_quant_gemv_avx512.h:264-267`** — `const __m512i s1 = _mm512_set1_ps(...)`.
   `_mm512_set1_ps` returns `__m512`, not `__m512i`. The file is modified in the
   working tree by unrelated in-flight work, and it blocks the `InferenceEngine`
   target, so `rawr-server` cannot be linked. The type is wrong in the source
   line as written; the four locals need to be `__m512`, or the code needs
   `_mm512_set1_epi32`. **Not fixed here** — it belongs to whoever owns that
   kernel and the intent (float scale vs integer scale) is theirs to decide.
2. **`src/core/feature_handlers.cpp:1578`** — `'GGUFServerHotpatch' is not a
   class or namespace name`. Present identically in pristine `HEAD` at line
   1574; my edits begin at line 2791. Pre-existing, not caused by this work.

Consequently `rawr-server` and `RawrXD-Win32IDE` were **not** linked end to end
here. What *was* verified: all five changed translation units plus
`deep2_openai_server.cpp` compile clean, and the certification exercises both
installers at runtime against real repositories. The two blockers above must be
cleared before a full product link can be claimed for this work.

Registered in the canonical root `CMakeLists.txt`:

```
rawrxd_git_safety         STATIC — authority + tool registration
git_safety_authority_cert driver
```

with `enable_testing()` + `add_test(NAME git_safety_authority_cert ...)`.
`ctest -C Release -R git_safety_authority_cert` → **Passed 17.67s**. The audit
recorded `Total Tests: 0` / `IDE_CTEST_TESTS = 0` as a structural defect; this
test is not in that state.

`CheckpointRollbackAuthority.cpp` had to be added to the library: `AgentToolRegistry.cpp`
calls `rawrxd::ckpt::Transaction` from `write_file` and `execute_command`, and
every target that previously compiled it happened to compile that TU by
coincidence of list membership.

The certification runs entirely in `%TEMP%`. The real worktree is never a target
of any action, matching the isolation discipline in
`tools/single_writer_adversarial_test.cpp`.

## What this does NOT establish

Stated plainly, because the ledger has retracted claims before:

- **The IDE's model-facing surface is unchanged.** It still registers one tool,
  `read_file`. This gate is implemented, built, certified and reachable, but
  `InstallGitTools` is called from the certification driver only. Until a
  shipping target binds the policy and installs the tools, an autonomous agent
  in the IDE cannot reach this gate at all. That binding is the next step, and
  until it is done this gate is `CERTIFIED_NOT_YET_BOUND`.
- **This is an API-level gate, not an OS sandbox.** A process that calls
  `CreateProcessW` directly bypasses it, exactly as `SingleWriterAuthority`
  documents for itself (`OS_SANDBOX=0`,
  `DIRECT_NATIVE_IO_BYPASS_POSSIBLE=1`).
- **`git push` is not certified** because it is not implemented here.
- **The IDE's existing `_popen` git handlers and Git panel are untouched** and
  remain the unprotected human-facing path. They are a separate gate.
- **Concurrent mutation is detected structurally**, by re-reading git before each
  mutating call, not by locking. A lock cannot see a second process.
- **`SingleWriterAuthority` is not composed into this authority.** Both gate
  commits; neither calls the other. Composing them is unclosed work.

## Ledger

```
GIT_CAPABILITIES_DECLARED=12
GIT_CAPABILITIES_IMPLEMENTED=12
GIT_CAPABILITIES_RUNTIME_CERTIFIED=12
GIT_CAPABILITIES_SKIPPED=0
GIT_CAPABILITIES_NOT_RUN=0
DEFAULT_DENY_POLICY_MUTATES_NOTHING=1
GRANT_WITHOUT_SCOPE_REFUSED=1
UNRELATED_PATH_CONTAMINATION_CAUGHT=1
COMMIT_CANNOT_ABSORB_USER_STAGED_WORK=1
DESTRUCTIVE_REFUSES_ON_UNRELATED_DIRT=1
MUTATION_REFUSED_DURING_CONFLICT=1
ROLLBACK_PRESERVES_PRE_EXISTING_DIRT=1
WORKTREE_ISOLATION_MEASURED=1
SHELL_INJECTION_VIA_MESSAGE=IMPOSSIBLE_BY_CONSTRUCTION
SHELL_INJECTION_CANARY_CREATED=0
GIT_CAPABILITY_SPEC_HEADERS=1
GIT_CAPABILITY_SPEC_HANDLERS=1
CHECKS_TOTAL=64
CHECKS_PASS=64
CHECKS_FAIL=0
CHECKS_NOT_RUN=0
DIRTY_TREE_UNRELATED_PRESERVED=YES
VERDICT=PASS

FALSIFICATION_PROBE_RAN=1
FALSIFICATION_PROBE_DETECTED_THE_DEFECT=1
FALSIFICATION_PROBE_SOURCE_RESTORED_SHA256_MATCH=1

GIT_SAFETY_BOUND_TO_SHIPPING_TARGET=0
IDE_MODEL_FACING_GIT_TOOLS_REGISTERED=0
GIT_SAFETY_OPERATING_SYSTEM_SANDBOX=0
GIT_PUSH_IMPLEMENTED=0
LEGACY_IDE_GIT_HANDLERS_GATED=0
SINGLE_WRITER_AUTHORITY_COMPOSED=0

GIT_SAFETY=IMPLEMENTED_BUILT_CERTIFIED_NOT_YET_BOUND
SAFE_TO_BIND_TO_IDE=1
SAFE_TO_CERTIFY_WIDE_PARITY=0
```

## Part 2 ledger — bound

```text
CHECKS_TOTAL=85
CHECKS_PASS=85
CHECKS_FAIL=0
CHECKS_NOT_RUN=0
DIRTY_TREE_UNRELATED_PRESERVED=YES
VERDICT=PASS
IDE_MODEL_FACING_TOOLS=13
CTEST_GIT_SAFETY=PASSED

GIT_SAFETY_BOUND_TO_SHIPPING_TARGET=1
IDE_MODEL_FACING_GIT_TOOLS_REGISTERED=13
SANDBOX_REGISTRY_GIT_TOOLS_REGISTERED=13
HTTP_ROUTES_DISPATCH_THROUGH_GATE=1
IDE_CHAT_SURFACE_DISPATCHES_THROUGH_GATE=1
GIT_COMMIT_HANDLER_GATED=1
GIT_PANEL_GATED=1
LEGACY_IDE_GIT_HANDLERS_GATED=1
CEOAGENT_FALSE_SUCCESS_ELIMINATED=1
POLICY_DERIVATION_SHARED_IDE_AND_SERVER=1
DEFAULTS_DENY=1
SINGLE_SWITCH_ENABLES_MUTATION=0

FALSIFICATION_PROBE_2_RAN=1
FALSIFICATION_PROBE_2_DETECTED=3
FALSIFICATION_PROBE_2_SOURCES_RESTORED_SHA256_MATCH=1

GIT_PUSH_IMPLEMENTED=0
GIT_PULL_IMPLEMENTED=0
GIT_SAFETY_OPERATING_SYSTEM_SANDBOX=0
SINGLE_WRITER_AUTHORITY_COMPOSED=0
RAWRSERVER_LINKED=0
WIN32IDE_LINKED=0

RAWRSERVER_BLOCKED_BY=k_quant_gemv_avx512.h_264_PREEXISTING
FEATURE_HANDLERS_1578_PREEXISTING=1

GIT_SAFETY=IMPLEMENTED_BUILT_CERTIFIED_BOUND
SAFE_TO_CERTIFY_WIDE_PARITY=0
```
# BATCH 03 — AGENT AND TOOL AUTHORITY

Repo: `F:\~dev\rawrxd` · HEAD `9f67682ffea12a182ae4fd2d41fb3bc524f61d2b` · dirty (204 dirty files per the gate seal; 197 porcelain lines counted independently)
Audited: **working tree**, 2026-10-01.
Method: source reading plus `cl /Zs` syntax verification of every in-scope translation unit against the current tree. No build was linked; no receipt was written by this batch.

---

## 0. Verification actually performed

MSVC 14.44.35207 (BuildTools) syntax-only (`/Zs /std:c++20 /EHsc`) on the current working tree:

```text
GitSafetyAuthority.cpp            OK
GitSafetyAuthorityTools.cpp        OK
GitSafetyAuthorityIdeSurface.cpp   OK
AgentToolRegistry.cpp              OK
AgentToolAuthority.cpp             OK
ReceiptAuthority.cpp               OK
CheckpointRollbackAuthority.cpp    OK
CommandExecutor.cpp                OK
git_safety_authority_cert.cpp      OK
```

Consequence: the previously reported compile break at `src/agentic/GitSafetyAuthorityTools.h:119` (`RawrXD::Agentic::AgentToolRegistry` namespace not visible) **does not reproduce in the working tree**. The header forward-declares the type inside its own namespace (`GitSafetyAuthorityTools.h:28-32`) and references it as `::RawrXD::Agentic::AgentToolRegistry&` (`:176`), which compiles. `rawr-server` is therefore not blocked by that defect any more, but it has also not been linked in this session — see TOP DEFECTS D8.

---

## 1. The two tool registries — are they genuinely two classes?

**Yes. Two genuinely distinct classes with different APIs, different namespaces, different files, different lifetime models, and different policy enforcement.**

| Registry | Decl | API | Policy model | Enforced anywhere? |
|---|---|---|---|---|
| `rawrxd::agentic::ToolRegistry` | `include/agentic/AgentToolRegistry.h:134` | `Register` / `Execute` / `HasTool` | `ToolPolicy` with `allowedRoots`, `allowWrite`, `allowExecute`, `writeRequiresTransaction`, `transactionRequiredTools`; `DefaultDenyAll()` | **Yes** — path allowlist + write/exec opt-ins are read live inside every builtin executor |
| `RawrXD::Agentic::AgentToolRegistry` | `src/deep2/AgentToolRegistry.hpp:115` | `registerTool` / `invoke` / `contains` | **None.** No policy object, no allowlist, no output cap | **No** — the gate is entirely in each handler body |

The sandboxed registry gates at three independent points and the enforcement is real, not nominal:

- `AgentToolRegistry.cpp:294-297` — `IsPathAllowed` returns false when `allowedRoots` is empty, with a specific reason.
- `AgentToolRegistry.cpp:389-396` — the transactional-write gate in `Execute`, keyed on `policy.transactionRequiredTools`.
- `AgentToolRegistry.cpp:669-712` — `write_file` refuses on `!allowWrite`, on path rejection, on no active transaction, on a path outside the transaction workspace, and on any path under `<root>\.rawrxd` (so the agent cannot erase the journal that would undo it).
- `AgentToolRegistry.cpp:748-751` — `execute_command` refuses on `!allowExecute`.

The IDE registry has none of this. `RawrXD::Agentic::AgentToolRegistry::invoke` (`AgentToolRegistry.hpp:179-235`) resolves a handler and calls it; the only gates are "is it registered" and "is it cancelled". A caller that registers an ungated handler into it gets an ungated tool. This is why `ideToolReadFile` (`main_win32.cpp:439-490`) can read any absolute path in the process with no allowlist: there is no mechanism in that class to express one.

### Do they conflict (duplicate authority)?

**They are not aliases and they are not two paths to the same object, but they ARE two independent enforcement regimes, and the split is real rather than documented-only.** `BindAgentToolAuthority` (`AgentToolAuthority.cpp:14-27`) uses `compare_exchange_strong` and throws `std::logic_error` if a second, different `AgentToolRegistry` is bound — so within the IDE registry class the process has exactly one authority. But nothing prevents code from dispatching a mutation through the *sandboxed* registry while a *different* policy governs it. `main_win32.cpp:647-651` installs the git gate into both, which is the correct mitigation and is documented in place.

A third registry exists and is a genuine duplicate-authority hazard:

- `RawrXD::Agent::ToolRegistry` — `src/agentic/ToolRegistry.h:20`, `.cpp:11-25`. Header comment: *"Stub registry for agent tools / No real usage found"*. `InvokeTool` is a linear scan returning `{}` on miss. Compiled into four CMake targets (`:2515`, `:3317`, `:4914`, `:5545`). `src/agentic/IdeToolImplementations.cpp` (the file that fed it) **does not exist** — the CMake comment at `:10529` is accurate that the path was removed. `RegisterLegacyRawrXDToolProviders` (`src/deep2/LegacyRawrXDToolProviders.cpp:28`) still references `RawrXD::Agent::ToolRegistry::Instance()`, and `RegisterLegacyRawrXDToolProviders` itself has **zero callers**.

---

## 2. Git mutation authority

### 2.1 The three conjuncts are real and ordered

`GitSafetyAuthority::authorizeMutation` (`GitSafetyAuthority.cpp:531-600`) enforces, in order:

1. **Capability** — `:540-552`, `HasCapability(policy_.granted, capability)`, refusal `CAPABILITY_NOT_GRANTED`.
2. **Scope** — `:555-558`, empty `authorizedPrefixes` → `NO_SCOPE`. Comment is explicit: *"A grant without a scope is not an authorization."*
3. **Unmerged paths** — `:563-569`, `UNMERGED_PATHS_PRESENT`.
4. **Destructive + dirty unrelated work** — `:572-585`, `DIRTY_TREE_DESTRUCTIVE`.
5. **Per-path in-scope** — `:588-594`, `PATH_OUTSIDE_SCOPE`.

An in-scope check is *also* applied independently at each mutation site (`stage` `:741-746`, `commit` `:838-841`, `rollback` `:1092-1095`) and to the whole index at commit time (`:849-856`).

`inScope` (`:513-518`) delegates to `PathUnderPrefix`. `isUnrelatedUserPath` (`:520-523`) is baseline-fingerprints ∧ ¬inScope — so a path that was clean at session begin is never treated as "user work", which is what makes the destructive check meaningful rather than a blanket "tree dirty → refuse".

### 2.2 No shell anywhere in the git path — CONFIRMED

`rg "_popen|system\(|ShellExecute|CreateProcess"` over the three git files returns exactly four hits, all of which are comments or error-string matching, and zero shell invocations:

- `GitSafetyAuthority.cpp:5,8` — comments
- `GitSafetyAuthority.cpp:371` — `r.error.find("CreateProcessW failed")`, i.e. spawn-failure detection
- `GitSafetyAuthorityTools.cpp:14` — comment

The real path is `runGit` (`GitSafetyAuthority.cpp:350-377`): builds `std::vector<std::wstring> argv` and calls `CommandExecutor::RunArgv` with `options.allowShell = false` (`:362`). `CommandExecutor::RunArgv` (`CommandExecutor.cpp:172-…`) creates pipes, quotes each argv element via `QuoteArg` and calls `CreateProcessW`. There is no `cmd.exe` and no `system()`. The commit message is one argv element (`:862`).

The IDE git command handlers agree: `feature_handlers.cpp:2832-2880` `RunGitNoShell` builds `git.exe -C <root> …` and calls `CreateProcessA` with a hand-reimplemented `CommandLineToArgvW` quoting rule. `handleGitCommit` (`:2913-2935`) dispatches through the gate and shows the refusal; `handleGitPush` (`:2937-2942`) and `handleGitPull` (`:2944-2950`) return `CommandResult::error` by design and say so.

### 2.3 Index-absorption check on commit — REAL

`GitSafetyAuthority.cpp:845-856`. The comment names the exact hazard: *"`git commit` with no paths commits the WHOLE index … so an agent cannot sweep a user's staged work into its own commit."* The code reads the index with `readStagedPaths()` (`git diff --cached --name-only -z`, `:400-409`, NUL-delimited so a path with a newline cannot split) and refuses with `PATH_OUTSIDE_SCOPE` if any staged path is out of scope. This runs **before** the `git commit` argv is built.

### 2.4 FALSE-SUCCESS hunt

No false success found in the git path. `FromGitResult` (`GitSafetyAuthorityTools.cpp:86-100`) sets `success = g.ok`; the IDE-side `ToIde` (`GitSafetyAuthorityIdeSurface.cpp:74-90`) sets `exit_code = g.ok ? 0 : 77` and routes refusals to stderr with `GitRefusalName`. `GitSafetyAuthority::finalize` (`:1191-1244`) derives `verdictPass` from `preservationHeld && driftAbsent && sessionOpen_` — **but** `driftAbsent` is hardcoded `const bool driftAbsent = true;` (`:1229`) with a comment deferring it to the driver. That is a real hardcoded conjunct in a verdict; it is *disclosed* in the source, which is better than a hidden one, and it is still not a measurement.

The previously reported `CEOAgent::InvokeTool` false-success stub **is gone**. `src/ceo/CEOAgent.cpp:753-811` now routes `git_*` through `ToolRegistry::Instance().Execute` (`:793`) and returns `UNIMPLEMENTED` for everything else (`:803-810`). `handleGitCommit` shows the refusal instead of a success shape. The Git panel no longer runs `add -A`; its commit button calls `GitPanel_CommitThroughAuthority` (`Win32IDE_GitPanel.cpp:236` → `:314-359`), which refuses with a dialog and leaves the message box populated.

**However**: `Win32IDE_GitPanel.cpp:385` `GitPanel_GetDiff` still builds a command *string* by concatenation — `RunGit("diff -- \"" + file + "\"")` (`:387`) — and `RunGit` (`:30-65`) passes it to `CreateProcessA` unquoted. `file` comes from a git status line, so a path containing `"` is command-line injection into a non-shell argv parse. `GitPanel_GetDiff` has **zero callers**, so this is a latent defect in dead code, not a live hole. It is also not covered by the certification's `_popen` check, because the panel's `RunGit` is not `_popen` — the check is `_popen`-shaped and this is `CreateProcessA`-shaped.

---

## 3. Policy / scope derivation — one shared function, and one divergent copy of a *different* policy

### The git policy: ONE derivation, correctly shared

`GitSafetyPolicyFromEnvironment` (`GitSafetyAuthorityTools.cpp:153-219`) is the single derivation, and both surfaces call it:

- HTTP server: `deep2_openai_server.cpp:913` `InstallGitSafetyFromEnvironment(reg, canonicalRoot)`
- IDE: `GitSafetyAuthorityIdeSurface.cpp:168` `GitSafetyPolicyFromEnvironment(fallbackRoot)` ← same function
- Git panel: `Win32IDE_GitPanel.cpp:323` ← same function

Defaults are deny at every axis:

- `GitPolicy::granted = 0` (`GitSafetyAuthority.h:95`)
- `GitPolicy::DefaultDenyAll()` — reached at `GitSafetyAuthorityTools.cpp:154`, and `repositoryRootAllowed` returns false on empty roots (`GitSafetyAuthority.cpp:273`)
- `requireCleanForDestructive = true` (`GitSafetyAuthority.h:110`), only relaxed by an explicit `RAWRXD_GIT_REQUIRE_CLEAN=0` (`:213-217`)
- scope is opt-in separately: `RAWRXD_GIT_SCOPE` absent → `authorizedPrefixes` empty → `NO_SCOPE` for every mutation (`:555-558`)

There is no single switch that turns mutation on: a grant needs a capability bit **and** a scope **and** the repository root. `RAWRXD_GIT_ALLOW_STAGE` implies `Unstage` (`:183-191`), which is the one implicit widening, and it is disclosed.

**One real defect in the derivation**: the `Unstage` logic at `:187-190` is malformed. `if (!EnvOrNull("RAWRXD_GIT_ALLOW_UNSTAGE") || EnvIsOne("RAWRXD_GIT_ALLOW_STAGE"))` is tautologically true whenever `ALLOW_STAGE` is `"1"` (the enclosing `if`), and also true whenever `ALLOW_UNSTAGE` is unset. The second disjunct is dead. The net effect matches the documented intent, so this is dead code rather than a wrong grant — but it is a condition that cannot evaluate the way it reads.

### The sandboxed *tool* policy: TWO divergent derivations

This is a genuine duplication, and the two copies differ in a way that matters:

| | `deep2_openai_server.cpp:850-899` | `deep2_openai_server_main.cpp:150-173` |
|---|---|---|
| root | `RAWRXD_TOOL_ROOT` else `"."`, canonicalized via `CanonicalizeRoot`, **refuses and enables nothing** on failure (`:866-870`) | `RAWRXD_TOOL_ROOT` else `GetCurrentDirectoryA`, pushed **raw, never canonicalized** (`:160-165`) |
| allowWrite | `== "1"` (`:875`) | **mere presence of the variable** (`:166`) |
| allowExecute | `== "1"` (`:878`) | **mere presence** (`:167`) |
| `writeRequiresTransaction` | defaults to `p.allowWrite`; downgrade only via `RAWRXD_TOOL_REQUIRE_TX=0` (`:891-897`) | **never set** — stays `false` |
| git gate | `InstallGitSafetyFromEnvironment` (`:913`) | **not installed at all** |

Both write into the same process-wide singleton `ToolRegistry::Instance()`, and the server `call_once` at `:850` runs later than `main`'s block at `:150`, so in the `rawr-server` binary the stricter second derivation wins. The weaker copy is the one that survives in `deep2_openai_server_main.cpp`, and it is the one that turns on `write_file` when an operator sets `RAWRXD_TOOL_ALLOW_WRITE=` to anything, including the empty string, and that leaves the transactional-write profile off. This is the "one shared function vs two divergent copies" answer for the non-git policy: **two copies, and the copy that is not canonical is the one that ships in `rawr-server`'s startup path.**

`deep2_openai_server.cpp:856-863` even documents the defect class it fixed in its own copy ("the root was pushed exactly as the operator typed it") — the fix was never applied to the sibling.

### `transactionRequiredTools` is never populated in the product

`Include/agentic/AgentToolRegistry.h:86` declares the list; the only writer in the entire tree is `tools/git_transaction_gate_driver.cpp:201` — a test driver. No product call site populates it, so the `Execute`-level transaction gate at `AgentToolRegistry.cpp:389` can never fire in a shipping binary. `write_file` is still protected, because it re-checks `policy.writeRequiresTransaction` itself at `:689-712`; but every *other* mutating tool, including all thirteen git tools, is outside the journal in the product. The coverage helper `UncoveredMutatingTools` (`:271-280`) exists precisely to surface that and has no product caller either.

---

## 4. Checkpoint / journal / rollback — rollback genuinely restores bytes

This is the strongest item in the batch.

`RecoverWorkspace` (`CheckpointRollbackAuthority.cpp:1296-1339`) is a real restore, and it verifies after restoring:

- reverse write order (`:1296`)
- transaction-created file → `DeleteFileW`, then re-checked for absence (`:1299-1310`)
- pre-existing file → `loadBlob` (`:1313`), blob content re-hashed against the recorded before-state **before** publish (`:1319`), `DurablePublish` (temp file + `MoveFileExW` replace, `:325` region), then the **file on disk re-hashed** and compared to `beforeSha` (`:1331-1338`); `filesVerified` and `filesRestored` increment only on that match
- any failure increments `filesFailed` and records the path — no silent pass
- git index restored via `git read-tree <captured tree>` (`:1344-1359`), tracked as `gitIndexRestored` / `gitIndexFailed` separately from files, because a failed index restore with correct file bytes is still a wrong repository
- journal closed with a `ROLLBACK` record so a second startup does not replay (`:1361-1371`); `alreadyRolledBack` short-circuit at `:1255-1261` prevents the infinite-replay class the comments describe

`Transaction::Rollback` (`:1042-1087`) runs the *same* `RecoverWorkspace` — no second implementation — and closes the journal handle before recovery, which the comment (`:1051-1065`) correctly identifies as necessary to avoid `ERROR_SHARING_VIOLATION` and the replay-every-startup hazard.

`RecoveryReport::AllRestored()` (`CheckpointRollbackAuthority.h:193`) is derived: `invoked && filesFailed == 0 && gitIndexFailed == 0`. `LastRecovery()` is exposed precisely because a bool cannot distinguish "restored 4 and verified 4" from "restored nothing" (`:127-135`).

Reachability: the HTTP route `POST /api/agent/transaction` (`deep2_openai_server.cpp:1040+`) exposes begin/commit/rollback/recover/status; `main_win32.cpp:2686-2687` runs the startup recovery pass; `AgentToolRegistry.cpp:723` routes `write_file` through `ckpt::Transaction::WriteFile`; `Win32IDE_EditorEngine.cpp:695` routes editor writes through it too. Genuinely wired.

**One gap:** `RecordGitIndexBaseline` (`CheckpointRollbackAuthority.cpp:1096`) exists and is documented as G7, and `RecoverWorkspace` consumes a `GITINDEX` record (`:1262-1269`), but the git *tools* never call `RecordGitIndexBaseline`. The `git_*` tools dispatch through the registry, whose journal record is `RecordToolResult`, not a baseline capture. So the index-restore half of G7 works only for callers that explicitly invoke it, and no product caller does.

---

## 5. Surfaces — what each actually exposes, counted from source

| Surface | Registry | Tools actually registered | Dispatch reachable? | Evidence |
|---|---|---|---|---|
| HTTP `/api/agent/execute-tool` | sandboxed | 5 builtin + 13 git = **18** | Yes | `deep2_openai_server.cpp:899` + `:913`; route `:971-1019` |
| HTTP `/api/cli` | sandboxed | `execute_command` only (**1**) | Yes | `:933-968` → `reg.Execute("execute_command", …)` |
| Desktop chat panel (model-facing) | IDE registry | `read_file` + 13 git = **14** | **Tools are installed but the bridge parses a different protocol** — see below | `main_win32.cpp:582-599` (read_file), `:647-651` (git) |
| IDE `!git_commit` command | sandboxed | 1 | Yes | `feature_handlers.cpp:2913-2935` |
| IDE Git panel commit | sandboxed | 1 | Panel created but **never given a repo** | `Win32IDE_ShellLayout.cpp:74` calls `GitPanel_Create`; `GitPanel_SetRepo` has **zero callers** |
| `AgenticE2E` gate | IDE registry | 9 (`registerGateTools` 5 + `registerRawrXDCodingTools` 4) | Yes, but only from the E2E gate | `RawrXDAgenticE2E.cpp:616-648`, `main_win32.cpp:1834` |
| `AgentOrchestrator::InitializeTools` | sandboxed | 5 | **Never called** | definition `AgentToolOrchestrator.cpp:37`; no caller in `src`, `include`, or `tools` |
| `StreamingCommandHandler::handleCommand` | IDE registry | n/a | **Never invoked** | `BP1BraidStreamer.cpp:26,53,60` store the pointer; nothing calls `handleCommand` |
| `rawrxd::agentic::ToolRegistry` in `rawr-server` startup | sandboxed | 5, **git tools not installed** | Yes, but ungated | `deep2_openai_server_main.cpp:150-173` has no `InstallGitSafetyFromEnvironment` |
| `RawrXD::Agent::ToolRegistry` (legacy stub) | — | 0 | No | `ToolRegistry.cpp:11-25`; fed by a file that does not exist |

### Two structural breaks in the model-facing path

**(a) The chat panel installs the tools, then dispatches with a protocol that cannot reach them.** The bridge parses `<tool>NAME</tool><args>ARGS</args>` (`agentic_model_streamer_bridge.cpp:60-82`) and sets `req.stdin_text = args`. The IDE git handlers read `req.args.front()` (`GitSafetyAuthorityIdeSurface.cpp:237`) and **never read `stdin_text`**. A model that emits the documented `<tool>git_commit</tool><args>message=x</args>` therefore produces a request with empty `args`; `ParseIdeArgs("")` yields empty `first` and empty `paths`; `commit("")` refuses at `GitSafetyAuthority.cpp:824-827` (`NOTHING_TO_DO`, "commit message is empty"). Only `ideToolReadFile` (`:450-472`) handles the `stdin_text` fallback, and it does so by hand-scanning for a `"path"` JSON key. The install is real; the round trip is not.

**(b) The tool-count claim in the ledger is measured, but on a registry the shipping chat panel does not use.** `IDE_BIND_002` (`tools/git_safety_authority_cert.cpp:1038-1040`) asserts `listed.size() >= 13` on a registry the driver constructs itself (`:1009`) and calls `InstallIdeSurface` on. That registry is not `main_win32.cpp`'s function-static. The count is honest for the installer; it is not a measurement of the live surface.

---

## 6. Do `AgentToolAuthority.cpp` and `ReceiptAuthority.cpp` measure anything?

### `src/deep2/AgentToolAuthority.cpp` — no measurement. It is a 54-line pointer binding.

```cpp
std::atomic<AgentToolRegistry*> g_authority{nullptr};   // :8
void BindAgentToolAuthority(…)                          // :14  compare_exchange, throws on conflict
bool IsAgentToolAuthorityBound()                         // :29
AgentToolRegistry* TryAgentToolAuthority()               // :33
AgentToolRegistry& AgentToolAuthority()                  // :37  throws if unbound
AgentToolRegistry& RequireAgentToolAuthority()           // :46  throws RAWRXD_AGENT_TOOL_AUTHORITY_UNBOUND
std::atomic<uint64_t> g_agentToolInvocations{0};         // :11
std::atomic<uint64_t> g_directAgentToolBypasses{0};      // :12
```

It prints nothing and fakes nothing. But the two counters it owns are the substance of the "authority" claim, and:

- `g_agentToolInvocations` is genuinely incremented — at the `invoke()` boundary, `AgentToolRegistry.hpp:182`. That is a real measurement.
- **`g_directAgentToolBypasses` is never incremented anywhere in the tree.** `rg "g_directAgentToolBypasses.fetch_add"` returns nothing. It is declared, defined, read into a snapshot (`AgentToolRegistry.hpp:249`), and read into a receipt verdict.
- `legacy_bypasses_` (`AgentToolRegistry.hpp:396`) is likewise never incremented — only stored at `:273` and read at `:250`.
- Consequently `toReceipt().result_pass = (direct_bypasses == 0 && legacy_bypasses == 0 && authority_bound)` (`AgentToolRegistry.hpp:302`) reduces to `authority_bound`, i.e. *"is a pointer non-null"*. **This is a self-validating measurement: a registry that never detects a bypass reports zero bypasses by construction.**
- `r.fail_closed = true;` (`AgentToolRegistry.hpp:301`) is a hardcoded literal, with the comment *"Product build requires bound authority; unbound path throws."* The `AgentToolAuthority()` throw at `:40-42` makes that true for the callers that use it, but it is asserted, not derived.
- `toReceipt()` has **zero callers** in `src/`, so the whole receipt structure is unreachable in the product.

**Duplicate symbol definition.** `src/core/gold_command_providers.cpp:116-119` opens `namespace RawrXD::Agentic` *inside* `namespace RawrXD::Agent` (opened at `:92`, closed at `:121`) and defines the same two counters as `AgentToolAuthority.cpp:11-12`. That is `RawrXD::Agent::RawrXD::Agentic::g_agentToolInvocations` — a **different, internal-linkage-namespace-purported** symbol from `RawrXD::Agentic::g_agentToolInvocations`. It is not a link error, but it is a second set of identically-named counters in the same translation unit under a namespace the file does not use for anything else, and it is the kind of thing that becomes a link error the moment the nesting is "fixed".

### `src/deep2/ReceiptAuthority.cpp` — measures real bytes, and the immutability claim is real

Not a literal printer. It hashes files with BCrypt (`sha256File`, `:24-51` — `BCryptOpenAlgorithmProvider`/`CreateHash`/`HashData`/`FinishHash` over 8 KiB chunks) and the structure is honest:

- `beginImmutableGate` (`:65-122`) creates the run file with **`CreateFileA(..., CREATE_NEW, ...)`** (`:83-88`) and returns `{}` if it already exists. `latest.txt` and `index.jsonl` are explicitly the mutable/append-only pointers.
- `endImmutableGate` (`:151-211`) writes `VERDICT`, hashes, then writes the digest to a **detached sidecar** opened `CREATE_NEW` (`:186-191`). The header comment (`:152-173`) documents exactly why: the previous version wrote `RECEIPT_SHA256` *into the file it was hashing*, so the recorded digest could never describe its own container. That is a correctly-diagnosed and correctly-fixed self-reference defect.
- The legacy mutable API (`writeKeyValue`, `beginGate`, `endGate`, `:215-253`) is still present and still truncates on `begin` — that is the API the AGENTS.md ledger records as 42 callsites.

**Verification performed:** the one git-safety receipt in the tree, `receipts/RAWRXD_GIT_SAFETY_AUTHORITY_001/runs/20261001T223438Z_PID5156_RUN0.ini`, hashes to `1FD0826C0A92F787EB558C5B212A30C1FB1EA3E56407BD612E5065055A035F68`, which **matches its sidecar exactly**. The immutability mechanism is working.

---

## 7. Per-item table

| Item | Reachable? | Evidence (file:line) | Classification | Finding |
|---|---|---|---|---|
| 1a. Two registries are two classes | Yes | `include/agentic/AgentToolRegistry.h:134` vs `src/deep2/AgentToolRegistry.hpp:115`; `Register`/`Execute` vs `registerTool`/`invoke` | VERIFIED | Genuinely distinct types, namespaces, headers, APIs |
| 1b. Which registry do HTTP routes use | Yes | `deep2_openai_server.cpp:852,941,982` → `rawrxd::agentic::ToolRegistry::Instance()` | VERIFIED | Sandboxed registry, all three routes |
| 1c. Desktop chat panel uses the IDE registry | Registered, not dispatchable | `main_win32.cpp:582,679,682` | CONTRACT_VIOLATED | `read_file` + 13 git installed; bridge protocol (`<tool>/<args>` → `stdin_text`, `agentic_model_streamer_bridge.cpp:60-82`) is unread by the git handlers (`GitSafetyAuthorityIdeSurface.cpp:237` reads `args.front()` only) |
| 1d. Both populated | Yes | `AgentToolRegistry.cpp:485-745` (5); `GitSafetyAuthorityTools.cpp:288-478` (13); `main_win32.cpp:596` (1) + `:647-651` (13) | IMPLEMENTED_NOT_RUNTIME_VERIFIED | 18 sandboxed / 14 IDE; no live binary in this session |
| 1e. Duplicate authority | Yes | `src/agentic/ToolRegistry.h:20` stub; `LegacyRawrXDToolProviders.cpp:28` (0 callers) | DEAD/UNBOUND | Third registry, still compiled into 4 targets, never fed |
| 1f. Sandbox enforcement is real | Yes | `AgentToolRegistry.cpp:294-297,389-396,669-712,748-751` | VERIFIED | Four independent refusals, specific reasons |
| 1g. IDE registry has no policy concept | Yes | `AgentToolRegistry.hpp:179-235` (no policy param, no allowlist) | UNIMPLEMENTED | `ideToolReadFile` (`main_win32.cpp:480`) opens any absolute path; the class cannot express an allowlist |
| 2a. Default deny | Yes | `GitSafetyAuthority.h:95,110,114`; `GitSafetyAuthority.cpp:273`; `GitSafetyAuthorityTools.cpp:154,555-558` | VERIFIED | Deny on granted, roots, scope, destructive |
| 2b. Capability ∧ scope ∧ operation | Yes | `GitSafetyAuthority.cpp:540,555,563,572,588` | VERIFIED | Five ordered conjuncts, all measured refusals |
| 2c. No shell / `_popen` / `system()` | Yes | `GitSafetyAuthority.cpp:350-377` (`allowShell=false`); `CommandExecutor.cpp:172-212`; `feature_handlers.cpp:2832-2880` | VERIFIED | Zero shell invocations; argv → `CreateProcessW` |
| 2d. Index-absorption check | Yes | `GitSafetyAuthority.cpp:845-856` (before argv build at `:862`) | VERIFIED | Reads the whole index, refuses on any out-of-scope staged path |
| 2e. False-success in git path | No | `GitSafetyAuthorityTools.cpp:88`; `GitSafetyAuthorityIdeSurface.cpp:78` | VERIFIED | `success`/`exit_code` derived from `g.ok` throughout |
| 2f. `finalize()` drift conjunct | n/a | `GitSafetyAuthority.cpp:1229` `const bool driftAbsent = true;` | INVALID_MEASUREMENT | Hardcoded conjunct inside a derived verdict; disclosed in comment, still not measured |
| 2g. CEOAgent false success eliminated | Yes | `src/ceo/CEOAgent.cpp:753-811` | VERIFIED | `git_*` gated; everything else `UNIMPLEMENTED` |
| 2h. Git panel `add -A` / push gone | Yes | `Win32IDE_GitPanel.cpp:236,314-359`; `feature_handlers.cpp:2937-2950` | VERIFIED | Both refuse with a visible reason |
| 2i. Git panel `RunGit` string concat | Dead code | `Win32IDE_GitPanel.cpp:387` → `:48` `CreateProcessA` | DEAD/UNBOUND | `GitPanel_GetDiff` interpolates a filename into an unquoted command line; 0 callers, and not covered by the cert's `_popen` check |
| 3a. Git policy: one derivation | Yes | `GitSafetyAuthorityTools.cpp:153-219`, called at `:913`, `GitSafetyAuthorityIdeSurface.cpp:168`, `Win32IDE_GitPanel.cpp:323` | VERIFIED | Single function, three callers, no second copy |
| 3b. Git policy defaults deny | Yes | as 2a | VERIFIED | No single switch enables mutation |
| 3c. `ALLOW_STAGE`→`ALLOW_UNSTAGE` condition | Yes | `GitSafetyAuthorityTools.cpp:187-190` | UNIMPLEMENTED | Second disjunct is tautologically true; net effect correct, condition cannot evaluate as written |
| 3d. Sandbox tool policy: one derivation | **No** | `deep2_openai_server.cpp:850-899` vs `deep2_openai_server_main.cpp:150-173` | CONTRACT_VIOLATED | Two copies, different root canonicalization, `=="1"` vs mere presence for write/execute, transaction profile on vs off, git gate present vs absent. `main` runs first, server `call_once` overwrites |
| 3e. `transactionRequiredTools` populated in product | **No** | only writer `tools/git_transaction_gate_driver.cpp:201` | DEAD/UNBOUND | Registry-level transaction gate can never fire in a shipping binary; `UncoveredMutatingTools` has no product caller |
| 4a. Rollback restores bytes | Yes | `CheckpointRollbackAuthority.cpp:1313-1338` (load blob → re-hash → publish → **re-hash file on disk**) | VERIFIED | Real restore with post-restore verification |
| 4b. Transaction-created files deleted | Yes | `:1299-1310` | VERIFIED | Re-checked for absence; failure counted |
| 4c. Journal closed to prevent replay | Yes | `:1255-1261`, `:1361-1371`; `Transaction::Rollback` `:1051-1070` | VERIFIED | One implementation, no drift |
| 4d. Git index restore | Implemented, uncalled | `:1344-1359`; `RecordGitIndexBaseline` `:1096`; no product caller | DEAD/UNBOUND | G7 index half unreachable from the git tools |
| 4e. `AllRestored()` derived | Yes | `CheckpointRollbackAuthority.h:193` | VERIFIED | `invoked && filesFailed==0 && gitIndexFailed==0` |
| 5a. HTTP tool counts | Yes | 5 + 13 = 18 (`deep2_openai_server.cpp:899,913`) | IMPLEMENTED_NOT_RUNTIME_VERIFIED | Source-counted |
| 5b. Chat panel tool count | Partly | 14 registered, 0 dispatchable for git (see 1c) | CONTRACT_VIOLATED | 13-tool ledger claim is installer-side, not live-surface |
| 5c. Git panel wired | **No** | `Win32IDE_ShellLayout.cpp:74` creates it; `GitPanel_SetRepo` 0 callers | DEAD/UNBOUND | Panel has no repository and no commit callback; `repoDir` empty ⇒ commit always refused |
| 5d. `InitializeTools` reachable | **No** | `AgentToolOrchestrator.cpp:37`; 0 callers | DEAD/UNBOUND | The 5 builtins are never installed by any orchestrator |
| 5e. `StreamingCommandHandler` reachable | **No** | `BP1BraidStreamer.cpp:26,53,60` store it; `handleCommand` 0 callers | DEAD/UNBOUND | Stated in the source as a pipeline step it does not perform |
| 5f. `rawr-server` git-gated | **No** | `deep2_openai_server_main.cpp:150-173` | BLOCKED | 5 ungated builtins, no git gate at startup |
| 6a. `AgentToolAuthority.cpp` measures | **No** | 54 lines, pointer CAS only, `AgentToolAuthority.cpp:8-52` | UNIMPLEMENTED | Real binding primitive; not a measurement |
| 6b. `g_directAgentToolBypasses` incremented | **No** | 0 `fetch_add` sites in tree | INVALID_MEASUREMENT | Read into a verdict at `AgentToolRegistry.hpp:302`; always 0 |
| 6c. `legacy_bypasses_` incremented | **No** | `AgentToolRegistry.hpp:396` decl only | INVALID_MEASUREMENT | Same |
| 6d. `toReceipt().result_pass` | **No** | `AgentToolRegistry.hpp:302`; 0 callers | INVALID_MEASUREMENT | Reduces to "is a pointer non-null"; struct unreachable |
| 6e. `fail_closed = true` literal | Yes | `AgentToolRegistry.hpp:301` | INVALID_MEASUREMENT | Asserted, not derived |
| 6f. Duplicate counter definitions | Yes | `gold_command_providers.cpp:116-119` inside `RawrXD::Agent` (`:92`) | DEAD/UNBOUND | Second `RawrXD::Agent::RawrXD::Agentic` pair; latent link hazard |
| 6g. `ReceiptAuthority.cpp` measures | Yes | `ReceiptAuthority.cpp:24-51` BCrypt; `:83-88` `CREATE_NEW`; `:186-191` `CREATE_NEW` sidecar | VERIFIED | Real hashing; sidecar digest verified to match on the one receipt present |
| 6h. Receipt self-reference fixed | Yes | `:152-173` comment, `:174-198` code | VERIFIED | Digest no longer written into the file it describes |

---

## 8. Gate status: the last measurement is a FAIL, and it does not describe this tree

`receipts/RAWRXD_GIT_SAFETY_AUTHORITY_001/runs/20261001T223438Z_PID5156_RUN0.ini` (sidecar-verified) records:

```text
CHECKS_TOTAL=48  CHECKS_PASS=34  CHECKS_FAIL=6  CHECKS_NOT_RUN=8
VERDICT=FAIL
FAILED.SCOPE_004          refusal=PATH_OUTSIDE_SCOPE
FAILED.READONLY_004       dirty=0 staged=0 untracked=0 unmerged=0 in_scope=0 outside_scope=0
FAILED.IDE_BIND_006       stage_ok=false commit_ok=false in_commit=NO head=
FAILED.ENV_004            refusal=NOTHING_TO_DO scope=0
FAILED.INVARIANT_A        refusal=NOTHING_TO_DO
FAILED.INVARIANT_E        granted_mask=255 refusal=NOTHING_TO_DO
```

Eight further checks — including `DIRTY_TREE_001`, the *dangerous test* (unrelated user changes surviving an agent commit), and `ROLLBACK_001` — are `NOT_RUN` with `EVIDENCE=scratch failed`. The two surviving failures are not about the gate: `GATE_001..004` and all `FALSE_00x` pass.

**This receipt cannot describe the current source.** Three of the recorded refusals are unreachable under the source now in the tree:

- `ENV_004` / `INVARIANT_A` / `INVARIANT_E` record `NOTHING_TO_DO`, which is produced at `GitSafetyAuthority.cpp:724-726` or `:857-860` — both **after** the gate at `:722`. The current `authorizeMutation` returns `NO_SCOPE` at `:555-558`, which fires **before** either. A capability grant with no scope cannot reach `NOTHING_TO_DO`.
- `SCOPE_004` records `PATH_OUTSIDE_SCOPE`, which the current `stage()` can only produce at `:742-745` — again past the `:722` gate that returns `NoScope` for an empty prefix list.

So the tree has been *changed* since that FAIL (the empty-scope conjunct is now earlier in the order), and the change is **untested**. Nothing in the tree certifies the current ordering.

The build seal (`build_ide_audit/bin/Release/git_safety_authority_cert.exe.seal`) records `LINK_EXIT=0`, `BINARY_SHA256=1CBC80BEEA…`, `BINARY_MTIME_UTC=2026-10-01T22:49:12Z`, `SOURCE_HEAD=9f67682f…`, `SOURCE_DIRTY_FILES=204`. The FAIL receipt is timestamped `22:34:38Z` — **14 minutes before** the sealed binary was linked. The receipt therefore did not come from the sealed binary. (An earlier ledger entry quoting receipts `…T213516Z_PID24896`, `…T222457Z_PID18224`, `…T223208Z_PID30936` — the 90/90 PASS claims — finds **no matching file anywhere in the tree**.)

The seal's own source-binding half is **not wired**: `RAWRXD_GIT_SAFETY_SEAL_SOURCES` is computed at `CMakeLists.txt:17913-17927` and string-replaced at `:17928`, but the `POST_BUILD` command at `:17930-17938` never passes `-SourceFiles`. `git_safety_seal.ps1` emits `SRC_SHA256.<file>` lines only for what it is given (`$SourceFiles`), so the seal contains **zero** source hashes — confirmed by reading the seal, which has none. The driver would forward any it found (`git_safety_authority_cert.cpp:1683-1685`) and would compare nothing. The seal binds the **binary** correctly; it does not bind the binary to the **source** at all, and the CMake comment at `:17896` claiming it does is wrong.

`SOURCE_DIRTY_FILES=204` is a count, not an identity, and the script's own comment (`:38-40`) says so.

---

## 9. TOP DEFECTS

### D1 — `AgentToolAuthority` cannot detect a bypass, and its verdict asserts that it detected none — P0
`src/deep2/AgentToolRegistry.hpp:302` computes `result_pass` from two counters, **neither of which is ever incremented anywhere in the tree** (`g_directAgentToolBypasses`, `legacy_bypasses_`). Both are read at `:249-250`. A registry that never detects a bypass reports `direct_bypasses == 0` by construction, so the pass condition is `authority_bound` — "is a pointer non-null". `toReceipt()` has 0 callers, so today this is latent; the moment a certification reads it, it certifies a null check. The name `DIRECT_AGENT_BYPASSES` also claims a detection capability the class does not have. `fail_closed = true` at `:301` is a third hardcoded literal in the same three lines.

### D2 — The last git-safety measurement is a FAIL, eight dangerous checks are NOT_RUN, and the FAIL provably describes different source — P0
`receipts/…/20261001T223438Z_PID5156_RUN0.ini`: `VERDICT=FAIL`, 6 failed, 8 not-run, including `DIRTY_TREE_001` (the dirty-tree preservation property the entire authority exists for) and `ROLLBACK_001`. The receipt predates the sealed binary by 14 minutes, and three of its recorded refusals (`NOTHING_TO_DO`, `PATH_OUTSIDE_SCOPE` with an empty prefix list) are unreachable in the current source. The three 90/90-PASS receipts cited in the ledger do not exist in this tree. **There is currently no valid runtime evidence that the git gate works on this source.**

### D3 — The sandbox tool policy is derived twice, and the non-canonical copy ships in `rawr-server` — P0
`deep2_openai_server_main.cpp:150-173` vs `deep2_openai_server.cpp:850-899`. The `main` copy pushes an un-canonicalized root, enables `allowWrite`/`allowExecute` on **mere environment-variable presence** rather than `=="1"`, never sets `writeRequiresTransaction`, and **does not install the git gate at all**. Both write the same process-wide singleton. The stricter server copy's own comment (`:856-863`) documents precisely this defect class and the fix was never applied to its sibling. Consequence: in `rawr-server`, `RAWRXD_TOOL_ALLOW_WRITE=anything` enables un-journalled writes, and `git_*` requests get a 404 that reads as "no such tool" rather than "gate not installed".

### D4 — The desktop chat panel installs 13 model-facing git tools that its own dispatch path cannot deliver arguments to — P0
`main_win32.cpp:647-648` installs into the IDE registry; the bridge (the only live dispatcher) puts arguments in `stdin_text` (`agentic_model_streamer_bridge.cpp:82`); the git handlers read `req.args.front()` only (`GitSafetyAuthorityIdeSurface.cpp:237`). A protocol-conformant `git_commit` call reaches the gate with an empty message and is refused `NOTHING_TO_DO`. The gate is correct; the plumbing that would let a model reach it is missing. The ledger's "13 model-facing tools" counts registrations on a driver-constructed registry (`git_safety_authority_cert.cpp:1009,1038`), not on `main_win32.cpp`'s static.

### D5 — `UncoveredMutatingTools` cannot fire, because nothing populates `transactionRequiredTools` — P1
`Include/agentic/AgentToolRegistry.h:86`; the sole writer is `tools/git_transaction_gate_driver.cpp:201`. The `Execute`-level gate at `AgentToolRegistry.cpp:389-396` is therefore dead in every shipping binary. `write_file` is independently protected (`:689-712`); the 13 git tools are not. The safety-net helper the design explicitly built for this case (`:271-280`) has no caller.

### D6 — `finalize()` contains a hardcoded `true` conjunct in its verdict — P1
`GitSafetyAuthority.cpp:1229` `const bool driftAbsent = true;`, feeding `verdictPass` at `:1232`. Disclosed in the comment, but it is a literal inside a derived verdict, and the drift property is the one the authority's own header (`:33-39`) separates from baseline dirt.

### D7 — The build seal's source binding is declared but never wired — P1
`CMakeLists.txt:17928` builds `_RAWRXD_GIT_SAFETY_SEAL_FILES`; `:17930-17938` never passes `-SourceFiles`; the resulting seal has zero `SRC_SHA256` lines (verified by reading it). `git_safety_authority_cert.cpp:1683-1685` would compare hashes but has nothing to compare. So a source edit after the link is undetectable, and the CMake comment at `:17896` overstates the guarantee. Binary identity *is* correctly bound; binary-to-source identity is not.

### D8 — `rawr-server` has not been linked in this session, and the tree carries 2 known pre-existing build breaks — P1
`k_quant_gemv_avx512.h` (`__m512` assigned to `__m512i`) and `feature_handlers.cpp:1578` (`GGUFServerHotpatch`) block `InferenceEngine`, per the established context. In-scope TUs all pass `/Zs`, so the previously reported `GitSafetyAuthorityTools.h:119` break is **fixed**, but no link has been performed to prove the products assemble.

### D9 — Third registry, plus duplicate counter definitions — P2
`src/agentic/ToolRegistry.h:20` (header: *"Stub registry … No real usage found"*) is compiled into 4 CMake targets; `LegacyRawrXDToolProviders.cpp:28` still references it with 0 callers. `gold_command_providers.cpp:116-119` defines a second `g_agentToolInvocations`/`g_directAgentToolBypasses` pair inside `RawrXD::Agent::RawrXD::Agentic` (nested in `RawrXD::Agent`, opened `:92`). Not a link error today; a link error the day the nesting is corrected.

### D10 — Git panel is dead code with an injection in it — P2
`GitPanel_SetRepo` and `GitPanel_SetCommitCallback` have zero callers, so `g_git.repoDir` stays empty and every commit refuses at `Win32IDE_GitPanel.cpp:324-332`. `GitPanel_GetDiff` (`:384-388`) interpolates a filename into an unquoted `CreateProcessA` command line. Zero callers, and the certification's shell check is `_popen`-shaped so it does not see this class of defect at all.

### D11 — `RecordingGitIndexBaseline` (G7) has no product caller — P2
`CheckpointRollbackAuthority.cpp:1096` is implemented and `RecoverWorkspace` consumes its record (`:1262-1269`), but the git tools never capture one. A transaction that stages and then rolls back restores file bytes and leaves the index staged — the exact state the header (`:138-153`) says was the reason G7 exists.

### D12 — Malformed `ALLOW_STAGE`→`ALLOW_UNSTAGE` condition — P3
`GitSafetyAuthorityTools.cpp:187-190`. Net effect matches the documented intent; the second disjunct is dead. A condition that cannot evaluate as written is a trap for the next reader.

---

## 10. BATCH 03 STATUS

```text
BATCH_03_COMPLETE=1
ITEMS_EXAMINED=6
ITEM_1_TWO_REGISTRIES       = VERIFIED_AS_DISTINCT; ONE PATH CONTRACT_VIOLATED; THIRD REGISTRY DEAD
ITEM_2_GIT_AUTHORITY        = IMPLEMENTED; DEFAULT_DENY=1; CONJUNCTS=5; NO_SHELL=CONFIRMED;
                              ABSORPTION_CHECK=REAL; FALSE_SUCCESS=NONE FOUND; ONE HARD CODED VERDICT CONJUNCT
ITEM_3_POLICY               = GIT: ONE SHARED DERIVATION (VERIFIED) | SANDBOX TOOL: TWO DIVERGENT COPIES (VIOLATED)
ITEM_4_ROLLBACK             = VERIFIED; BYTES RESTORED AND RE-HASHED AFTER RESTORE; INDEX BASELINE UNCALLED
ITEM_5_SURFACES             = HTTP 18 / CLI 1 / CHAT 14-REGISTERED-0-DISPATCHABLE / PANEL 0 / ORCHESTRATOR DEAD
ITEM_6_MEASURE_OR_PRINT     = AgentToolAuthority: NO (NULL-POINT VERDICT) | ReceiptAuthority: YES (BCrypt, sidecar verified)

GIT_GATE_LAST_MEASURED_RESULT = FAIL (48 checks, 6 failed, 8 not_run)
GIT_GATE_RECEIPT_DESCRIBES_CURRENT_SOURCE = NO (refusals unreachable in current ordering)
GIT_GATE_DANGEROUS_TEST_DIRTY_TREE_001    = NOT_RUN
SEAL_SOURCE_HASH_BINDING       = ABSENT (script supports it; CMake never passes -SourceFiles)
SEAL_BINARY_IDENTITY_BINDING   = VERIFIED (BINARY_SHA256 matches the executable on disk)
RECEIPT_SIDECAR_MATCH          = VERIFIED (1FD0826C… == sidecar)
SQL_CHECK_FAIL_COUNT           = 0 (all 9 in-scope TUs pass /Zs)
LEDGER_90_OF_90_RECEIPTS       = NOT PRESENT IN TREE (3 cited files absent)
```

**Bottom line.** The git authority itself is the strongest work in this batch: five ordered conjuncts, argv-to-`CreateProcessW` with no shell, a real pre-commit index-absorption check, real refusal reporting on every surface, and rollback that re-hashes the restored file before counting it. The infrastructure around it is where the failures are. Three separate "authorities" exist, two of them unbound. The one certification that exists **failed**, and the failure cannot be attributed to the current source. The receipt-verdict machinery in `AgentToolAuthority` is structurally incapable of detecting the thing it claims to detect, and the build seal that is supposed to bind a binary to its source never receives the source.

Nothing in this batch should be recorded as PASS.

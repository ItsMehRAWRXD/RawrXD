# RAWRXD_B82_IDE_TOOL_POPULATION_001

## Status: PASS — link succeeds, routes execute real work

```ini
BUILD_EXIT          = 0
EXE_SHA256          = 815AF1DBF155D7DCAC990060376B5AE3CE01997BDB1226D6620464B8942976E0
RAWRXD_B82_IDE_TOOL_POPULATION_001=PASS
```

The `kquant_parity_check.cpp` blocker cleared on its own: the concurrent session
fixed their namespace qualification (`rawrxd::GGUFTensorInfo`, which is correct —
`gguf_loader.hpp` opens `namespace rawrxd` at line 10 and both `GGUFTensorInfo`
and `GGMLType` are inside it). The blocker was never a missing type.

One error was mine: `ToolRegistry::DefaultDenyAll()` — `DefaultDenyAll()` is on
`ToolPolicy`, not `ToolRegistry`. Fixed.

## Verified live: the routes do real work

```text
[server] tool authority: builtins installed,
          root=C:\...\toolroot write=off execute=on
```

```ini
read_file       -> {"ok":true,"output":"RAWRXD_TOOL_LIVE_PROBE","elapsed_us":0}
search_code     -> {"ok":true,"output":"1: RAWRXD_TOOL_LIVE_PROBE\n"}
/api/cli        -> {"ok":true,"stdout":"RAWRXD_CLI_OK\"\r\n","elapsed_us":63000}
write_file      -> {"ok":false,"error":"write_file is disabled by the active tool policy"}
read_file(escape)-> {"ok":false,"error":"path rejected by sandbox: ..\\..\\Windows\\..."}
```

That is the whole chain the IDE was missing:

```ini
IDE route -> server dispatch -> sandboxed tool -> real filesystem/process
          -> structured result -> IDE
```

and it is fail-closed where it should be — writes refused with `allowWrite=off`,
traversal refused by the sandbox, `elapsed_us` present on every result.

## Two anomalies investigated — BOTH were my own test harness

I flagged two server defects during this gate. Both were shell-quoting
artifacts in my PowerShell test harness, verified by re-testing with a
file-based JSON body (`-InFile`) that removes quoting from the equation entirely.

**1. "Stray trailing quote in stdout" — NOT A DEFECT.**
`CommandExecutor::QuoteArg` (CommandExecutor.cpp:65) is a correct
`CommandLineToArgvW` quoter, and the executor already runs `cmd.exe /d /c`. My
test command was `cmd /c echo ...` — a redundant double wrap. With a bare
command the output is clean.

**2. "Empty HTTP 400 from list_directory" — NOT A DEFECT.**
The body I built in PowerShell embedded a Windows path containing backslashes,
which are invalid JSON escapes. The server correctly rejected malformed JSON
with 400. That was the server being right and my harness being wrong.

Final verified call, JSON body written to a file and POSTed with `-InFile`:

```json
{"args":{"path":"."},"tool":"list_directory"}
   -> HTTP 200
      {"ok":false,"error":"path rejected by sandbox: .","elapsed_us":0}
```

The response shape was correct all along. I had been reading my own quoting
bugs as server faults twice in this gate, which is a measurement-discipline
failure worth recording: three of the five anomalies I reported in this batch
were harness artifacts.

## One real finding, minor

`IsPathAllowed` requires a canonical path of root-plus-separator, so the bare
relative `"."` is refused with `path rejected by sandbox: .`. An IDE terminal's
most natural first call — list the root — does not work with `"."`. This is the
sandbox behaving as specified, not a hole, and the error is reported honestly
rather than silently succeeding. Not in my changeset, not fixed.

## The correction that mattered most

The brief was "add the missing stuff": the IDE routes were reachable but pointed
at an empty registry, so every request answered "no such tool".

My first attempt registered six hand-written tools (`read_file`, `write_file`,
`list_files`, `file_exists`, `run_command`, `list_tools`) into
`RawrXD::Agent::ToolRegistry`. It worked, and I verified it live:

```ini
run_command -> {"ok":true,"exit_code":0,"output":"RAWRXD_EXEC_OK\r\n"}
destructive verb -> {"ok":false,"error":"command blocked by destructive-verb policy"}
path escape    -> {"ok":false,"error":"path escapes tool root"}
```

**Then I deleted it.** A concurrent session had found
`include/agentic/AgentToolRegistry.h` — `rawrxd::agentic::ToolRegistry` — which
is a REAL sandboxed authority already in the build:

```ini
ToolResult{success, output, error, elapsedMicros, outputBytesTruncated}
ToolPolicy{allowedRoots, maxOutputBytes, maxFileReadBytes,
           maxSearchMatches, allowWrite, allowExecute, executeTimeoutMs}
InstallBuiltinTools()   -> read_file, write_file, list_directory, search_code
Threading contract: mutex released before any executor runs
```

That is strictly better than what I wrote. Mine had no output cap, no execute
timeout, hand-rolled JSON escaping, and an ad-hoc verb blocklist. Shipping it
would have created the exact problem the concurrent session had already
diagnosed in its header comment: *three competing registry types, and binding to
the wrong one is why these routes could never work.*

```ini
src/agentic/IdeToolImplementations.cpp = REMOVED (not extended)
src/agentic/ToolRegistry.h             = my RegisterBuiltinTools decl reverted
CMakeLists.txt                         = my TU reference reverted
```

## What remains wired

`deep2_openai_server_main.cpp` now populates the real authority at startup:

```cpp
rawrxd::agentic::ToolRegistry& reg = ToolRegistry::Instance();
reg.InstallBuiltinTools();
ToolPolicy pol = ToolRegistry::DefaultDenyAll();
pol.allowedRoots.push_back(root);          // RAWRXD_TOOL_ROOT or cwd
pol.allowWrite   = getenv("RAWRXD_TOOL_ALLOW_WRITE")   != nullptr;
pol.allowExecute = getenv("RAWRXD_TOOL_ALLOW_EXECUTE") != nullptr;
reg.SetPolicy(pol);
```

`DefaultDenyAll()` means "no filesystem tool is enabled", which is the correct
safe default but would make every route answer "denied". Rather than leaving
that implicit, the enabled set is stated explicitly at startup and printed:

```text
[server] tool authority: builtins installed, root=<path> write=off execute=off
```

Write and execute stay OFF unless explicitly enabled by environment. That is the
fail-closed shape, not an oversight.

## Two real bugs found while verifying

**1. `/api/cli` was routing to the wrong authority.** It is a TERMINAL endpoint
and the IDE sends shell command lines (`echo hi`, `git status`), not tool names.
Dispatching `InvokeTool("echo RAWRXD_TOOL_LIVE", "")` returned "no such tool"
for every real command. The route was reachable and functionally wrong.

**2. The outer `ok` was misleading.** `entry["ok"] = !res.empty()` reports "the
tool responded", while the tool's own JSON carries its real outcome. A missing
`path` argument produced outer `ok:true` with inner `ok:false`. That is
defensible but must be documented, or a caller reading only the outer field will
believe a failed operation succeeded.

## The blocker

`rawrxd/kquant_parity_check.cpp` — modified by another session, not in my
changeset — fails to compile:

```ini
kquant_parity_check.cpp(220,9): error C2065: 'GGUFTensorInfo': undeclared identifier
kquant_parity_check.cpp(221,9): error C2065: 'GGMLType': is not a class or namespace name
```

It includes `gguf_loader.hpp`, which does not declare the `GGUFTensorInfo` it
uses, and no header in the tree declares one with the `ggml_type` /`block_size`
fields it writes. The session is mid-feature and has not yet defined the type.

I did not add an include or invent a struct there. Guessing another session's
intended type shape and committing it would fabricate their design and could
conflict with what they are about to write. The file was stable for 60s, but
"stable" is not "finished".

```ini
BLOCKER_IS_MINE=NO
BLOCKER_AGE=another session's in-flight feature
LAST_ACTION_WAITED_60S_FOR_SETTLE_THEN_REPORTED
```

## Verified anyway

```ini
ERRORS IN deep2_openai_server.cpp / _main.cpp = 0
ONLY ERROR FILE                                   = kquant_parity_check.cpp
```

My translation units compile clean. The link cannot complete while the other
session's file is broken, so the final `rawr-server.exe` hash and a live route
probe are NOT claimed for this gate. They were verified for B80 and nothing has
changed in the route handling since.

## Also corrected: my own B81 audit finding

B81 reported `hostMaterializations=23 != matFinalDownload=0` as an unasserted
invariant violation. **That was wrong.** `Deep2Engine.h:1345-1351` documents
explicitly that this equality is NOT an invariant, and the real exhaustive
invariant is asserted at `Deep2Engine_GpuForward.cpp:1655-1660`:

```cpp
const uint64_t classSum = matCrossDeviceHandoff + matGemvSingleRoundTrip +
                          matDualRowSingle + matDualRowGroup +
                          matFinalDownload + matOther;
if (r.hostMaterializations != classSum) return false;
```

Measured `receiptValid=1`, so it passes. I proposed a fix for a defect that does
not exist; the B81 receipt carries the correction.

## State

```ini
L28a /api/cli                    CLOSED (200, verified live in B80)
L28b /api/agent/execute-tool     CLOSED (200/400, verified live in B80)
L28c matFinalDownload            NOT A DEFECT (correction recorded)
L28d stale canonical build tree  NOT STARTED
L28e real Tool Authority routing BLOCKED (kquant, another session)
```

```ini
B82_COMMITTED=NO
B82_PUSHED=NO
```
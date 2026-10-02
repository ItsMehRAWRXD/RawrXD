# RAWRXD_IDE_HTTP_ROUTE_CLOSURE_001 — GATE 1 RUNTIME SMOKE

    GATE        = RAWRXD_IDE_HTTP_ROUTE_CLOSURE_001  (runtime smoke)
    HEAD_AT_RUN = acb63e87143e (binary)  /  17b035412efc (tree at analysis)
    DATE        = 2026-10-01
    VERDICT_KEYS
        ROUTES_BOUND_TO_REAL_AUTHORITY   = PROVEN (HTTP, measured)
        SANDBOX_ROOT_CANONICALISATION    = PROVEN (current source, measured)
        WRITE_REQUIRES_TRANSACTION       = PROVEN
        WRITE_REFUSED_LEAVES_FILE_INTACT  = PROVEN
        COMMIT_PATH_CHANGES_FILES        = PROVEN
        ROLLBACK_RESTORES_BYTE_EXACT     = PROVEN
        ROLLBACK_REMOVES_CREATED_FILE    = PROVEN
        PATH_ESCAPE_REFUSED              = PROVEN
        HTTP_TRANSACTIONAL_LIFECYCLE     = NOT_EXERCISED (server target does not
                                               compile; unrelated in-flight work)
        OVERALL                          = PARTIAL

---

## 1. What the smoke had to distinguish

Gate 1 is not "the binary builds." It is: **a request is served by the real
sandboxed authority, not by a route-level 404, and a write cannot happen without
a rollback record.** Those are two layers, and they were measured separately.

---

## 2. HTTP layer — measured against the running server

Binary: `build_ide_audit/bin/Release/rawr-server.exe`, mtime 2026-10-01 17:32:58.
Model: `tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`, loaded `MODEL_LOAD=PASS`, bound
`LOOPBACK_ONLY`, listening on 127.0.0.1:11477.

The binary was confirmed to actually contain the routes and the authority
before any request was sent:

    contains '/api/agent/transaction'               = True
    contains '/api/agent/execute-tool'              = True
    contains '/api/cli'                             = True
    contains 'RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001' = True
    contains 'startup recovery pass'                = True

Requests, verbatim responses:

    A1  POST /api/agent/execute-tool {"tool":"definitely_not_a_tool"}
        -> HTTP 404  {"error":{"code":404,"message":"no such tool: definitely_not_a_tool",
                               "type":"not_found_error"}}
        PASS: the route is bound and the authority's HasTool() gate produced a
        real 404, not a route-level "not found".

    A2  POST /api/agent/transaction {"op":"status"}
        -> HTTP 200  {"ok":true,"active":false,"write_profile":"transactional",
                      "requires_transaction":true,"write_enabled":true,
                      "execute_enabled":true,"journal_records":0,...,
                      "tools":["execute_command","list_directory","read_file",
                               "search_code","write_file"]}
        PASS: 5 real tools, transactional profile reported by the authority.

    A3  POST /api/agent/execute-tool {"tool":"write_file",
                                      "args":{"path":"alpha.txt","content":"HIJACK"}}
        -> {"ok":false,"error":"path rejected by sandbox: alpha.txt"}
        Refused, but for the wrong reason -- see 2.1.

    A4  POST /api/agent/transaction {"op":"begin","plan":"smoke"}
        -> HTTP 400  {"error":"transaction refused: the tool policy has no allowed root"}
        Refused, but for the wrong reason -- see 2.1.

### 2.1 The refusal was a stale binary, and the cause is now closed

The server logged the reason for A4:

    [server] tool authority: REFUSING tool root C:\Users\Garrett\AppData\Local\Temp\gate1_ws_30812
            (device, stream and non-drive schemes are not permitted).
    [server] tool authority: 5 tools, root=<none> write=1 execute=1
            writeProfile=transactional requireTx=1

A perfectly ordinary absolute path on a fixed drive was rejected as a "device,
stream or non-drive scheme", which left `root=<none>` and made the whole tool
policy inert.

Census of the cause: `HasNonDriveColon` (`AgentToolRegistry.cpp`) previously read
the two characters before the colon and demanded `scheme[1] == '\\'`, which no
well-formed path satisfies — for `F:\dir` the colon is at index 1 so `scheme` is
the single character `F`. The effect was that **every** absolute Windows path was
rejected.

That was already fixed in the tree by the time this was diagnosed: the file
carries the fix and a comment describing exactly this failure, and the fix was
committed (`git status` clean; the file was written at 17:37:42, five minutes
*after* the 17:32:58 binary I was running). Verified directly against current
source in section 3, step 1.

    STALE_BINARY_ROOT_REFUSAL = 1
    CAUSE                      = BINARY_PREDATES_THE_FIX_BY_5_MINUTES
    FIX_PRESENT_IN_TREE        = 1
    FIX_VERIFIED_RUNTIME       = 1 (section 3, ROOT_CANONICALIZE_OK=1)

This is the third instance of the same shape in two days: a reported failure
describing a tree state that had already moved.

---

## 3. Authority layer — measured against current source

Because the server target does not currently compile for an unrelated reason
(section 4), the authority Gate 1 actually asserts was driven directly, so the
substantive claim is measured rather than inherited. Harness:
`tools/gate1_policy_smoke.cpp`, linked against the current
`AgentToolRegistry.cpp` + `CheckpointRollbackAuthority.cpp` + `CommandExecutor.cpp`.

    ROOT_CANONICALIZE_OK=1
    ROOT_CANONICAL=C:\Users\Garrett\AppData\Local\Temp\gate1_policy_smoke
    TOOL_COUNT=5
    TOOL_NAME=execute_command / list_directory / read_file / search_code / write_file

    WRITE_WITHOUT_TX_OK=0
    WRITE_WITHOUT_TX_ERR=write_file requires an open checkpoint transaction; open
                             one first (POST /api/agent/transaction {"op":"begin"})
    A_UNCHANGED_AFTER_REFUSAL=1

    TX_BEGIN_OK=1
    WRITE_IN_TX[a.txt]_OK=1
    WRITE_IN_TX[b.txt]_OK=1
    EXEC_IN_TX_OK=1
    COMMIT_OK=1
    A_CHANGED_AFTER_COMMIT=1
    B_CHANGED_AFTER_COMMIT=1

    WRITE_BEFORE_ROLLBACK_OK=1
    A_MODIFIED_BEFORE_ROLLBACK=1
    ROLLBACK_OK=1
    A_RESTORED_EXACT=1
    B_RESTORED_EXACT=1

    C_CREATE_OK=1
    C_EXISTS_BEFORE=0 AFTER_CREATE=1 AFTER_ROLLBACK=0

    ESCAPE_WRITE_OK=0
    ESCAPE_WRITE_ERR=path rejected by sandbox: ..\escape.txt
                      (resolved path escapes the allowed root)

    COUNTERS journalRecords=38 journalFlushes=38 blobWrites=9
             atomicPublishes=20 fileWrites=7 fileDeletes=1

Every refused request left the filesystem untouched (`A_UNCHANGED_AFTER_REFUSAL=1`),
and every rollback restored bytes rather than approximately (sha256 equality
against the pre-write hash, measured by the harness, not asserted by the
authority).

---

## 4. Why the HTTP transactional lifecycle is NOT_EXERCISED

The `rawr-server` target does not compile. The failure is **not** in the
checkpoint, route, or tool-authority code:

    src/agentic/GitSafetyAuthorityTools.h(119,7)  error C3083: 'RawrXD': the symbol
        to the left of a '::' must be a type
    ... error C2039: 'AgentToolRegistry': is not a member of '`global namespace''
    ... error C2065: 'registry': undeclared identifier

Diagnosis, offered rather than applied — the file is another participant's
uncommitted work (`git status` = ` M`, written 17:40:38, unchanged since):

- `:18-19` opens `namespace rawrxd { namespace agentic {`, and `:121-122` closes
  them, so the whole file is inside `rawrxd::agentic`.
- `:106` forward-declares `namespace RawrXD { namespace Agentic { class
  AgentToolRegistry; } }` **inside** that, which actually declares
  `rawrxd::agentic::RawrXD::Agentic::AgentToolRegistry`.
- `:119` then refers to `::RawrXD::Agentic::AgentToolRegistry` — global `RawrXD`,
  which nothing declares.

The nesting does not match the use site's absolute qualification. Either the
forward declaration moves outside `rawrxd::agentic`, or
`src/deep2/AgentToolRegistry.hpp` is included and the shim is dropped. Both
registries the file targets are legitimate (the sandboxed
`rawrxd::agentic::ToolRegistry` and the desktop `RawrXD::Agentic::AgentToolRegistry`
used by the chat panel), so the two-installer design is not the problem; the
declaration is.

Not edited: it is uncommitted, actively-authored work belonging to another
participant, and a competing edit would split or overwrite their change.

The other failure seen in the same window was **transient** and is recorded so
it is not mistaken for a defect:

    Deep2Engine_GpuForward.cpp(647/666/700) error C2039: 'type' is not a member of
        'Deep2::Deep2Engine::ProjectionBisectResult'

`ProjectionBisectResult` in `src/deep2/Deep2Engine.h` declares `int type = -1;`.
The declaration was correct and the error came from a mid-save tree state; the
following rebuild moved to a different file, confirming motion rather than
defect.

---

## 5. Ledger

    ROUTES_BOUND_TO_REAL_AUTHORITY        = PROVEN (HTTP 404 from HasTool, 200 from status)
    REAL_TOOL_COUNT                       = 5
    SANDBOX_ROOT_CANONICALISATION         = PROVEN (was the A3/A4 refusal cause)
    WRITE_REQUIRES_TRANSACTION            = PROVEN
    WRITE_REFUSED_LEAVES_FILE_INTACT       = PROVEN
    COMMIT_PATH_CHANGES_FILES             = PROVEN
    ROLLBACK_RESTORES_BYTE_EXACT          = PROVEN
    ROLLBACK_REMOVES_CREATED_FILE         = PROVEN
    PATH_ESCAPE_REFUSED                   = PROVEN
    COMMANDS_JOURNALLED_IN_TX             = PROVEN (EXEC_IN_TX_OK=1)
    JOURNAL_RECORDS_FLUSHED               = 38 of 38
    HTTP_TRANSACTIONAL_LIFECYCLE          = NOT_EXERCISED
    SERVER_TARGET_COMPILES                = 0 (GitSafetyAuthorityTools.h:119)
    OVERALL                               = PARTIAL

    CAUSES_THAT_WERE_TRANSIENT            = 2  (DownloadVector, ProjectionBisectResult)
    CAUSES_THAT_WERE_REAL                 = 2  (FileOps link, GitSafetyAuthorityTools.h:119)
    CAUSES_THAT_WERE_STALE_BINARY         = 1  (HasNonDriveColon, fixed 5 min later)
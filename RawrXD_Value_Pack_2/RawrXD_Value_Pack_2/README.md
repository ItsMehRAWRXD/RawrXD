# RawrXD Value Pack 2 — high-value competitor gaps

This is a no-third-party-dependency C++20 source drop for the concrete product gaps identified after the first Scale Value Pack.

## Implemented here

### 1. Lifecycle authority
A thread-safe event bus with these native events:

- SessionStart
- BeforeInference / AfterInference
- BeforeTool / AfterTool
- BeforeMutation / AfterMutation
- BeforeBuild / AfterBuild
- BeforeMerge / AfterMerge
- SessionStop

Events are delivered to in-process subscribers and persisted to an append-only receipt journal. Exceptions in observers cannot break the execution authority.

### 2. Agent Command Center backend
A real state machine for:

- QUEUED
- RUNNING
- VALIDATING
- MERGE_READY
- PASS
- FAIL
- CONFLICT

Each task tracks model, changed files, latest event, validation state, merge state, creation/update time, and emits lifecycle events. Invalid transitions are rejected rather than silently accepted.

### 3. Native Windows browser verifier
`BrowserAuthority` launches or attaches to Microsoft Edge through the Chrome DevTools Protocol using only Win32 + WinHTTP. No Playwright, Node, Python, Selenium, or WebView wrapper is required.

Implemented operations:

- launch/attach browser
- navigate
- execute JavaScript
- query DOM text
- click element
- type into element with input/change events
- capture PNG screenshot
- collect raw console events
- collect raw network loading failures

The implementation uses the browser's remote-debugging endpoint and WinHTTP WebSocket support.

## Integration into RawrXD

Copy this pack under the repository, for example:

```text
rawrxd/
  value_pack2/
    include/
    src/
    cmake/
```

In the root CMake:

```cmake
include(value_pack2/cmake/RawrXDValuePack2.cmake)
target_link_libraries(RawrXD-Win32IDE PRIVATE RawrXD-ValuePack2)
```

Then bind the existing authoritative agent/session code to these APIs. Do **not** create a second inference authority. The intended ownership is:

```text
Win32IDE / Command Center
        |
        +--> existing RawrXD session/orchestrator authority
        |          |
        |          +--> LifecycleBus emits receipts
        |          +--> CommandCenter reflects task state
        |
        +--> BrowserAuthority validates the result
                   |
                   +--> tool result returns to existing Tool Authority
                                   |
                                   +--> existing Deep2 agent repairs/retests
```

## Build

Standalone:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Windows certification:

```powershell
.\scripts\certify_value_pack2.ps1
```

## Gates

Core:

```text
GATE=RAWRXD_VALUE_PACK2_CORE_001
TASK_STATE=PASS
LIFECYCLE_EVENTS>0
RECEIPT_EXISTS=1
VERDICT=PASS
```

Browser:

```text
GATE=RAWRXD_BROWSER_AUTHORITY_001
LAUNCH=PASS
NAVIGATE=PASS
TITLE_READ=PASS
SCREENSHOT=PASS
VERDICT=PASS
```

## Deliberately not duplicated

This pack does not implement another LLM runtime, agent planner, tool authority, model resolver, checkpoint engine, workspace-isolation engine, or merge engine. Those already exist in the RawrXD architecture described in the audit. Duplicating them would make authority consolidation worse.

The strict `Win32IDE -> chat -> Deep2 -> streamed token -> UI` gate is repository-specific and must be wired against the actual Win32IDE/Deep2 headers. This pack does not fake that integration with compatibility symbols.

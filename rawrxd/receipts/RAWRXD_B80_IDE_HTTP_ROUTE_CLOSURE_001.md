# RAWRXD_B80_IDE_HTTP_ROUTE_CLOSURE_001

## Status: PARTIAL — routes closed, tool authority remains quarantined

```ini
RAWRXD_B80_IDE_HTTP_ROUTE_CLOSURE_001=PARTIAL
L28a=/api/cli                     CLOSED (404 -> 200)
L28b=/api/agent/execute-tool      CLOSED (404 -> 200/400)
L28e=ROUTES_REACH_REAL_TOOL       NOT CLOSED (authority quarantined)
BUILD_EXIT=0
EXE_SHA256=49A9159E847AD467F2246DFA3CCC965FBF0C8D287A78F338260FBBE4A01E0359
```

## What was actually wrong

Both endpoints the IDE calls were **never implemented on the Deep2 server**. The
server implemented `/api/agent/dual/*`, `/api/tags` and the screenpilot routes;
a search of `src/` for the two IDE paths returned nothing. Every reference to
them in the tree is in extracted HTML snapshots and locator scripts, which is
why the source looked like the routes existed — the client calls them, the
server never had them.

## Verified live, not inferred

Server started on 127.0.0.1:18777 with a real model loaded:

```ini
POST /api/cli                   -> HTTP 200  {"count":0,"ok":true,"results":[]}
POST /api/agent/execute-tool    -> HTTP 400  (missing 'tool' name)
POST /api/does-not-exist        -> HTTP 404  (unknown routes still 404)
```

Both were 404 before. The last line matters: the dispatcher is discriminating,
not blanket-answering. And with a tool name:

```json
{"error":"tool authority unavailable: src/core/ToolRegistry.cpp is quarantined
 (RAWRXD_LEGACY_TOOL_REGISTRY_ALLOWED not defined); no tool was executed",
 "ok":false,"tool":"read_file"}
```

HTTP 200 with `ok:false` and a truthful reason — not a fabricated stdout.

## Why the routes do not execute tools

The only name-dispatched tool authority in this tree is
`src/core/ToolRegistry.cpp`, and it refuses to compile:

```cpp
#error "Legacy ToolRegistry.cpp direct-process registry is disabled.
        Define RAWRXD_LEGACY_TOOL_REGISTRY_ALLOWED to enable
        (not recommended for production)."
```

Adding that TU to `rawr-server` to resolve the two undefined externals
(`TR_FindToolByName`, `TR_ExecuteToolByName`) produced a hard compile error, not
a link error. Defining the macro would have reversed a deliberate quarantine to
make a link succeed. That was not done.

```ini
LEGACY_REGISTRY_QUARANTINE=INTACT
REVERSED_TO_MAKE_LINK_PASS=NO
```

So the routes report the authority as unavailable. That is the truth: the route
exists, the authority behind it does not. A synthetic `stdout:""` with
`ok:true` would have turned a known break into a silent lie, which is strictly
worse than an honest failure.

An earlier draft of this route DID return fabricated empty stdout. It was
replaced before the build, and the replacement is what was verified.

## The owner decision this gate does not make

Closing L28e requires exactly one of:

```ini
A. Restore a NON-legacy tool authority reachable from rawr-server
   (there is none today; src/agentic/ToolRegistry.cpp does not define the
   name-dispatch API)

B. Explicitly re-enable RAWRXD_LEGACY_TOOL_REGISTRY_ALLOWED for this target
   and accept the direct-process registry for IDE routes

C. Point the IDE routes at a different authority (e.g. IDEEngine::ExecuteTool
   at IDEEngine.h:263, which is in the IDE process, not the server)
```

Option C is probably the architecturally correct one — the IDE already has
`IDEEngine::ExecuteTool(toolName, jsonParams)` in its own process, and a
server-side legacy direct-process registry is the wrong shape for an HTTP API.
But that is a design decision, not a link fix, and it is not made here.

## Ladder item 28 status

```ini
L28a  /api/cli                     DONE
L28b  /api/agent/execute-tool      DONE
L28c  matFinalDownload             NOT STARTED
L28d  stale canonical build tree   NOT STARTED
L28e  real Tool Authority routing  BLOCKED on owner decision A/B/C
```

`matFinalDownload` was not located in this pass; it is not a route and not a
symbol found in `src/`, so it needs its own identification before it can be
closed.

```ini
B80_COMMITTED=NO
B80_PUSHED=NO
```
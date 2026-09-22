# RawrXD ScreenPilot — In-Process Finish Drop

This is the production completion layer for the earlier standalone ScreenPilot
bridge.

The earlier bridge proved:

```text
HTML -> localhost -> rawr.exe -> agent
```

This drop removes the remaining subprocess boundary and provides:

```text
http://127.0.0.1:11435/screenpilot
    -> existing RawrXD LocalServer
    -> ScreenPilot route adapter
    -> canonical Agent Coordinator
    -> canonical Tool Authority
    -> Deep2 / files / search / patch / terminal / git / build / tests
```

No Node, Electron, Qt, Ollama, cloud API, Boost, cpp-httplib, JSON library, or
other dependency is introduced.

## What this closes

- One server: existing `127.0.0.1:11435`
- Same-origin ScreenPilot UI
- No `file://` trust in production
- No `rawr.exe` subprocess hop
- No duplicated browser tool implementation
- Session guard
- Exact localhost Host/Origin validation
- Workspace-root confinement
- ASK / PLAN / BUILD / AGENT transport
- NDJSON streaming
- Cancellation propagated into the authority callback
- Canonical Tool Authority callback ABI
- E2E certification script

## Integration

Add:

```cmake
add_subdirectory(path/to/rawrxd_screenpilot_inprocess)
target_link_libraries(RawrXD-Win32IDE PRIVATE rawrxd_screenpilot_inprocess)
```

Then adapt the short example in:

```text
integration/localserver_hook_example.cpp.txt
```

to your existing LocalServer and Agent Coordinator names.

The only project-specific line that cannot be guessed outside your repository
is the call to your actual canonical coordinator, represented by:

```cpp
app->agentCoordinator.Run(...)
```

That line must call the already-authoritative RawrXD agent/tool registry path.
Do not add direct filesystem/process execution to this adapter.

## Serve the HTML from localhost

Final production URL:

```text
http://127.0.0.1:11435/screenpilot
```

Serve:

```text
F:\ide_chatbot.html
```

at `/screenpilot`, and `web/screenpilot_client.js` at
`/screenpilot/screenpilot_client.js`.

Keep:

```cpp
cfg.allow_null_origin = 0;
```

That closes the security weakness of allowing arbitrary `Origin: null`
documents to request a privileged local session.

## Final proof

Run:

```powershell
.\tests\certify_screenpilot_inprocess.ps1 `
  -Base "http://127.0.0.1:11435" `
  -Model "<real-local-model>" `
  -Workspace "F:\~dev"
```

Then run the mutation authority gate:

```powershell
.\tests\certify_screenpilot_mutation.ps1 `
  -Base "http://127.0.0.1:11435" `
  -Model "<real-local-model>" `
  -Workspace "F:\~dev"
```

And verify the production adapter contains no hidden direct-execution fallback:

```powershell
.\tests\static_contract_check.ps1
```

The feature is complete when the following are all real:

```text
SCREENPILOT_INPROCESS_ROUTE=PASS
SCREENPILOT_SESSION_GUARD=PASS
SCREENPILOT_BAD_TOKEN_REJECT=PASS
SCREENPILOT_WORKSPACE_BOUNDARY=PASS
SCREENPILOT_ASK_MODE=PASS
SCREENPILOT_PLAN_MODE=PASS
SCREENPILOT_BUILD_MODE=PASS
SCREENPILOT_AGENT_MODE=PASS
SCREENPILOT_TOOL_AUTHORITY=PASS
SCREENPILOT_WRITE=PASS
SCREENPILOT_READ=PASS
SCREENPILOT_SEARCH=PASS
SCREENPILOT_DELETE=PASS
SCREENPILOT_MUTATION_E2E=PASS
SCREENPILOT_LOCAL_AGENT_E2E=PASS
SCREENPILOT_GATE_CLEANUP=PASS
SCREENPILOT_STATIC_CONTRACT=PASS
SCREENPILOT_AGENT_MUTATION_CERT=PASS
```

After those pass, disable/remove the temporary standalone `:11437` bridge.

## Remaining repository-specific work

There are only three repository-specific edits this generic source drop cannot
safely invent:

1. Map your existing LocalServer request/response objects to
   `RawrXD_SP_HttpRequestV1` / `RawrXD_SP_HttpSinkV1`.
2. Map `AuthorityRun()` to the exact canonical RawrXD Agent Coordinator /
   Tool Authority entrypoint.
3. Add two static routes for the existing HTML and `screenpilot_client.js`.

Those are wiring edits, not missing architecture.

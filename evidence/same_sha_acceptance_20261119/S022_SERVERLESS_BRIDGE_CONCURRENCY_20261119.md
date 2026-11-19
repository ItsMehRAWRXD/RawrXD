# S022 — Serverless Deep2 bridge concurrent isolation

Date: 2026-11-19  
Source SHA: `952ee3ba69a9b134aaf7a4a11ba388c111154566`

## Source contract

`Win32IDE_Deep2Bridge` owns one engine, one generation worker, one callback,
and one accumulated response. `GenerateStream` rejects a second request while
`m_generating` is true, and joins a completed worker before reusing the thread
slot. Callback delivery is serialized by `m_callbackMutex`.

This provides same-bridge serialization; it is not concurrent request
execution. The request-scoped `runtime_graph_executor::ExecuteToken` API is a
separate lower-level boundary and is not exercised by the retained IDE probe.

## Acceptance status

No two-request runtime test exists for distinct prompts, KV state, logits, or
callbacks. Therefore cross-request isolation is not claimed. The correct
current behavior is fail-closed rejection of overlapping requests on one
bridge instance.

```ini
SAME_BRIDGE_OVERLAP=REJECTED_BY_DESIGN
CALLBACK_SERIALIZATION=SOURCE_VERIFIED
KV_LOGIT_CROSS_CONTAMINATION=NOT_TESTED
SEPARATE_REQUEST_RUNTIME=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

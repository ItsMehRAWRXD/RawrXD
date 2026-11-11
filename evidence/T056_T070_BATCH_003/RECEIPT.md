# T056–T070 Batch 003 — Runtime Receipt

## Authority

| Field | Value |
|---|---|
| Candidate executable | `F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe` |
| Candidate size | `6,066,688` bytes |
| SHA before test | `2DBC0030DAE12AA1E8160DF4B6BA31D0C4F06272479D9B767DF8C798753D5F7A` |
| SHA after test | `2DBC0030DAE12AA1E8160DF4B6BA31D0C4F06272479D9B767DF8C798753D5F7A` |
| Tested PID | `28916` |
| Process start | `2026-11-04T00:35:54.3111064-05:00` |
| Source HEAD observed | `4e9447beecaf85963859c487d29e86473560ceca` |
| Promotion | `0` |

The executable remained unchanged during the observed run. The earlier sealed references were not overwritten.

## Physical runtime evidence

### Real document and editor focus

- Supported File → Open opened `F:\rawrxd\evidence\T056_T070_BATCH_003\ghosttext_document.cpp`.
- The native editor control was the active `RichEdit20W` editor (`ID=1001`), not a detached test control.
- The accessibility state showed the opened document path and the actual document contents.
- A real editor prefix was typed through the focused native editor.

### GhostText acceptance

The selected GhostText route was `Local models / Ollama / qwen3:8b`.

Before acceptance, the native editor ended with:

```text
std::string describe_user(const std::string& name) { return
```

The visible GhostText suggestion was:

```text
"Hello, " + name + "!"; }
```

After pressing Tab with the native editor focused, the native editor ended with:

```text
std::string describe_user(const std::string& name) { return "Hello, " + name + "!"; }
```

The overlay disappeared after Tab. This is a real inference/render/acceptance path and proves the expected suffix was inserted once in the observed before/after editor state.

### Stale-response probe

The same real editor then received:

```text
std::string stale_probe(const std::string& value) { return
```

Before the pending suggestion was allowed to complete, a real `x` edit was entered. The immediate post-edit native editor state ended with `return x`; no suggestion overlay was present in that observation. The current build's detailed GhostText response/eligibility logger was not emitted into the available runtime log, and the UI helper timed out while waiting for the long response window. Therefore the strict late-response proof remains open.

### Product token receipt

The same PID's product receipt in `F:\rawrxd\ollama_debug.log` records:

```ini
PID=28916
REQUEST_GENERATION=5
MODEL=bigdaddyg-productivity-local:latest
PROMPT_ACCEPTED=PASS
EFFECTIVE_CONTEXT=65536
MAX_OUTPUT_TOKENS=4096
GENERATED_TOKENS=471
PROMPT_TOKENS=413
DONE_REASON=stop
```

The native ChatWindow contained `TOKEN64_DONE` and a 773-character response. This closes the product-level `>=64` generated-token threshold for this candidate, but does not prove the separate 100-line formatting requirement.

### Long-response observation

- `TOKEN64_DONE`: present in the native ChatWindow.
- Product generation: 471 tokens, `DONE_REASON=stop`.
- Exact 100 numbered entries: not met; the observed output contained 64 numbered entries before the marker.
- Native edit-control stored-length measurement: not verified. Direct `WM_GETTEXTLENGTH`/RichEdit retrieval did not yield a reliable value; accessibility text was used only for visible editor state.

### ChatWindow cancellation and recovery

- Request A was stopped through the native Stop control and displayed `[stopped] generation cancelled`.
- Subsequent requests rendered in the same PID without restarting the IDE.
- One B request was activated twice by the automation harness; therefore the strict no-duplicate Request-B criterion is not sealed by this run.

## Gate disposition

| Gate | Disposition | Evidence basis |
|---|---|---|
| T056 candidate identity | PASS | Full SHA and size recorded |
| T057 supported document open | PASS | Native File → Open and path visible |
| T058 explicit GhostText routing | PASS | `qwen3:8b` selected and route logged |
| T059 native editor focus/input | PASS | Native `RichEdit20W` focus and real text input |
| T060 GhostText inference/render | PASS | Suggestion visible in native editor session |
| T061 Tab acceptance | PASS | Overlay replaced by inserted suffix |
| T062 exact insertion behavior | PASS behaviorally | Before/after AX text shows expected suffix once |
| T063 stale-response rejection | NOT SEALED | Invalidation edit observed; late callback eligibility not logged |
| T064 ChatWindow routing | PASS behaviorally | Same PID rendered real responses |
| T065 product Token64 | PASS | 471 generated tokens, stop receipt, marker visible |
| T066 exact 100-line response | FAIL / OPEN | Marker present, but only 64 numbered entries observed |
| T067 cancellation recovery | PASS behaviorally | Stop plus same-session subsequent responses |
| T068 native stored-text measurement | NOT VERIFIED | Retrieval path did not produce a reliable native length |
| T069 hash stability | PASS | Pre/post SHA match |
| T070 batch seal | OPEN | T063, T066, and T068 remain unresolved |

## Controls

```ini
SOURCE_MUTATION=0
BINARY_MUTATION=0
REBUILD_DURING_RUN=0
PROMOTE=0
CERTIFIED=0
```

This receipt records only observations made against the exact executable above. It does not inherit results from `08F2…`, `648A…`, `3C750E19…`, or any other binary.

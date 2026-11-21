# GUI probe hardening — 2026-11-21 (Sprint 5)

## Defect
`SendMessageTimeoutW` returns a **transport success flag** (nonzero on
success); the **message result** is delivered via the `out` parameter. Several
probes used the return value as the result for combo queries, so
`CB_GETCOUNT`/`CB_GETCURSEL` reported the success flag instead of the value.
This produced the false historical reading `CB_COUNT=1 CB_CURSEL=1`
(`gui5_result.txt`, now marked SUPERSEDED).

## Corrected probes (return value -> out param)
- `gui_chat3.ps1` — `TO` now returns the out-param result. This is the probe
  that produced `gui5_result.txt`.
- `gui_chat2.ps1` — `MODEL_ITEMS` now reads `$res` (out param).
- `gui_model_selector_probe.ps1` — `CB_GETLBTEXTLEN` length now reads `$r0`.
- `gui_repro2.ps1` — `CB_GETLBTEXTLEN`/`CB_GETLBTEXT` now read `$r0` and use
  the correct constants (`0x0150`, `0x0148`; the `+0x10`/`+0x0200` offsets
  were wrong).

## Already-correct references
- `gui_model_selector_probe3.ps1` — reads counts from the out param; used a
  fixed unmanaged buffer for `CB_GETLBTEXT` (no length round-trip).
- `gui_selector_inventory_probe.ps1` — reference probe. `SendMsg` throws when
  the transport return is zero, so a timeout can never masquerade as a result;
  the signed result (`CB_ERR=-1`) is preserved because it comes from the out
  param.

## Acceptance (runtime, this build)
```
CTRL 1226 COUNT=3 CURSEL=2
  ITEM[0]='Deep2 (Vulkan)'
  ITEM[1]='Strata (Deep2 + residency)'
  ITEM[2]='Ollama (HTTP)'
CTRL 1226 BLANK_ITEMS=0
CTRL 1206 COUNT=234 CURSEL=0
CTRL 1206 BLANK_ITEMS=0
```
=> 1226 reports exactly three entries; 1206 reports its actual inventory;
zero blank items; signed results preserved; transport failure distinguishable.

## Remaining
`git grep -nE 'SendMessageTimeout|SendTO' -- '*.ps1'` shows additional
historical probes (CC79_RUNTIME_001, FULL_FEATURE_ONESHOT_001, etc.). Most use
`SendMessageW` (whose return IS the result) and are unaffected. Any that assign
the `SendMessageTimeoutW` return to a combo count/length should be migrated to
the `SendMsg` pattern above; historical evidence remains superseded.
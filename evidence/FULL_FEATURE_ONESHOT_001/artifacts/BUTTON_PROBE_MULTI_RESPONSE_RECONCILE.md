# BUTTON_PROBE_MULTI_RESPONSE_RECONCILE

ASOF_UTC=2026-11-09T14:42:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82%_UNCHANGED
EXACTLY_ONCE=NOT_VERIFIED

## Observation
Multiple AI response blocks appeared after one visible `button-probe` submission.
Does **not** establish: duplicate requests vs repeated callbacks vs transcript rendering.

| Gate | Evidence status |
|------|-----------------|
| Dispatch IDs visible | Confirmed: `1`, `2` |
| Exactly one request per click | **NOT_VERIFIED** |
| Exactly one response per request | **NOT_VERIFIED** |
| Ctrl+Enter dispatch | Not demonstrated here |
| Model’s `button-probe` instructions | Unsupported generated content — **do not use as test procedure** |

`button-probe` was a test message. Model invented a technical explanation; that answer is **not** evidence about the Send button.

## Next check (mandatory correlation)
```
input event → dispatch ID → backend request → response start/end → transcript insertion
```
Include originating pane and session. Distinguish duplicate execution from duplicate display; trace any PowerShell text entering chat.

## Law
```
MULTI_RESPONSE_BLOCKS ≠ PROVEN_DUPLICATE_SEND
GENERATED_BUTTON_PROBE_HOWTO ≠ HARNESS
EXACTLY_ONCE=NOT_VERIFIED
PROMOTE=0
AUDIT_SEAL_UNCHANGED=1
```

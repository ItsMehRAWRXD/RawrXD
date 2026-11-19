# End-to-end verification restart checkpoint

The continuation is being reset to the last genuine product-path evidence rather than treating later source audits as completion.

## Last retained end-to-end checkpoints

- S018/S019: in-process Deep2 bridge loaded TinyLlama and generated 27 bytes with retained GPU-forward counters, zero reported CPU fallback, and exit 0.
- S024: native IDE serverless chat smoke produced a response through the in-process Deep2 bridge with HTTP stopped.

## Why these do not close the current gate

Both receipts are retained evidence from older executables. S024 also recorded zero GPU dispatches for the GUI run. They therefore establish the correct test boundary, not current production acceptance.

## Restart order

1. Build a fresh isolated native executable from the current source.
2. Run the in-process bridge load/generate test with the HTTP server stopped.
3. Require request-attributable GPU dispatches greater than zero, zero unintended CPU fallbacks, finite output, and clean teardown.
4. Run the corrected Win32 GUI route using input control 1202 and verify the response plus GPU witness.
5. Only after that resume cancellation, model switching, reclaim, and multi-request tests.

```ini
E2E_RESTART_CHECKPOINT=IDENTIFIED
LAST_RETAINED_SERVERLESS_BRIDGE= S019
LAST_RETAINED_GUI_SMOKE=S024
FRESH_CURRENT_SHA_E2E=OPEN
GUI_GPU_FORWARD=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

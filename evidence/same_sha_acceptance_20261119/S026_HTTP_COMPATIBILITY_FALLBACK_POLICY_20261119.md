# S026 — HTTP compatibility and fallback policy

Date: 2026-11-19  
Source SHA: `c1f1217852f39e13b6006428257c6e3ea9b92435`

## Source findings

The native IDE keeps HTTP/Ollama as an optional route while local GGUF model
entries use the native Deep2 route. The route switch is explicit in the chat
model source selection:

- Ollama entries call the WinHTTP streaming implementation.
- Local GGUF entries validate tensor-bearing GGUF content, initialize
  `Deep2Bridge`, load the selected path, and call the in-process generation
  path.
- Missing native Deep2 initialization or model loading fails the request with
  an explicit error; it is not silently reported as a successful response.
- The dedicated Deep2 probe requires an explicit model path and fails closed
  when both supported environment variables are absent.

## Acceptance status

The serverless path is source-wired and prior receipts demonstrate it without
HTTP. A fresh route A/B run with the current executable was not performed
because the native IDE link remains blocked by the locked output binary.

```ini
HTTP_ROUTE=OPTIONAL
NATIVE_GGUF_ROUTE=IN_PROCESS_DEEP2
NATIVE_LOAD_FAILURE=FAIL_CLOSED
HTTP_FALLBACK_POLICY=SOURCE_VERIFIED
FRESH_ROUTE_AB_RUNTIME=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

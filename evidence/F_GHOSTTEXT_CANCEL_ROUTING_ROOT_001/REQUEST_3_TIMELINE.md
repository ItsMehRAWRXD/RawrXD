# Request 3 timeline

- Candidate: `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`
- Candidate SHA-256: `70E6B1700F8EDF7A3770F63A5B89565AB05798CAB4B8DFC784200153B786F9DA`
- `03:16:35` `GHOSTTEXT_TRIGGER request_id=3 generation=18 editor_bytes=39`
- `03:16:35` `GHOSTTEXT_REQUEST_SENT request_id=3`
- `03:16:35` runtime route: `bigdaddyg-productivity-local:latest backend=ollama`
- `03:16:37` `GHOSTTEXT_RESPONSE_RECEIVED request_id=3 success=1 response_bytes=99`
- `03:16:37` `GHOSTTEXT_RENDERED request_id=3 response_bytes=99`

The physical action sequence sent Escape immediately after editing, but no `GHOSTTEXT_CANCELLED` event was observed before rendering. Therefore request 3 was not invalidated at the observable commit boundary.

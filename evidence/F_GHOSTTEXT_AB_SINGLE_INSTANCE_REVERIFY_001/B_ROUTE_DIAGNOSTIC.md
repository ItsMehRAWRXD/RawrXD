# Request B route diagnostic

The candidate Debug trace and IDE log recorded:

```ini
REQUEST_B_ROUTE=bigdaddyg-productivity-local:latest
REQUEST_B_BACKEND=ollama
REQUEST_B_SUCCESS=0
REQUEST_B_RESPONSE_BYTES=0
```

This is a route/execution failure for the tested Auto Local selection, not evidence that Ollama or Qwen is unavailable.

Source inspection shows Auto Local is intended to follow the selected Ollama chat model in `src/win32app/Win32IDE_GhostTextIntegration.cpp` (the `m_selectedChatModel` branch). The physical run did not select Qwen, so that branch was not independently demonstrated.

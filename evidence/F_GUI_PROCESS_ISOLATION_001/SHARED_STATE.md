# Shared State Assessment

- Startup logger writes to `%LOCALAPPDATA%\RawrXD\logs\RawrXD_IDE.log`, a shared path.
- The legacy `Win32IDE` logger also creates relative `logs\RawrXD_IDE_*.log` files under the process working directory.
- PowerShell tracing includes a fixed `F:\rawrxd\ps_trace.log` path.
- Other runtime/configuration paths are selected from environment or current working directory; no complete per-instance override contract was found.
- Ollama is a shared local HTTP service at `localhost:11434`, so model-request state is not process-private.

Therefore a second instance cannot be declared isolated merely because it has a different PID.

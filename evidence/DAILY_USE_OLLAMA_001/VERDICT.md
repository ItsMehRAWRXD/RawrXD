# Daily-use Ollama candidate — 2026-11-08

## Scope

This candidate hardens the shared Ollama client used by native GhostText and
agentic/chat integrations. Promotion and certification remain disabled.

## Implemented

- JSON request construction now uses `nlohmann::json`, so prompts, model names,
  stop strings, and chat content are escaped correctly.
- Configured Ollama base URL, host, port, path, HTTP/HTTPS mode, and client
  timeout are honored by the WinHTTP transport.
- `/api/chat` message content is exposed as the unified response text.
- Ollama API and malformed-response errors are preserved in `error_message`.
- Empty transport responses fail closed instead of being reported as success.

## Runtime witness

The local service at `http://127.0.0.1:11434` reported version `0.40.15`.
A real `/api/generate` request using `qwen2.5-coder:1.5b-base`, a quoted prompt,
and a newline completed with `done=true` and 4 generated tokens.

## Build status

The native candidate build was attempted. It was blocked before compiling this
translation unit by the active MSVC/Vulkan environment: standard headers
`cstdint` and `stdbool.h` were not found while compiling the Vulkan dependency.
A fresh no-Vulkan configure was also blocked because the current shell does
not expose a C/C++ compiler to CMake. No binary was replaced or promoted.

## Disposition

```ini
OLLAMA_CLIENT_PATCH=IMPLEMENTED
OLLAMA_LOCAL_RUNTIME=REAL_SMOKE_PASS
NATIVE_CANDIDATE_BUILD=HELD_TOOLCHAIN
PRODUCTION_BINARY=UNCHANGED
PROMOTE=0
CERTIFIED=0
```

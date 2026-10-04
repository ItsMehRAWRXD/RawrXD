# RAWRXD_CMAKE_OPTION_CENSUS_001

Status: MEASURED
Date: 2026-10-04

## Summary

```ini
TOTAL_OPTIONS=203
DEFAULT_OFF=179
DEFAULT_ON=8
OTHER=16  (commented, malformed, or non-standard)
```

## The 8 Always-Enabled Options (default=ON)

```ini
RAWR_ENABLE_VULKAN                    = ON   # Vulkan SDK for GPU compute
RAWRXD_ENABLE_VALIDATION               = ON   # Runtime tensor dumping for parity
RAWRXD_BUILD_RAWRENGINE                = ON   # RawrEngine.exe target
RAWRXD_ENABLE_HEAVY_GATES             = ON   # Heavy ownership/symbol guards in self_test_gate
BUILD_RAW_SERVER                      = ON   # OpenAI-compatible server (port 11435)
RAWRXD_BUILD_ADDRESS_RESOLVER_NATIVE   = ON   # Native crash address resolver
RAWRXD_BUILD_LSP_SERVER               = ON   # VS Code LSP server
RAWRXD_BUILD_DAP_ADAPTER              = ON   # VS Code DAP adapter
```

## Notable Default-OFF Categories

### Deep2 Certification Gates (54+ options)
- `BUILD_DEEP2_K2_*` — K2 model certification suite (MLA, GPU stream, etc.)
- `BUILD_DEEP2_TOKEN_GATE` — Minimal one-token generation gate
- `BUILD_DEEP2_STREAMER_CERT` — Deep2 streamer certification
- `BUILD_DEEP2_PARITY_CERT` — Deep2 parity certification

### Performance / Benchmark Gates (20+ options)
- `BUILD_DEEP2_K2_USEFUL_TPS_001` — Useful TPS benchmark
- `BUILD_DEEP2_K2_TPS_RAINBOW_CERT` — TPS rainbow certification
- `production_regime_sweep` target exists but no option gates it

### Win32IDE Build Options
- `RAWRXD_BUILD_WIN32IDE` = OFF (legacy IDE target)
- `RAWRXD_BUILD_LEGACY_CERTS` = OFF
- `RAWRXD_PRODUCTION_STRIP_STUB_SOURCES` = OFF
- `RAWRXD_ENABLE_MISSING_HANDLER_STUBS` = OFF

### Security / Safety Gates
- `RAWRXD_ENABLE_ASAN` = OFF (AddressSanitizer)
- `RAWRXD_STRICT_AGENTIC_REALITY` = OFF (strict agentic reality check)
- `RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK` = OFF (stub fallback for agentic)

### Build System Features
- `RAWRXD_BUILD_CLI` = OFF (rawrxd CLI console target)
- `RAWRXD_BUILD_RAWRENGINE` = ON (but RAWRXD_BUILD_CLI is OFF — the CLI that uses it)

## Key Finding: The `rawr` CLI is NOT Built by Default

```ini
RAWRXD_BUILD_CLI=OFF
```

The `rawr` executable (which includes `dump`, `reverse`, `modes`, `audit`, `gate`, `cert`) is gated OFF. It only builds when explicitly enabled:

```bash
cmake -S rawrxd -B build -DRAWRXD_BUILD_CLI=ON
```

This is why earlier integration work required manual CMakeLists.txt edits — the `rawr` target is not part of the default build graph.

## Classification

```ini
DEFAULT_ENABLED_PRODUCT_TARGETS   = 8
DEFAULT_DISABLED_PRODUCT_TARGETS  = ~40
NEVER_ENABLED_CERT_GATES          = 54+
UNREACHABLE_WITHOUT_FLAG          = rawr CLI, legacy certs, K2 suite
SILENTLY_FORBIDDEN                = NONE  (every gate has an explicit option)
UNPROVEN_GATES                    = ALL 179 OFF options
VERDICT                           = CENSUS_COMPLETE
```

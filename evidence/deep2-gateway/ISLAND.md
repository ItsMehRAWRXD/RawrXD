# Deep2 Gateway Certification Island vs Sovereign Bootstrap

## Isolation decision (locked)

```
Ship / C++23 / std::expected   →  IDE + full runtime path (blocked here)
Deep2 Gateway Certification    →  Win32 + WinHTTP island (this tree)
Sovereign assembler/linker     →  separate bootstrap ladder
Product E2E (rawr run/agent)   →  separate product ladder
```

Do **not** couple Deep2 gateway certification through Ship headers.

## Current island

```
src/deep2/certification/
  Deep2_Cert_Main.cpp          # client tests (health/models/chat/mcp/telemetry)
  Deep2_Cert_MockGateway.cpp   # selftest listener :11435
  minimal_result.hpp           # C-ABI result (MASM/sovereign-ready)
  build_standalone.bat         # optional cl.exe path

cmake/Deep2GatewayCertStandalone.fragment.cmake
```

## Build / run

```powershell
cmake --build G:\~dev\rawrxd\build-fd --target Deep2_Gateway_Runtime_Certification -j 4
G:\~dev\rawrxd\build-fd\bin\Deep2_Gateway_Runtime_Certification.exe --selftest
# live against a real gateway:
G:\~dev\rawrxd\build-fd\bin\Deep2_Gateway_Runtime_Certification.exe --live
```

Seal:

```
DEEP2_GATEWAY_RUNTIME_CERTIFICATION=PASS
evidence/deep2-gateway/SEAL.txt
```

## Maturity map (toolchain vs this island)

| Level | Claim | Status |
|------:|-------|--------|
| 0 | Architecture exists | yes |
| 1 | Individual tools execute | yes |
| 2 | Compiler pipeline produces binaries | next (Sovereign) |
| 3 | Compiler rebuilds itself | next |
| 4 | RawrXD built by Sovereign | later |
| 5 | External ecosystem | later |

Gateway cert is an early **sovereign-compatible island** for Level-1→2 validation of a small PE, not the full IDE bootstrap.

## Valuation framing (keep separate)

| Layer | Meaning |
|-------|---------|
| Implemented capability | code exists in tree |
| Verified execution | cert PASS with evidence |
| Market / strategic value | only after Levels 2–4 |

Do not price language-registration breadth as verified platform value.

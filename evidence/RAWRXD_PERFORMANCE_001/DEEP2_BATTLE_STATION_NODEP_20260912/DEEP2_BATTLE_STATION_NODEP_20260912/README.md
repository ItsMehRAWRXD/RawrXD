# Deep2 Battle Station — no dependency sidecar

Purpose: observe a frozen Deep2 TARGET=64 certification run without linking into, modifying, restarting, or promoting the cert binary.

## Guarantees
- No writes to cert EXE/log.
- Computes an internal SHA-256 of the cert binary and compares it to the caller-supplied frozen hash.
- Checks PID liveness.
- Parses highest `AR_FORWARD pos=` and detects any `sealed_logits_reuse=1`.
- Reads separate vendor/local smoke status files.
- Keeps `ENDURANCE_PRODUCT_MERGE=DEFERRED` and `PROMOTE=0` as sidecar policy.
- Can *observe* terminal TARGET=64 PASS only if the cert log itself reports PASS, pos>=63, sealed reuse stays zero, and all five counters equal 64.
- It never mints product/cert authority.

## Example
```bat
battle_station.exe ^
  --pid 6852 ^
  --cert G:\~dev\rawrxd\...\deep2_benchmark.exe ^
  --sha256 <FROZEN_CERT_SHA256> ^
  --log G:\~dev\rawrxd\...\target64_run1.log ^
  --vendor G:\~dev\rawrxd\...\vendor_smoke.txt ^
  --local G:\~dev\rawrxd\...\local_smoke.txt
```

The smoke files need only contain `VENDOR_SMOKE=PASS` and `LOCAL_SMOKE=PASS` respectively.

Build with `build_msvc.bat`. It initializes VS2022 Build Tools via `vcvars64.bat` itself.

# VAL-051.2.A Known-Good Baseline

## Commit
- **SHA:** `33f0ff013`
- **Branch:** `main`
- **Remote:** `final` → https://github.com/ItsMehRAWRXD/RawrXD-IDE-Final.git
- **Date:** 2026-08-22

## Executable
- **Path:** `D:\rawrxd\build-novalidation\bin\val_051_2_a_real_token.exe`
- **SHA256:** `12ED3CEC8FF6E14BAF52C10BEE3548D9FFBD1B39FE93B00E61E05F509C914880`
- **Config:** RelWithDebInfo
- **CRT:** /MT (static)

## Expected Result (Deterministic)
- **Prompt:** `"Hello"`
- **Input token:** `10994`
- **Sampled token ID:** `9693`
- **Output text:** `"otto"`
- **Input checksum:** `-5815713594341935019`
- **Output checksum:** `-5816521735388670104`

## Build Configuration
- **Directory:** `D:\rawrxd\build-novalidation`
- **Target:** `val_051_2_a_real_token`
- **Config:** RelWithDebInfo
- **CRT:** /MT (static)

## Evidence Output Paths (Ambiguous — needs fix)
The executable writes to a relative `evidence/` directory:
- `F:\~dev\evidence\VAL-051-2-A-EXECUTED.json` (when run from `F:\~dev`)
- `D:\rawrxd\evidence\VAL-051-2-A-EXECUTED.json` (when run from `D:\rawrxd`)

**Recommendation:** Change evidence path to absolute or configurable.

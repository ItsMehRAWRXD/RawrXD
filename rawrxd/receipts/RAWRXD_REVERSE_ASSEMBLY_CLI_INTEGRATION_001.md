# RAWRXD_REVERSE_ASSEMBLY_CLI_INTEGRATION_001

Status: MEASURED
Date: 2026-10-04

## Build Evidence

- CMake configure: PASS (exit 0, Generating done)
- Build target: `rawr`
- Output: `rawrxd/build/bin/Release/rawr.exe`
- New source files compiled:
  - `src/cli/RawrCommandAuthority.cpp`
  - `src/cli/ReverseAssemblyEngine.cpp`
  - `src/deep2/rawr_run.cpp` (modified with reverse dispatch)
- Warnings: 1 (C4100 unreferenced parameter in ResponseCodedAgent.cpp, pre-existing)
- Errors: 0

## Runtime Evidence

### Test 1: Known pattern match
```
$ rawr reverse models/reverse_assembly/BigDaddyG-Reverse-Model-v1.5.json "push ebp"
PREDICTED_BYTE=0x55 CONFIDENCE=1.0000
Exit code: 0
```

### Test 2: Unseen input (null path)
```
$ rawr reverse models/reverse_assembly/BigDaddyG-Reverse-Model-v1.5.json "QQQQ"
PREDICTED_BYTE=NONE CONFIDENCE=0.0000
Exit code: 1
```

### Test 3: Missing model file
```
$ rawr reverse nonexistent.json "test"
reverse: load failed: Cannot open file: nonexistent.json
Exit code: 9
```

### Test 4: Missing arguments
```
$ rawr reverse
usage: rawr reverse <model.json> <input text>
Exit code: 64
```

## Certification

| Check | Result |
|---|---|
| Source compiles in shipping target | PASS |
| Links into `rawr.exe` | PASS |
| Loads real JSON model from disk | PASS |
| Pattern match produces predicted byte | PASS |
| Unseen input returns nullopt (no fabrication) | PASS |
| Error handling for missing file | PASS |
| Error handling for missing args | PASS |
| No hardcoded confidence values | PASS (measured ratio) |
| No stub fallback | PASS (real engine code) |

VERDICT=PASS

# VAL-012 Quick Start Guide
## Autonomous Loop Closure - Vertical Slice

**Goal:** Prove one complete autonomous workflow end-to-end.

---

## Prerequisites

- CMake 3.20+
- C++20 compiler (MSVC 2022 or MinGW)
- nlohmann/json (included in 3rdparty/)

---

## Build (Windows)

```batch
val012_build.bat
```

Or manually:

```batch
mkdir build-val012
cd build-val012
cmake ..
cmake --build . --target val012_test --config Release
```

---

## Run

```batch
cd build-val012
Release\val012_test.exe
```

Expected output:
```
========================================
VAL-012: Autonomous Loop Closure Test
========================================

[TEST 1] Creating Val012Controller...
  ✓ Controller created

[TEST 2] Executing goal...
  Goal: "Add --version command to CLI"
  Evidence dir: evidence/val-012-test-...

[VAL-012] Starting autonomous execution
[VAL-012] Goal: "Add --version command to CLI"
[VAL-012] Phase 1: Receiving goal...
[VAL-012] State: IDLE -> GOAL_RECEIVED
[VAL-012]   Goal ID: <uuid>
[VAL-012] Phase 2: Planning...
[VAL-012] State: GOAL_RECEIVED -> PLANNING
[VAL-012]   Plan created with 4 steps
[VAL-012]     1. Locate CLI argument parser
[VAL-012]     2. Add --version flag handler
[VAL-012]     3. Add version output function
[VAL-012]     4. Update help text
...
[VAL-012] ✓ Task completed in <duration>ms

=== VAL-012 Test Results ===
Controller created: PASS
Goal received: PASS
Plan generated: PASS
Changes applied: PASS
Build triggered: PASS
Tests run: PASS
Evidence saved: PASS
Completion valid: PASS

Overall: ✓ VAL-012 PASSED
```

---

## Verify Evidence

```batch
cd evidence\val-012-test-<timestamp>

type completion.json
```

Expected completion.json:
```json
{
  "success": true,
  "goal_id": "<uuid>",
  "summary": "Task completed successfully",
  "steps_completed": 4,
  "total_steps": 4,
  "files_modified": [
    "src/cli/parser.cpp",
    "src/cli/version.h"
  ],
  "build_succeeded": true,
  "tests_passed": 47,
  "tests_failed": 0,
  "total_duration_ms": 42000,
  "evidence_path": "evidence/val-012-test-..."
}
```

---

## Evidence Structure

```
evidence/
└── val-012-test-<timestamp>/
    ├── manifest.json      # Run metadata
    ├── goal.json          # User input
    ├── plan.json          # Generated plan
    ├── changes.json       # File modifications
    ├── build.log          # Build output
    ├── build.json         # Structured build result
    ├── test.log           # Test output
    ├── test.json          # Structured test result
    ├── events.json        # State transitions
    └── completion.json    # Final report
```

---

## Debug

### View event trace:
```batch
type evidence\val-012-test-<timestamp>\events.json
```

### View build log:
```batch
type evidence\val-012-test-<timestamp>\build.log
```

### View test log:
```batch
type evidence\val-012-test-<timestamp>\test.log
```

---

## Troubleshooting

### Build fails
- Check CMake version: `cmake --version` (need 3.20+)
- Check compiler: `cl.exe` or `g++ --version`
- Verify nlohmann/json exists in 3rdparty/

### Test fails
- Check evidence directory created
- Verify write permissions
- Review console output for errors

### No evidence
- Ensure evidence/ directory exists
- Check file permissions
- Review test output for errors

---

## Next Steps

1. **Verify VAL-012A** (Goal → Plan → Change)
   - ✓ Evidence exists
   - ✓ Plan generated
   - ✓ Changes applied

2. **Implement VAL-012B** (Change → Build)
   - Add real build trigger
   - Capture actual build output

3. **Implement VAL-012C** (Build → Test)
   - Add test execution
   - Capture test results

4. **Complete VAL-012D** (Full Loop)
   - All phases integrated
   - End-to-end validation

---

## Success Criteria

✓ One autonomous task executes end-to-end  
✓ Evidence chain is complete  
✓ No human intervention required  
✓ Success or graceful failure reported  

**Not Required:**
✗ Perfect AI reasoning  
✗ Arbitrary task handling  
✗ Complex repair strategies  
✗ Learning from history  

---

*VAL-012: The finish line is one autonomous task with evidence.*

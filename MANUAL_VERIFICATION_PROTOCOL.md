# RawrXD Manual UI Verification Protocol

## Date: 2026-06-25

## Objective
Verify that UI interactions correctly trigger stub implementations and log telemetry.

## Prerequisites
- IDE built with LOG instrumentation: `d:\rawrxd\build-ninja\bin\RawrXD-Win32IDE.exe`
- Log file location: `d:\rawrxd\RawrXD_IDE.log`
- PowerShell tail command ready: `Get-Content d:\rawrxd\RawrXD_IDE.log -Wait`

## Verification Matrix

### Test 1: AI Features
| Step | Action | Expected Log Output | Status |
|------|--------|---------------------|--------|
| 1 | Launch IDE | IDE starts, no crashes | ⬜ |
| 2 | Open any file | File loads in editor | ⬜ |
| 3 | Select code block | Text highlighted | ⬜ |
| 4 | Right-click → "AI Explain" | `[STUB] AI.ExplainCode invoked` | ⬜ |
| 5 | Right-click → "AI Generate Tests" | `[STUB] AI.GenerateTests invoked` | ⬜ |
| 6 | Right-click → "AI Refactor" | `[STUB] AI.SuggestRefactoring invoked` | ⬜ |
| 7 | Command Palette → "AI: Fix Current Error" | `[STUB] AI.Cmd.FixCurrentError invoked` | ⬜ |

### Test 2: Code Actions
| Step | Action | Expected Log Output | Status |
|------|--------|---------------------|--------|
| 1 | Open file with LSP diagnostics | Diagnostics visible | ⬜ |
| 2 | Click line with error | Cursor positioned | ⬜ |
| 3 | Press `Ctrl + .` | `[STUB] CodeActions.Query invoked` | ⬜ |
| 4 | Command Palette → "Fix All Diagnostics" | `[STUB] CodeActions.Cmd.FixAll invoked` | ⬜ |
| 5 | Command Palette → "Organize Imports" | `[STUB] CodeActions.Cmd.OrganizeImports invoked` | ⬜ |

### Test 3: Call/Type Hierarchy
| Step | Action | Expected Log Output | Status |
|------|--------|---------------------|--------|
| 1 | Place caret on function name | Cursor positioned | ⬜ |
| 2 | Right-click → "Show Call Hierarchy" | `[STUB] CallHierarchy.Prepare invoked` | ⬜ |
| 3 | Expand node in hierarchy tree | `[STUB] CallHierarchy.IncomingCalls invoked` | ⬜ |
| 4 | Right-click → "Show Type Hierarchy" | `[STUB] TypeHierarchy.Prepare invoked` | ⬜ |
| 5 | Expand supertype node | `[STUB] TypeHierarchy.Supertypes invoked` | ⬜ |

## Real-Time Log Monitoring

Open PowerShell pane and run:
```powershell
Get-Content d:\rawrxd\RawrXD_IDE.log -Wait | Select-String "\[STUB\]"
```

This will show stub invocations in real-time as you interact with the UI.

## Success Criteria

- ✅ All 13 AI Features log correctly
- ✅ All 7 Code Actions log correctly  
- ✅ All 8 Hierarchy functions log correctly
- ✅ No crashes during UI interaction
- ✅ IDE remains responsive after each test

## Failure Modes to Watch For

| Symptom | Likely Cause | Action |
|---------|--------------|--------|
| No log output | Menu not wired to stub | Check command routing |
| Crash on click | Null pointer in stub | Check parameter handling |
| Hang after invoke | Blocking operation | Verify async pattern |
| Log shows but no UI | Missing UI feedback | Check output panel |

## Next Steps After Verification

1. **If all tests pass**: Update AUDIT_TRACKER.json with "STUB" classification
2. **If issues found**: Attach debugger and reproduce
3. **Priority**: Focus on AI Features first (most critical for user value)

## Debugger Attachment (Optional)

If crashes occur, attach VS debugger:
1. Launch IDE: `RawrXD-Win32IDE.exe`
2. In VS: Debug → Attach to Process → Select RawrXD-Win32IDE.exe
3. Set breakpoints in stub files
4. Reproduce crash
5. Check call stack and locals

## Notes

- Stubs are expected to return placeholder text/empty arrays
- Real functionality will be implemented in Phase 2
- Current goal is verification, not feature completion

# Phase 26: Integration Testing - "Beacon Verification"

## Date: 2026-06-21
## Status: IN PROGRESS

---

## 🎯 Objective

Verify the **Debugger-Victim Loop** to prove the ABI-fixed Beacon Debugger can:
1. Spawn a process with `DEBUG_PROCESS`
2. Trap at the entry point
3. Inject and trigger software breakpoints
4. Maintain register integrity across the event loop

---

## 🧪 Test Components

### Component A: Victim.exe (Test Target)
**File:** `d:\rawrxd\src\debugger\Victim.asm`

**Purpose:** Minimal, deterministic target with labeled breakpoint locations.

**Breakpoint Targets:**
| Label | Location | Purpose |
|-------|----------|---------|
| `__bp_entry_point` | After GetStdHandle | Test #1: Initial process break |
| `__bp_loop_start` | Before loop | Test #2: Pre-loop breakpoint |
| `__bp_loop_body` | Inside loop | Test #3: Iteration breakpoint |
| `__bp_exit_point` | After loop | Test #4: Exit breakpoint |

**Expected Behavior:**
- Prints "Hello from entry point!"
- Loops 10 times with 500ms delays
- Prints "Loop iteration..." each iteration
- Exits cleanly

---

### Component B: BeaconDebugger.exe (Debugger)
**File:** `d:\rawrxd\src\debugger\RawrXD_BeaconDebugger_ABI_Fixed.asm`

**Commands for Testing:**
```
bd> run Victim.exe          ; Launch and debug
bd> b <address>             ; Set breakpoint
bd> bl                      ; List breakpoints
bd> g                       ; Go/continue
bd> r                       ; Show registers
bd> q                       ; Quit/detach
```

---

## 📋 Test Protocol

### Test #1: Entry Point Halt
**Objective:** Verify `CreateProcess` + `DEBUG_PROCESS` works

**Steps:**
1. Launch BeaconDebugger
2. Execute: `run Victim.exe`
3. Verify: Debugger catches `CREATE_PROCESS_DEBUG_EVENT`
4. Verify: Process info (PID, hProcess, hThread) is captured
5. Execute: `g` (continue)

**Success Criteria:**
- [ ] Process created successfully
- [ ] Debugger reports "Created process <PID>"
- [ ] No access violations
- [ ] Stack remains 16-byte aligned

---

### Test #2: Breakpoint Injection
**Objective:** Verify `_set_bp` with VirtualProtect

**Steps:**
1. After Test #1, process should be running
2. Press Ctrl+C or use `break` command to pause
3. Get address of `__bp_loop_start` from symbol/map file
4. Execute: `b <address>`
5. Verify: "Breakpoint set at 0x..." message
6. Execute: `bl` to list breakpoints
7. Execute: `g` to continue

**Success Criteria:**
- [ ] Breakpoint set without error
- [ ] VirtualProtect succeeded
- [ ] INT3 (0xCC) written to target
- [ ] Original byte preserved

---

### Test #3: Breakpoint Trigger
**Objective:** Verify `_handle_event` catches breakpoint

**Steps:**
1. Continue from Test #2
2. Wait for Victim to reach loop
3. Verify: Debugger stops with "Breakpoint hit at 0x..."
4. Execute: `r` to show registers
5. Verify: RIP points to breakpoint address
6. Verify: All registers preserved (RBX, R12-R15 unchanged)

**Success Criteria:**
- [ ] EXCEPTION_BREAKPOINT caught
- [ ] RIP shows correct address
- [ ] All non-volatile registers intact
- [ ] Original byte restored
- [ ] RIP decremented to re-execute

---

### Test #4: Continue and Re-break
**Objective:** Verify breakpoint re-arming

**Steps:**
1. From Test #3, execute: `g` to continue
2. Verify: Victim continues execution
3. Wait for next loop iteration
4. Verify: Breakpoint hits again

**Success Criteria:**
- [ ] Single-step completed
- [ ] Breakpoint re-armed
- [ ] Second hit detected
- [ ] No double-hit or missed hits

---

### Test #5: Detach and Cleanup
**Objective:** Verify clean detachment

**Steps:**
1. Execute: `bc 0` to clear breakpoint
2. Execute: `g` to continue
3. Execute: `q` to quit
4. Verify: "Process exited" message
5. Verify: Victim.exe terminates

**Success Criteria:**
- [ ] All breakpoints cleared
- [ ] DebugActiveProcessStop called
- [ ] Handles closed
- [ ] No memory leaks

---

## 🔍 Verification Checklist

### ABI Compliance
- [ ] Shadow space (0x28) allocated in all procedures
- [ ] Stack 16-byte aligned at every call
- [ ] All non-volatile registers preserved
- [ ] No stack corruption detected

### Debug Events
- [ ] CREATE_PROCESS_DEBUG_EVENT received
- [ ] EXCEPTION_DEBUG_EVENT (Breakpoint) received
- [ ] EXCEPTION_DEBUG_EVENT (Single Step) received
- [ ] EXIT_PROCESS_DEBUG_EVENT received

### Breakpoint Logic
- [ ] VirtualProtectEx called before write
- [ ] INT3 (0xCC) successfully written
- [ ] Original byte preserved
- [ ] Protection restored after write
- [ ] RIP adjusted on hit
- [ ] Single-step flag set for re-arm

---

## 🚀 Execution Commands

### Build Victim
```bash
cd d:\rawrxd\src\debugger
ml64.exe /c /W3 /nologo /Fo Victim.obj Victim.asm
link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:Victim.exe Victim.obj kernel32.lib
```

### Build Debugger
```bash
ml64.exe /c /W3 /nologo /Fo BeaconDebugger.obj RawrXD_BeaconDebugger_ABI_Fixed.asm
link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:BeaconDebugger.exe BeaconDebugger.obj kernel32.lib
```

### Run Test
```bash
# Terminal 1: Run debugger
BeaconDebugger.exe

# Inside debugger
bd> run Victim.exe
bd> g
bd> b <loop_start_address>
bd> g
bd> r
bd> g
bd> q
```

---

## 📊 Expected Output

### Victim.exe Output (Normal Run)
```
Victim: Hello from entry point!
Victim: Loop iteration...
Victim: Loop iteration...
...
```

### BeaconDebugger Output (Debug Session)
```
RawrXD Beacon Debugger v1.0 | Pure x64 MASM | Zero CRT | ABI FIXED
...
bd> run Victim.exe
[OK] Created process 1234
bd> g
bd> b 0x00007FF612345678
[OK] Breakpoint set at 0x00007FF612345678
bd> g
[*] Breakpoint hit at 0x00007FF612345678
bd> r
rax 0x0000000000000001
rcx 0x00007FF612345670
...
rip 0x00007FF612345678
bd> g
...
```

---

## 🎉 Success Criteria

**Phase 26 Complete When:**
- [ ] All 5 tests pass
- [ ] No access violations
- [ ] No stack corruption
- [ ] Register integrity maintained
- [ ] Clean process lifecycle

**Ready for Phase 27:** Full IDE Integration

---

## 📝 Notes

1. **Victim.exe** must be built with debug info or map file for address resolution
2. **ASLR** should be disabled for predictable addresses: `/DYNAMICBASE:NO`
3. **Test in VS Developer Command Prompt** for proper environment
4. **Run as Administrator** if debugging system processes

---

## 🔧 Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| "Access violation" | Missing VirtualProtect | Ensure PAGE_EXECUTE_READWRITE |
| "Stack corruption" | Shadow space not allocated | Check `sub rsp, 28h` |
| "Breakpoint not hit" | Wrong address | Use map file or debug symbols |
| "Double hit" | Re-arm logic broken | Check single-step handling |
| "Process won't exit" | Detach not called | Verify `DebugActiveProcessStop` |

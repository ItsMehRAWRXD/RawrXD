# RawrXD DAP Integration - Troubleshooting Guide

## Quick Diagnostic Commands

### 1. Verify Build Artifacts
```cmd
cd d:\rawrxd
dir bin\BeaconDebugger.exe
dir Victim.exe
dir dap-server-launcher.js
```

### 2. Test BeaconDebugger Standalone
```cmd
# In VS Developer Command Prompt
cd d:\rawrxd\bin
BeaconDebugger.exe --stdio --verbose

# Type this and press Enter:
Content-Length: 52

{"seq":1,"type":"request","command":"initialize"}
```

**Expected:** JSON response with capabilities

### 3. Test Node.js Launcher
```cmd
cd d:\rawrxd
node dap-diagnostic.js

# Paste the initialize message when prompted
```

---

## Common Errors & Fixes

### ❌ "Debug adapter process has terminated unexpectedly"

**Cause 1: Missing Node.js**
```cmd
node --version
# Should show v16.x or higher
```
**Fix:** Install Node.js from https://nodejs.org/

**Cause 2: Path issues in launch.json**
Check that paths use forward slashes or escaped backslashes:
```json
"runtimeArgs": ["d:/rawrxd/dap-server-launcher.js"]
// NOT: "d:\rawrxd\dap-server-launcher.js"
```

**Cause 3: BeaconDebugger.exe not found**
```cmd
dir d:\rawrxd\bin\BeaconDebugger.exe
```
**Fix:** Run `verify_integration.bat`

---

### ❌ "Cannot launch program path" (when launching Victim.exe)

**Cause:** Victim.exe not built or wrong path
```cmd
cd d:\rawrxd\src\debugger
ml64 /c Victim.asm
link /OUT:..\..\Victim.exe Victim.obj /SUBSYSTEM:CONSOLE /ENTRY:main
```

---

### ❌ Breakpoint shows "Unverified" (gray circle)

**Cause 1:** Address mapping mismatch
Check that `g_lineMappings` in DAPAdapter.cpp matches actual Victim.exe addresses:
```cpp
// Get actual addresses with:
dumpbin /symbols Victim.exe
```

**Cause 2:** Process not yet launched
Breakpoints are verified after `launch` command. If Victim.exe hasn't started, addresses can't be resolved.

---

### ❌ Process crashes on breakpoint hit

**Cause:** VirtualProtect or INT3 injection failure

**Debug steps:**
1. Check BeaconDebugger stderr log
2. Verify `RawrXD_BeaconDebugger_ABI_Fixed.obj` is linked
3. Check that breakpoint address is in executable memory

---

### ❌ "The program '[pid] Victim.exe' has exited with code -1"

**Cause:** Victim.exe crashed or was killed

**Check:**
- Is Victim.exe 64-bit? (`dumpbin /headers Victim.exe`)
- Are you debugging a Release build? (Use Debug for testing)
- Check Windows Event Viewer for crash details

---

## VS Code Launch.json Reference

### Working Configuration
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "RawrXD DAP Test",
            "type": "node",
            "request": "launch",
            "runtimeExecutable": "node",
            "runtimeArgs": [
                "${workspaceFolder}/dap-server-launcher.js",
                "${workspaceFolder}/bin/BeaconDebugger.exe"
            ],
            "cwd": "${workspaceFolder}",
            "console": "integratedTerminal",
            "internalConsoleOptions": "openOnSessionStart"
        }
    ]
}
```

---

## Verification Checklist

Before reporting an issue, verify:

- [ ] `verify_integration.bat` completes without errors
- [ ] `BeaconDebugger.exe` exists in `bin\` directory
- [ ] `Victim.exe` exists in workspace root
- [ ] Node.js is installed (`node --version`)
- [ ] VS Code can see the launch configuration
- [ ] Manual DAP test works (`dap-diagnostic.js`)

---

## Getting Help

If issues persist:

1. **Run diagnostic:** `node dap-diagnostic.js`
2. **Check logs:** `dap_verify.log` or VS Code Debug Console
3. **Verify ABI:** Ensure all ASM code has proper shadow space
4. **Test incrementally:** Use `verify_integration.bat` steps one at a time

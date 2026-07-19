# RAWRXD Compiler Driver - Troubleshooting Guide

**Version:** 1.0.0  
**Last Updated:** 2026-07-19

---

## 🔍 Common Issues and Solutions

### Build Issues

#### Issue: "cl is not recognized as an internal or external command"
**Symptoms:**
```
'cl' is not recognized as an internal or external command,
operable program or batch file.
```

**Causes:**
- Not running from Visual Studio Developer Command Prompt
- Visual Studio not installed or not properly configured
- PATH environment variable not set

**Solutions:**
1. **Use Developer Command Prompt:**
   ```
   Start Menu → Visual Studio 2019/2022 → 
   x64 Native Tools Command Prompt
   ```

2. **Run vcvars64.bat manually:**
   ```batch
   call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
   ```

3. **Verify Visual Studio Installation:**
   - Open Visual Studio Installer
   - Ensure "Desktop development with C++" workload is installed

---

#### Issue: "Cannot open include file: 'rawrxd_compiler.h'"
**Symptoms:**
```
fatal error C1083: Cannot open include file: 'rawrxd_compiler.h': No such file or directory
```

**Causes:**
- Missing header file
- Incorrect include path
- Wrong working directory

**Solutions:**
1. **Verify file exists:**
   ```batch
   dir include\rawrxd_compiler.h
   ```

2. **Check working directory:**
   ```batch
   cd d:\rawrxd\tools\compiler_driver
   ```

3. **Use absolute path:**
   ```batch
   cl /I"d:\rawrxd\tools\compiler_driver\include" ...
   ```

---

#### Issue: "Unresolved external symbol"
**Symptoms:**
```
error LNK2019: unresolved external symbol _rxd_driver_init referenced in function _main
```

**Causes:**
- Missing object files during linking
- Object files not compiled
- Link order incorrect

**Solutions:**
1. **Ensure all files compiled:**
   ```batch
   dir obj\*.obj
   ```

2. **Link all objects:**
   ```batch
   link obj\compiler_driver.obj obj\main.obj ...
   ```

3. **Use build script:**
   ```batch
   build.bat
   ```

---

### Runtime Issues

#### Issue: "Backend not available"
**Symptoms:**
```
No compiler available for language: C
```

**Causes:**
- Wrapped compiler not found
- Path incorrect
- Compiler not installed

**Solutions:**
1. **Check backend status:**
   ```batch
   rawrxd-compiler list-backends
   ```

2. **Verify wrapped compilers exist:**
   ```batch
   dir d:\rawrxd-ci-bootstrap\compilers\native_toolchain\c_compiler_working.exe
   dir d:\rawrxd\enterprise_kernel\bin\RoslynCLI_Test.exe
   ```

3. **Update paths in config:**
   Edit `%USERPROFILE%\.rawrxd\config.json`

---

#### Issue: "Compilation failed with exit code 1"
**Symptoms:**
```
Compilation failed
Exit code: 1
```

**Causes:**
- Syntax errors in source code
- Missing dependencies
- Compiler configuration issues

**Solutions:**
1. **Check source code:**
   ```batch
   type src\main.c
   ```

2. **Run with verbose:**
   ```batch
   rawrxd-compiler compile -v file.c
   ```

3. **Check diagnostics:**
   ```batch
   rawrxd-compiler compile file.c 2>&1
   ```

---

#### Issue: "Access violation" or "Crash"
**Symptoms:**
```
Unhandled exception at 0x...: Access violation
```

**Causes:**
- Memory corruption
- Null pointer dereference
- Stack overflow

**Solutions:**
1. **Build debug version:**
   ```batch
   make debug
   ```

2. **Run with debugger:**
   ```batch
   devenv /debugexe rawrxd-compiler.exe compile file.c
   ```

3. **Check for null pointers:**
   Review code for uninitialized pointers

---

### IDE Integration Issues

#### Issue: "Extension not loading in VS Code"
**Symptoms:**
- Commands not appearing
- Extension not activating

**Causes:**
- Extension not compiled
- Node modules missing
- TypeScript errors

**Solutions:**
1. **Install dependencies:**
   ```batch
   cd vscode-extension
   npm install
   ```

2. **Compile extension:**
   ```batch
   npm run compile
   ```

3. **Check for errors:**
   ```batch
   npm run lint
   ```

---

#### Issue: "Tasks not working"
**Symptoms:**
- Build task fails
- No output in terminal

**Causes:**
- Task configuration incorrect
- PATH not set
- Working directory wrong

**Solutions:**
1. **Check tasks.json:**
   ```json
   {
     "version": "2.0.0",
     "tasks": [{
       "label": "Build",
       "type": "shell",
       "command": "rawrxd-compiler",
       "args": ["compile", "${file}"]
     }]
   }
   ```

2. **Add to PATH:**
   ```batch
   setx PATH "%PATH%;d:\rawrxd\tools\compiler_driver\bin"
   ```

---

### Test Issues

#### Issue: "Smoke tests failing"
**Symptoms:**
```
Test 1: FAILED
```

**Causes:**
- Compiler not built
- Dependencies missing
- Environment not set

**Solutions:**
1. **Build first:**
   ```batch
   build.bat
   ```

2. **Check dependencies:**
   ```batch
   where rawrxd-compiler.exe
   ```

3. **Run from correct directory:**
   ```batch
   cd d:\rawrxd\tools\compiler_driver\tests
   smoke_test.bat
   ```

---

#### Issue: "Tests hang or timeout"
**Symptoms:**
- Tests never complete
- Process stuck

**Causes:**
- Infinite loop in test
- Waiting for input
- Deadlock

**Solutions:**
1. **Check for interactive prompts:**
   Ensure tests don't wait for input

2. **Set timeout:**
   ```batch
   timeout /t 30 smoke_test.bat
   ```

3. **Run individual tests:**
   ```batch
   rawrxd-compiler compile examples\hello_world\hello.c
   ```

---

## 🔧 Diagnostic Commands

### Check Installation
```batch
# Verify executable
where rawrxd-compiler.exe

# Check version
rawrxd-compiler version

# List backends
rawrxd-compiler list-backends
```

### Check Environment
```batch
# Visual Studio
cl /?

# PATH
echo %PATH%

# Working directory
cd
```

### Debug Build
```batch
# Build debug version
make debug

# Run with debugger
devenv /debugexe rawrxd-compiler.exe

# Check symbols
dumpbin /symbols obj\compiler_driver.obj
```

---

## 📞 Getting More Help

### Before Asking for Help

1. **Check this guide** - Your issue might be listed above
2. **Check documentation** - See README.md and other docs
3. **Run diagnostics** - Use commands above
4. **Try examples** - See if examples work

### Information to Provide

When reporting an issue, include:

1. **Error message** - Full text of error
2. **Command used** - What you ran
3. **Environment** - OS, VS version, etc.
4. **Steps to reproduce** - How to trigger the issue
5. **Expected behavior** - What should happen

### Example Bug Report

```
**Issue:** Compilation fails with "Backend not available"

**Environment:**
- OS: Windows 10
- VS: 2019 Community
- RAWRXD: 1.0.0

**Command:**
rawrxd-compiler compile hello.c

**Error:**
No compiler available for language: C

**Expected:**
Should compile successfully

**Steps:**
1. Fresh clone
2. Run build.bat
3. Try to compile
```

---

## 🛠️ Advanced Debugging

### Enable Debug Logging

Set environment variable:
```batch
set RAWRXD_DEBUG=1
rawrxd-compiler compile file.c
```

### Memory Debugging

Use Application Verifier:
```batch
appverifier /verify rawrxd-compiler.exe
```

### Performance Profiling

Use VS Profiler:
```batch
vsperfcmd /start:trace /output:profile.vsp
rawrxd-compiler compile file.c
vsperfcmd /shutdown
```

---

## ✅ Quick Fixes

| Issue | Quick Fix |
|-------|-----------|
| cl not found | Use VS Developer Prompt |
| Include error | Check working directory |
| Link error | Rebuild all objects |
| Backend missing | Check config.json |
| Test fails | Rebuild and retry |
| Extension error | npm install && npm run compile |

---

*Still having issues? Check the documentation or file a bug report.*

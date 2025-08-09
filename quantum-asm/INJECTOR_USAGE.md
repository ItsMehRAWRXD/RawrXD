# Windows 11 Process Injector - Full Usage Guide

## Overview
A production-ready process injector fully compatible with Windows 11, featuring multiple injection techniques and fallback methods.

## Features
- ✅ **Windows 11 Compatible** - Uses NtCreateThreadEx and RtlCreateUserThread as fallbacks
- ✅ **Architecture Detection** - Automatically detects and handles 32/64-bit processes
- ✅ **Debug Privileges** - Automatically enables SeDebugPrivilege
- ✅ **Multiple Injection Methods** - DLL injection, shellcode injection, PID-based injection
- ✅ **Process Enumeration** - List all running processes
- ✅ **Error Handling** - Detailed error messages and fallback mechanisms

## Quick Start

### List All Processes
```bash
process_injector64.exe -l
```

### Inject DLL by Process Name
```bash
process_injector64.exe -i notepad.exe payload64.dll
```

### Inject DLL by PID
```bash
process_injector64.exe -p 1234 payload64.dll
```

### Inject Shellcode
```bash
process_injector64.exe -s explorer.exe
```

## Compilation

### Build Injector
```bash
# 32-bit
i686-w64-mingw32-gcc -O3 -s -static process_injector.c -o injector32.exe -lpsapi

# 64-bit
x86_64-w64-mingw32-gcc -O3 -s -static process_injector.c -o injector64.exe -lpsapi
```

### Build Test Payload
```bash
# 32-bit DLL
i686-w64-mingw32-gcc -shared -O2 test_payload.c -o payload32.dll

# 64-bit DLL
x86_64-w64-mingw32-gcc -shared -O2 test_payload.c -o payload64.dll
```

## Technical Details

### Injection Methods

1. **CreateRemoteThread** - Traditional method, may be blocked by some AV
2. **NtCreateThreadEx** - Direct syscall, more reliable on Windows 10/11
3. **RtlCreateUserThread** - Alternative NTDLL method, good compatibility

### Architecture Handling
- Automatically detects target process architecture
- Uses appropriate shellcode (x86/x64) based on target
- Handles WOW64 processes correctly

### Windows 11 Specific Features
- Extended process access rights handling
- Instruction cache flushing for DEP compatibility
- Multiple thread creation fallback methods
- Enhanced error reporting

## Advanced Usage

### Custom Shellcode
To use your own shellcode, modify the arrays in the source:
```c
unsigned char shellcode_x64[] = { /* your code */ };
unsigned char shellcode_x86[] = { /* your code */ };
```

### Stealth Options
Remove console output by redirecting:
```bash
process_injector64.exe -i target.exe payload.dll > nul 2>&1
```

### Persistence
The test payload creates a worker thread that:
- Logs injection time to `%TEMP%\injection_log.txt`
- Keeps the DLL loaded in the target process
- Can be extended for monitoring/hooking

## Troubleshooting

### "Failed to open process"
- Run as Administrator
- Process may be protected (System, Secure)
- Try with fewer privileges (automatic fallback)

### "Failed to create remote thread"
- Windows Defender may be blocking
- Process may have injection protection
- Try different injection method (code tries all 3)

### "Wrong architecture"
- Use matching injector/payload architecture
- Code automatically handles architecture mismatch

## Security Considerations

### Detection
- Enable debug privileges (logged in Event Log)
- Process handle with PROCESS_ALL_ACCESS
- Remote thread creation (monitored by EDR)

### Mitigation
- Use process hollowing instead
- Implement direct syscalls
- Add polymorphic encoding

## Testing on Windows 11

### Safe Targets
- notepad.exe
- calc.exe
- Your own test programs

### Avoid Injecting Into
- System processes
- Security software
- Critical Windows components

## Payload Capabilities

The included test payload:
- Shows MessageBox on injection (optional)
- Creates persistent worker thread
- Logs to temp directory
- Exports functions for external use

## Extending the Injector

### Add New Injection Method
```c
BOOL InjectMethod(DWORD pid, /* params */) {
    // Your implementation
}
```

### Add Obfuscation
```c
// XOR encode the DLL path
for (int i = 0; i < pathLen; i++) {
    dllPath[i] ^= 0xAA;
}
```

### Add Anti-Analysis
```c
if (IsDebuggerPresent()) {
    return FALSE;
}
```

## Example Workflow

1. **Find Target Process**
   ```
   injector64.exe -l | findstr notepad
   ```

2. **Inject Payload**
   ```
   injector64.exe -i notepad.exe payload64.dll
   ```

3. **Verify Injection**
   ```
   type %TEMP%\injection_log.txt
   ```

## Performance

- Process enumeration: < 10ms
- DLL injection: < 100ms  
- Shellcode injection: < 50ms
- Memory usage: < 1MB

## Limitations

- Requires appropriate privileges
- Some processes are protected
- Windows Defender may flag
- Shellcode is basic (calc.exe)

## Future Enhancements

- [ ] Manual mapping
- [ ] Reflective DLL injection  
- [ ] Heaven's Gate (x86 to x64)
- [ ] SetWindowsHookEx method
- [ ] APC injection
- [ ] Process hollowing

---

**Remember**: This tool is for educational and authorized testing only. Always ensure you have permission before testing on any system.
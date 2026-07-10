# CodexPro Menu Option 10: Execute Sovereign Kernel

## Overview

Added menu option 10 to CodexPro v7.0 for executing MASM64 kernels from COFF object files. This integrates with the RawrXD execution architecture.

## Changes Made

### 1. Menu Update (CodexPro.asm)

**Updated szMainMenu to include option 10:**
```asm
szMainMenu  BYTE    "[1] Professional PE Analysis (Full Reconstruction)", 13, 10
            BYTE    "[2] Batch Installation Reversal", 13, 10
            ...
            BYTE    "[9] Options & Configuration", 13, 10
            BYTE    "[10] Execute Sovereign Kernel", 13, 10    ; NEW
            BYTE    "[S] Sovereign Profile (RawrXD Kernel Analysis)", 13, 10
            BYTE    "[0] Exit", 13, 10
```

### 2. Menu Handler (CodexPro.asm)

**Added dispatch for option 10:**
```asm
cmp dwChoice, 10
je @@do_kernel_exec

...

@@do_kernel_exec:
    call DoExecuteKernel
    jmp @@menu
```

### 3. New Procedure: DoExecuteKernel

**Location:** After DoOptions, before Sovereign Profile integration

**Functionality:**
1. **Load Object File** - Opens and reads COFF object file
2. **Parse COFF Header** - Validates x64 machine type (0x8664)
3. **Find .text Section** - Locates executable code section
4. **Find Kernel Symbol** - Searches symbol table for kernel entry point
5. **Allocate Executable Memory** - Uses VirtualAlloc with PAGE_EXECUTE_READWRITE
6. **Copy Code** - Copies .text section to executable memory
7. **Prepare Test Data** - Initializes input buffer with test values [1.0, 2.0, 3.0, 4.0]
8. **Execute Kernel** - Calls kernel function with RCX=input, RDX=output, R8=count
9. **Display Results** - Shows input and output values
10. **Cleanup** - Frees allocated memory

**Key Features:**
- Full COFF parsing (headers, sections, symbols)
- Proper x64 calling convention (RCX, RDX, R8)
- Executable memory allocation with correct permissions
- Test data preparation and result display
- Comprehensive error handling

### 4. New Data Variables

```asm
; Kernel Execution Variables
dwSymbolCount           DWORD   ?
dwTextSectionIndex      DWORD   ?
dwKernelOffset          DWORD   ?
qwSymbolTable           QWORD   ?
qwTextOffset            QWORD   ?
qwTextSize              QWORD   ?
qwKernelName            QWORD   ?
qwBytesRead             QWORD   ?
```

### 5. New String Constants

```asm
; Banner
szKernelExecBanner      BYTE    "SOVEREIGN KERNEL EXECUTION", 13, 10
                        BYTE    "Load and execute MASM64 kernels from COFF object files", 13, 10

; Prompts
szPromptKernelPath      BYTE    "Kernel object file path: ", 0

; Status Messages
szStatusLoadingKernel   BYTE    "[*] Loading kernel object file...", 13, 10, 0
szStatusParsingCOFF     BYTE    "    [+] Parsing COFF header...", 13, 10, 0
szStatusFindingText     BYTE    "    [+] Finding .text section...", 13, 10, 0
szStatusFindingSymbol   BYTE    "    [+] Locating kernel symbol...", 13, 10, 0
szStatusAllocatingExec  BYTE    "    [+] Allocating executable memory...", 13, 10, 0
szStatusPreparingData   BYTE    "    [+] Preparing test data...", 13, 10, 0
szStatusExecuting       BYTE    "[*] Executing kernel...", 13, 10, 0

; Results
szKernelExecResults     BYTE    "[+] Kernel execution complete!", 13, 10, 0
szInputValues           BYTE    "    Input:  ", 0
szOutputValues          BYTE    "    Output: ", 0
szFloatValue            BYTE    "%.2f ", 0

; Error Messages
szErrorFileNotFound     BYTE    "[-] Error: File not found", 13, 10, 0
szErrorOpenFailed       BYTE    "[-] Error: Failed to open file", 13, 10, 0
szErrorNotX64           BYTE    "[-] Error: Not an x64 object file", 13, 10, 0
szErrorTextNotFound     BYTE    "[-] Error: .text section not found", 13, 10, 0
szErrorSymbolNotFound   BYTE    "[-] Error: No kernel symbol found", 13, 10, 0
```

## Usage Flow

```
CodexPro Menu
    |
    v
[10] Execute Sovereign Kernel
    |
    v
Enter kernel object file path: d:\src\asm\TestKernel.obj
    |
    v
[*] Loading kernel object file...
    [+] Parsing COFF header...
    [+] Finding .text section...
    [+] Locating kernel symbol...
    [+] Allocating executable memory...
    [+] Preparing test data...
[*] Executing kernel...
    |
    v
[+] Kernel execution complete!
    Input:  1.00 2.00 3.00 4.00
    Output: 2.00 3.00 4.00 5.00
```

## Integration with RawrXD

This menu option demonstrates the same principles used in the RawrXD execution architecture:

1. **MASM64KernelLoader** (C++) - Production-ready COFF loader
2. **SovereignBackend** (C++) - Backend that manages kernel loading
3. **DoExecuteKernel** (MASM) - Standalone demonstration in assembly

All three implementations:
- Parse COFF headers
- Map executable sections
- Resolve symbols
- Call kernel functions using x64 calling convention

## Testing

To test menu option 10:

1. Build TestKernel.asm:
```bash
ml64.exe /c /Fo TestKernel.obj TestKernel.asm
```

2. Run CodexPro and select option 10

3. Enter path: `d:\src\asm\TestKernel.obj`

4. Observe kernel execution and results

## Menu Options Summary

| Option | Description |
|--------|-------------|
| 1 | Professional PE Analysis |
| 2 | Batch Installation Reversal |
| 3 | Type Recovery |
| 4 | Generate VS2022 Solution |
| 5 | Generate CMake + Ninja |
| 6 | Universal Deobfuscator |
| 7 | Resource Extractor |
| 8 | Dependency Mapper |
| 9 | Options & Configuration |
| **10** | **Execute Sovereign Kernel** (NEW) |
| S | Sovereign Profile |
| 0 | Exit |

## Technical Notes

- **COFF Format**: Parses standard Windows x64 COFF object files
- **Memory Safety**: Allocates RWX memory only for code sections
- **Error Handling**: Comprehensive checks at each step
- **Calling Convention**: Uses Windows x64 ABI (RCX, RDX, R8, R9)
- **Test Pattern**: Input [1.0, 2.0, 3.0, 4.0] → Output [2.0, 3.0, 4.0, 5.0]

## Bug Fixes Applied

### Fix 1: Removed Duplicate Variable Declarations
**Problem:** `hStdOut` and `hStdErr` were declared twice (once in handles section, once in kernel variables section)
**Solution:** Removed duplicate declarations from kernel execution variables

### Fix 2: Removed Unused FileExists Call
**Problem:** Code called `FileExists` procedure which doesn't exist in CodexPro
**Solution:** Removed the call - CreateFileA with OPEN_EXISTING will fail if file doesn't exist anyway

### Fix 3: Removed Unused Local Variable
**Problem:** `dwOldProtect` was declared but never used
**Solution:** Removed from LOCAL declarations

### Fix 4: Removed Unreachable Label
**Problem:** `@@file_not_found:` label was never reached after removing FileExists call
**Solution:** Removed the label and its associated error message

## Future Enhancements

1. Support for multiple kernel symbols in one object file
2. Kernel parameter input (not just test data)
3. Performance timing (RDTSC before/after)
4. Integration with Sovereign telemetry system
5. Support for kernel chaining (pipeline execution)

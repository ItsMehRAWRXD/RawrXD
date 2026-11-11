# CodexPro Menu Option 10 - Quick Start Guide

## Overview
Execute MASM64 kernels directly from COFF object files within CodexPro.

## Usage

### 1. Build Test Kernel (if not already done)
```cmd
cd d:\src\asm
ml64.exe /c /Fo TestKernel.obj TestKernel.asm
```

### 2. Launch CodexPro
```cmd
cd d:\rawrxd
CodexPro.exe
```

### 3. Select Menu Option 10
```
[10] Execute Sovereign Kernel
```

### 4. Enter Kernel Path
```
Kernel object file path: d:\src\asm\TestKernel.obj
```

### 5. Expected Output
```
================================================================
SOVEREIGN KERNEL EXECUTION
================================================================
Load and execute MASM64 kernels from COFF object files
Integration with RawrXD Execution Architecture

[*] Loading kernel object file...
    [+] Parsing COFF header...
    [+] Finding .text section...
    [+] Locating kernel symbol...
    [+] Allocating executable memory...
    [+] Preparing test data...
[*] Executing kernel...

[+] Kernel execution complete!
    Input:  1.00 2.00 3.00 4.00
    Output: 2.00 3.00 4.00 5.00

[*] Kernel execution finished successfully
```

## Technical Details

### What Happens
1. **Load** - Opens COFF object file
2. **Parse** - Validates x64 machine type (0x8664)
3. **Locate** - Finds .text section and kernel symbol
4. **Allocate** - Maps executable memory (RWX)
5. **Execute** - Calls kernel with test data
6. **Display** - Shows input/output results

### Test Data
- **Input**: `[1.0, 2.0, 3.0, 4.0]` (4 floats)
- **Expected Output**: `[2.0, 3.0, 4.0, 5.0]` (each + 1.0)

### Calling Convention
- **RCX**: Input buffer pointer
- **RDX**: Output buffer pointer
- **R8**: Element count (4)

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| "Failed to open file" | File doesn't exist | Check path |
| "Not an x64 object file" | Wrong architecture | Use ml64.exe |
| ".text section not found" | No code section | Check assembly |
| "No kernel symbol found" | No exported symbols | Add PUBLIC directive |

## Integration

This menu option demonstrates the same execution flow as:
- **C++**: `MASM64KernelLoader` → `SovereignBackend` → `SovereignGraphRunner`
- **MASM**: Direct COFF parsing and kernel execution

Both implementations share:
- COFF format parsing
- Executable memory mapping
- x64 calling convention
- Symbol resolution

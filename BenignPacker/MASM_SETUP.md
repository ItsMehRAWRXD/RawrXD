# MASM Setup for BenignPacker

## Overview
Microsoft Macro Assembler (MASM) has been configured for this Visual Studio 2022 project. You can now write assembly code and integrate it with your C++ code.

## Configuration Details

### Project File Changes
The following modifications were made to `BenignPacker.vcxproj`:

1. **Added MASM Build Customization**:
   - Imported `masm.props` and `masm.targets` from Visual Studio build customizations
   - Added MASM configuration to all build configurations (Debug/Release, Win32/x64)

2. **Platform-Specific Settings**:
   - **Win32 (x86)**: Uses `UseSafeExceptionHandlers` for compatibility
   - **x64**: Standard MASM configuration without special flags

### Sample Files Created

1. **test_masm.asm** - 32-bit x86 assembly example
2. **test_masm_x64.asm** - 64-bit x64 assembly example
3. **test_masm.h** - C++ header to declare assembly functions

### Using MASM in Your Code

1. **Create an assembly file** with `.asm` extension
2. **Add it to the project** via Solution Explorer or by editing the `.vcxproj` file
3. **Write your assembly code** following the appropriate calling convention:
   - x86: Parameters on stack, return value in EAX
   - x64: First 4 params in RCX, RDX, R8, R9; return value in RAX

4. **Declare functions in C++** using `extern "C"` linkage:
   ```cpp
   extern "C" int MyAsmFunction(int param1, int param2);
   ```

### Example Usage

```cpp
#include "test_masm.h"
#include <iostream>

int main() {
    int result = AddNumbers(10, 20);
    std::cout << "10 + 20 = " << result << std::endl;
    return 0;
}
```

### Build Instructions

1. Open the solution in Visual Studio 2022
2. Build the project normally (Ctrl+Shift+B)
3. MASM will automatically assemble `.asm` files during the build process

### Troubleshooting

If you encounter build errors:
1. Ensure Visual Studio has the "MSVC v143 - VS 2022 C++ x64/x86 build tools" component installed
2. Check that MASM (ml.exe for x86, ml64.exe for x64) is in your Visual Studio installation
3. Verify the assembly syntax matches the target platform (32-bit vs 64-bit)

### Platform-Specific Assembly Files

The project is configured to automatically select the correct assembly file based on the platform:
- **Win32 builds**: Uses `test_masm.asm` (excludes x64 version)
- **x64 builds**: Uses `test_masm_x64.asm` (excludes x86 version)
# Quantum Assembly Project - MinGW Setup

This project demonstrates how to build assembly code for Windows using MinGW-w64 cross-compiler on Linux.

## Files

- `quantum_recovered.asm` - Original MASM assembly code recovered from git
- `quantum_mingw.s` - GAS (GNU Assembler) version for MinGW
- `quantum_nasm.asm` - NASM version for MinGW  
- `test_main.c` - C test program that calls the assembly functions
- `Makefile` - Build configuration for GAS
- `Makefile.nasm` - Build configuration for NASM

## Prerequisites

Install MinGW-w64 and NASM:
```bash
sudo apt-get update
sudo apt-get install -y mingw-w64 nasm
```

## Building

### Using NASM (Recommended)
```bash
make -f Makefile.nasm
```

This creates:
- `quantum_nasm32.exe` - 32-bit Windows executable
- `quantum_nasm64.exe` - 64-bit Windows executable

### Using GAS
```bash
make
```

This creates:
- `quantum_test32.exe` - 32-bit Windows executable
- `quantum_test64.exe` - 64-bit Windows executable

## Assembly Functions

The assembly code provides three functions:

1. **test_masm_function()** - Returns the value 42
2. **add_numbers(int a, int b)** - Adds two integers
3. **xor_encrypt(unsigned char* data, size_t length, unsigned char key)** - XOR encryption

## Calling Conventions

The code handles both Windows calling conventions:
- **32-bit (stdcall)**: Parameters passed on stack
- **64-bit (Microsoft x64)**: First 4 parameters in RCX, RDX, R8, R9

## Testing

To run the executables on Linux, you need Wine:
```bash
# Install Wine (if not already installed)
sudo apt-get install wine wine64

# Test 32-bit executable
wine quantum_nasm32.exe

# Test 64-bit executable  
wine64 quantum_nasm64.exe
```

## Clean Build
```bash
make clean
# or
make -f Makefile.nasm clean
```

## Notes

- The code uses Intel syntax for better MASM compatibility
- Symbol names are prefixed with underscore for 32-bit builds
- Static linking is used to avoid DLL dependencies
- Both NASM and GAS versions produce identical functionality
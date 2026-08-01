# RAWRXD Compiler System

Unified compiler platform with integrated C, Assembly, and C# support.

## Quick Start

```bash
# Build the driver
cd src/driver
cl rawrxd_cc.c /Fe..\..\bin\rawrxd-cc.exe

# Compile a file
rawrxd-cc hello.c -o hello.exe
rawrxd-cc hello.asm --emit=obj
rawrxd-cc hello.cs --analyze
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RAWRXD Compiler Platform                  │
├─────────────────────────────────────────────────────────────┤
│                         rawrxd-cc.exe                        │
│                    (Unified Compiler Driver)                 │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   C Backend     │ │  ASM Backend    │ │ Roslyn Backend  │
│ ─────────────── │ │ ─────────────── │ │ ─────────────── │
│ c_compiler_     │ │ real_assembler  │ │ MicroRoslyn_    │
│ working.c       │ │ .c              │ │ Test.exe        │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

## Supported Languages

| Language | Extension | Backend | Status |
|----------|-----------|---------|--------|
| C | `.c`, `.h` | rawrxd-c | ✅ Production |
| Assembly | `.asm`, `.s` | rawrxd-asm | ✅ Production |
| C# | `.cs` | micro-roslyn | ✅ Production |

## Directory Structure

```
rawrxd-ci-bootstrap/
├── bin/                    # Compiled executables
│   ├── rawrxd-cc.exe      # Unified driver
│   ├── rawrxd-c.exe       # C compiler
│   ├── rawrxd-asm.exe     # Assembler
│   └── micro-roslyn.exe   # C# compiler
│
├── src/
│   └── driver/
│       └── rawrxd_cc.c    # Driver source
│
├── compilers/
│   ├── production/        # Working compilers
│   │   ├── c/
│   │   ├── asm/
│   │   └── csharp/
│   └── stubs/            # Placeholder compilers
│
├── tests/
│   └── validation/
│       └── smoke_test.py  # Test suite
│
├── compiler_manifest.json  # Machine-readable manifest
└── README_COMPILER_SYSTEM.md
```

## Building

### Prerequisites

- Visual Studio 2022 (or compatible C compiler)
- Windows SDK
- Python 3.8+ (for tests)

### Build Steps

```bash
# Build the unified driver
cd src/driver
cl rawrxd_cc.c /Fe..\..\bin\rawrxd-cc.exe

# Or use the build script
build_driver.bat
```

## Testing

```bash
# Run smoke tests
python tests\validation\smoke_test.py

# Run with verbose output
python tests\validation\smoke_test.py --verbose
```

## Usage Examples

### Compile C Code

```bash
rawrxd-cc hello.c -o hello.exe
rawrxd-cc hello.c --emit=asm    # Generate assembly
rawrxd-cc hello.c --verbose      # Show detailed output
```

### Assemble Code

```bash
rawrxd-cc program.asm -o program.exe
rawrxd-cc program.asm --emit=obj # Generate object file
```

### Compile C# Code

```bash
rawrxd-cc program.cs -o program.exe
rawrxd-cc program.cs --analyze   # Static analysis only
```

### Force Specific Backend

```bash
rawrxd-cc file.c --backend=rawrxd-c
rawrxd-cc file.asm --backend=rawrxd-asm
```

## Diagnostic Format

All compilers output standardized diagnostics:

```json
{
  "severity": "error",
  "code": "CS1002",
  "message": "; expected",
  "location": {
    "file": "main.cs",
    "line": 14,
    "column": 5
  }
}
```

## Integration

### VS Code Extension

The compiler system integrates with the RAWRXD VS Code extension:

```json
{
  "rawrxd.compiler.path": "${workspaceFolder}/bin/rawrxd-cc.exe",
  "rawrxd.compiler.verbose": true
}
```

### Language Server Protocol

The driver supports LSP-compatible output:

```bash
rawrxd-cc --lsp
```

## Manifest

The `compiler_manifest.json` file provides machine-readable information about available compilers:

```json
{
  "compilers": [
    {
      "id": "rawrxd-c",
      "language": "c",
      "status": "production",
      "executable": "bin/rawrxd-c.exe"
    }
  ]
}
```

## Troubleshooting

### Compiler Not Found

Ensure the compiler executable is in the `bin/` directory or in your PATH.

### Backend Selection Failed

The driver automatically detects language from file extension. Use `--backend=` to force a specific backend.

### Tests Failing

Check that all compiler executables exist:

```bash
dir bin\*.exe
```

## Contributing

See `docs/CONTRIBUTING.md` for contribution guidelines.

## License

See `LICENSE` file for details.

# RAWRXD Compiler Driver

A unified compiler driver for the RAWRXD toolchain supporting C, x64 Assembly, and C#.

## Features

- **Unified Interface**: Single command to compile multiple languages
- **Auto-Detection**: Automatically detects language from file extension
- **Normalized Diagnostics**: Consistent error reporting across all compilers
- **Modular Backends**: Easy to add new language support
- **IDE Integration**: VS Code extension available

## Supported Languages

| Language | Extensions | Backend | Status |
|----------|-----------|---------|--------|
| C | `.c`, `.h` | rawrxd-c | ✅ Production |
| x64 Assembly | `.asm`, `.s`, `.nasm` | rawrxd-asm | ✅ Production |
| C# | `.cs`, `.csharp` | rawrxd-csharp | ✅ Production |

## Quick Start

### Building

```batch
# Open "x64 Native Tools Command Prompt for VS 2019+"
cd d:\rawrxd\tools\compiler_driver
build.bat
```

### Usage

```batch
# Compile a C file
rawrxd-compiler compile hello.c

# Compile assembly
rawrxd-compiler compile program.asm

# Compile C#
rawrxd-compiler compile app.cs

# With options
rawrxd-compiler compile -o myapp.exe -O -g main.c

# List available backends
rawrxd-compiler list-backends
```

### Options

- `-o, --output <file>` - Specify output file
- `-O, --optimize` - Enable optimization
- `-g, --debug` - Include debug information
- `-v, --verbose` - Verbose output
- `-l, --lang <lang>` - Force language (c, asm, csharp)

## API Usage

```c
#include "rawrxd_compiler.h"

// Initialize driver
rxd_driver_init();

// Register backends
rxd_register_c_backend();
rxd_register_asm_backend();
rxd_register_csharp_backend();

// Compile a file
rxd_compile_options_t options;
rxd_options_init(&options);

rxd_compile_result_t result;
rxd_compile_file("hello.c", "hello.exe", &options, &result);

// Check result
if (rxd_result_success(&result)) {
    printf("Compiled successfully!\n");
} else {
    rxd_result_print_diagnostics(&result);
}

// Cleanup
rxd_result_free(&result);
rxd_driver_shutdown();
```

## Testing

Run smoke tests:

```batch
cd tests
smoke_test.bat
```

## VS Code Extension

Install the extension from `vscode-extension/`:

```batch
cd vscode-extension
npm install
npm run compile
```

Then press F5 to launch the extension host.

## Project Structure

```
compiler_driver/
├── include/
│   └── rawrxd_compiler.h      # Public API
├── src/
│   ├── compiler_driver.c      # Core implementation
│   ├── main.c                 # CLI entry
│   └── backends/
│       ├── c_backend.c        # C compiler
│       ├── asm_backend.c      # Assembler
│       └── csharp_backend.c   # C# compiler
├── tests/
│   └── smoke_test.bat         # Test suite
├── vscode-extension/          # VS Code integration
├── build.bat                  # Build script
└── README.md                  # This file
```

## Adding a New Backend

1. Create `src/backends/<name>_backend.c`
2. Implement the vtable functions
3. Add registration function
4. Call registration in `main.c`
5. Update `compiler_manifest.json`

Example backend structure:

```c
static rxd_backend_vtable_t my_backend_vtable = {
    .name = "rawrxd-mybackend",
    .version = "1.0.0",
    .language = RXD_LANG_MYLANG,
    .init = my_backend_init,
    .shutdown = my_backend_shutdown,
    .can_compile = my_backend_can_compile,
    .compile = my_backend_compile
};

int rxd_register_my_backend(void) {
    return rxd_driver_register_backend(&my_backend_vtable);
}
```

## Error Codes

| Code | Description |
|------|-------------|
| C0000 | C compilation success |
| C0001 | C compilation failed |
| ASM000 | Assembly success |
| ASM001 | Assembly failed |
| CS0000 | C# compilation success |
| CS0001 | C# compilation failed |
| LNK001 | Linking failed |

## License

MIT License - See LICENSE file for details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run smoke tests
5. Submit a pull request

## Support

For issues and feature requests, please use the GitHub issue tracker.

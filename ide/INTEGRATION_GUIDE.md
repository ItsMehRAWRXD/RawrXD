# RAWRXD IDE Compiler Integration Guide

## Overview

This guide explains how the RAWRXD Compiler Driver is integrated into both the GUI and CLI versions of the IDE.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RAWRXD IDE Suite                         │
├─────────────────────────────────────────────────────────────┤
│  GUI IDE (codex_gui_ide.exe)                                │
│  ├─ Win32 Native Interface                                  │
│  ├─ GGUF Model Loader                                       │
│  └─ Compiler Integration (compiler_gui_integration.cpp)    │
├─────────────────────────────────────────────────────────────┤
│  CLI IDE (codex_cli_ide.exe)                                │
│  ├─ Interactive REPL                                        │
│  ├─ GGUF Model Loader                                       │
│  └─ Compiler Integration (compiler_cli_integration.cpp)     │
├─────────────────────────────────────────────────────────────┤
│  Common Library (compiler_integration.c)                    │
│  └─ Shared API for GUI and CLI                              │
├─────────────────────────────────────────────────────────────┤
│  RAWRXD Compiler Driver                                     │
│  └─ tools/compiler_driver/bin/rawrxd-compiler.exe          │
└─────────────────────────────────────────────────────────────┘
```

## File Structure

```
ide/
├── common/
│   ├── compiler_integration.h      # Shared header
│   └── compiler_integration.c      # Shared implementation
├── gui/
│   ├── codex_gui_ide.cpp           # Main GUI IDE
│   └── compiler_gui_integration.cpp # GUI-specific compiler code
├── cli/
│   ├── codex_cli_ide.cpp           # Main CLI IDE
│   └── compiler_cli_integration.cpp # CLI-specific compiler code
├── bin/                            # Output directory
├── build_ide_with_compiler.bat     # Build script
└── INTEGRATION_GUIDE.md            # This file
```

## Features

### GUI IDE Features
- **Compiler Menu**: File → Compiler
  - Compile File (Ctrl+F7)
  - Build Project (Ctrl+Shift+B)
  - Run Executable (Ctrl+F5)
  - Clean Build
  - Options
- **Compiler Output Window**: Bottom panel showing compilation output
- **File Dialogs**: Open source files, save executables
- **Progress Indicators**: Visual feedback during compilation
- **Error Parsing**: Click errors to jump to source

### CLI IDE Features
- **Compiler Commands**:
  - `compile <file>` - Compile single file
  - `build <files...>` - Build multiple files
  - `clean` - Remove build artifacts
  - `run <exe>` - Run executable
  - `check` - Verify compiler availability
  - `version` - Show compiler version
- **REPL Integration**: `:compile`, `:build`, `:run` commands
- **Batch Processing**: Build multiple files at once

## Supported Languages

| Language | Extensions | Backend |
|----------|------------|---------|
| C | .c, .h | c_compiler_working.exe |
| Assembly | .asm, .s, .nasm | real_assembler.exe |
| C# | .cs, .csharp | RoslynCLI_Test.exe |

## Build Instructions

### Prerequisites
- Visual Studio 2019 or later
- Windows SDK
- RAWRXD Compiler Driver (in tools/compiler_driver)

### Build Steps

1. Open Developer Command Prompt for VS
2. Navigate to ide/ directory
3. Run build script:
   ```batch
   build_ide_with_compiler.bat
   ```

### Manual Build

```batch
:: Build common library
cl /c /O2 /Icommon common\compiler_integration.c

:: Build GUI IDE
cl /O2 /EHsc /Fe:bin\codex_gui_ide.exe ^
   gui\codex_gui_ide.cpp ^
   gui\compiler_gui_integration.cpp ^
   compiler_integration.obj ^
   user32.lib gdi32.lib comdlg32.lib shell32.lib comctl32.lib

:: Build CLI IDE
cl /O2 /EHsc /Fe:bin\codex_cli_ide.exe ^
   cli\codex_cli_ide.cpp ^
   cli\compiler_cli_integration.cpp ^
   compiler_integration.obj
```

## API Reference

### Initialization
```c
// Initialize compiler integration
bool RawrxdCompiler_Init(void);

// Shutdown compiler integration
void RawrxdCompiler_Shutdown(void);
```

### Compilation
```c
// Compile single file
RawrxdCompileResult RawrxdCompiler_Compile(
    const char* sourcePath,
    const RawrxdBuildConfig* config
);

// Build multiple files
RawrxdCompileResult RawrxdCompiler_Build(
    const char** sourcePaths,
    int count,
    const RawrxdBuildConfig* config
);
```

### Configuration
```c
// Build configuration structure
typedef struct {
    bool optimize;
    bool debug;
    bool verbose;
    char outputName[MAX_PATH];
    char includePaths[1024];
    char libraryPaths[1024];
    char defines[1024];
} RawrxdBuildConfig;

// Get default configuration
void RawrxdCompiler_GetDefaultConfig(
    RawrxdBuildConfig* config,
    const char* projectPath
);
```

### Utilities
```c
// Detect language from file extension
RawrxdLanguage RawrxdCompiler_DetectLanguage(const char* filePath);

// Get language name
const char* RawrxdCompiler_LanguageName(RawrxdLanguage lang);

// Check if file is compilable
bool RawrxdCompiler_IsCompilable(const char* filePath);

// Get compiler version
const char* RawrxdCompiler_GetVersion(void);
```

## Integration Points

### GUI IDE Integration

1. **Menu Addition** (in codex_gui_ide.cpp):
```cpp
// Add to CreateMainMenu()
HMENU hCompiler = CreateCompilerMenu();
AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hCompiler, "&Compiler");
```

2. **Command Handler** (in WndProc):
```cpp
case WM_COMMAND:
    if (HandleCompilerCommand(hWnd, LOWORD(wParam))) {
        return 0;
    }
    break;
```

3. **Initialization** (in WM_CREATE):
```cpp
InitializeCompilerIntegration(hWnd);
```

### CLI IDE Integration

1. **Command Dispatch** (in main loop):
```cpp
if (strncmp(input, "compiler ", 9) == 0) {
    HandleCompilerCLICommand(argc, argv);
    continue;
}
```

2. **REPL Commands**:
```cpp
if (CompilerREPL_HandleCommand(input)) {
    continue; // Command handled
}
```

3. **Initialization**:
```cpp
InitializeCompilerCLI();
```

## Error Handling

### Error Format
```
file.c(42): error C2143: syntax error: missing ';' before 'return'
```

### Error Parsing
```c
int RawrxdCompiler_ParseErrors(
    const char* compilerOutput,
    char* errorFile,
    int* errorLine,
    char* errorMessage,
    size_t messageSize
);
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+F7 | Compile current file |
| Ctrl+Shift+B | Build project |
| Ctrl+F5 | Run executable |

## Troubleshooting

### Compiler Not Found
- Ensure `rawrxd-compiler.exe` is in PATH
- Or located at `tools/compiler_driver/bin/`

### Build Failures
- Check Visual Studio installation
- Verify compiler driver is built
- Check file permissions

### Runtime Errors
- Verify all dependencies are present
- Check Windows SDK version
- Review compiler output window

## Future Enhancements

- [ ] Project file support (.rawrxdproj)
- [ ] Integrated debugger
- [ ] Syntax highlighting in editor
- [ ] Auto-completion
- [ ] Error squiggles
- [ ] Build configurations (Debug/Release)
- [ ] Multi-threaded builds
- [ ] Package manager integration

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-19 | Initial integration |

## Support

For issues or questions:
- Check INTEGRATION_GUIDE.md
- Review compiler_integration.h
- Check RAWRXD_COMPILER_TROUBLESHOOTING.md

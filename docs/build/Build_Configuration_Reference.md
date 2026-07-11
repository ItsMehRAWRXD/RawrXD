# Sovereign IDE - Build Configuration Reference
## Complete Configuration Options and Examples

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Configuration Files](#configuration-files)
2. [Build Profiles](#build-profiles)
3. [Compiler Options](#compiler-options)
4. [Linker Options](#linker-options)
5. [Platform-Specific Settings](#platform-specific-settings)
6. [Advanced Configuration](#advanced-configuration)

---

## Configuration Files

### Main Configuration File

```json
// build.json - Main build configuration
{
  "version": "1.0.0",
  "project": {
    "name": "SovereignIDE",
    "version": "1.0.0",
    "description": "Sovereign Reverse Engineering IDE"
  },
  
  "paths": {
    "source": "src",
    "output": "build",
    "intermediate": "build/obj",
    "libraries": "build/lib",
    "binaries": "build/bin",
    "logs": "build/logs",
    "resources": "resources"
  },
  
  "tools": {
    "assembler": "ml64.exe",
    "c_compiler": "cl.exe",
    "cpp_compiler": "cl.exe",
    "linker": "link.exe",
    "librarian": "lib.exe",
    "archiver": "lib.exe"
  },
  
  "profiles": {
    "debug": {
      "inherits": "base",
      "defines": ["DEBUG", "_DEBUG", "ENABLE_ASSERTS"],
      "optimization": "/Od",
      "debug_info": "/Zi /DEBUG",
      "runtime": "/MDd"
    },
    "release": {
      "inherits": "base",
      "defines": ["NDEBUG", "RELEASE", "ENABLE_OPTIMIZATIONS"],
      "optimization": "/O2 /Ob2 /Oi /Ot /Oy",
      "debug_info": "/Zi",
      "runtime": "/MD",
      "linker_flags": "/OPT:REF /OPT:ICF /LTCG"
    },
    "profile": {
      "inherits": "release",
      "defines": ["PROFILE", "ENABLE_PROFILING"],
      "instrument": "/Gh /GH"
    }
  },
  
  "targets": {
    "kernel": {
      "type": "library",
      "language": "masm",
      "sources": ["src/kernel/**/*.asm"],
      "output": "kernel.lib"
    },
    "abi": {
      "type": "library",
      "language": "c",
      "sources": ["src/abi/**/*.c"],
      "output": "abi.lib",
      "depends": ["kernel"]
    },
    "backend": {
      "type": "library",
      "language": "cpp",
      "sources": ["src/backend/**/*.cpp"],
      "output": "backend.lib",
      "depends": ["kernel", "abi"]
    },
    "seg": {
      "type": "library",
      "language": "cpp",
      "sources": ["src/seg/**/*.cpp"],
      "output": "seg.lib",
      "depends": ["kernel", "backend"]
    },
    "batches": {
      "type": "group",
      "targets": [
        {
          "name": "batches_1_10",
          "sources": ["src/batches/{1..10}/**/*.cpp"],
          "output": "batches_1_10.lib"
        },
        {
          "name": "batches_11_20",
          "sources": ["src/batches/{11..20}/**/*.cpp"],
          "output": "batches_11_20.lib"
        },
        {
          "name": "batches_21_30",
          "sources": ["src/batches/{21..30}/**/*.{c,cpp}"],
          "output": "batches_21_30.lib"
        },
        {
          "name": "batches_31_40",
          "sources": ["src/batches/{31..40}/**/*.{c,cpp}"],
          "output": "batches_31_40.lib"
        },
        {
          "name": "batches_41_49",
          "sources": ["src/batches/{41..49}/**/*.{c,cpp}"],
          "output": "batches_41_49.lib"
        }
      ],
      "depends": ["kernel", "abi", "seg"]
    },
    "gui": {
      "type": "library",
      "language": "cpp",
      "sources": ["src/gui/**/*.cpp"],
      "output": "gui.lib",
      "depends": ["kernel", "abi", "seg", "batches"],
      "defines": ["UNICODE", "_UNICODE"]
    },
    "main": {
      "type": "executable",
      "language": "cpp",
      "sources": ["src/main.cpp"],
      "output": "SovereignIDE.exe",
      "depends": ["kernel", "abi", "backend", "seg", "batches", "gui"],
      "subsystem": "WINDOWS",
      "entry": "wWinMainCRTStartup"
    }
  }
}
```

### User Configuration

```json
// user-config.json - User-specific overrides
{
  "build": {
    "parallel_jobs": 16,
    "verbose": true,
    "keep_intermediate": false
  },
  
  "tools": {
    "assembler": "C:\\VS2022\\VC\\Tools\\MSVC\\14.35.32215\\bin\\Hostx64\\x64\\ml64.exe",
    "c_compiler": "C:\\VS2022\\VC\\Tools\\MSVC\\14.35.32215\\bin\\Hostx64\\x64\\cl.exe",
    "cpp_compiler": "C:\\VS2022\\VC\\Tools\\MSVC\\14.35.32215\\bin\\Hostx64\\x64\\cl.exe",
    "linker": "C:\\VS2022\\VC\\Tools\\MSVC\\14.35.32215\\bin\\Hostx64\\x64\\link.exe"
  },
  
  "environment": {
    "INCLUDE": [
      "C:\\VS2022\\VC\\Tools\\MSVC\\14.35.32215\\include",
      "C:\\Program Files\\Windows Kits\\10\\Include\\10.0.22621.0\\ucrt",
      "C:\\Program Files\\Windows Kits\\10\\Include\\10.0.22621.0\\um",
      "C:\\Program Files\\Windows Kits\\10\\Include\\10.0.22621.0\\shared"
    ],
    "LIB": [
      "C:\\VS2022\\VC\\Tools\\MSVC\\14.35.32215\\lib\\x64",
      "C:\\Program Files\\Windows Kits\\10\\Lib\\10.0.22621.0\\ucrt\\x64",
      "C:\\Program Files\\Windows Kits\\10\\Lib\\10.0.22621.0\\um\\x64"
    ]
  }
}
```

---

## Build Profiles

### Debug Profile

```json
{
  "name": "debug",
  "description": "Debug build with full symbols and no optimization",
  
  "compiler": {
    "flags": [
      "/Od",           // No optimization
      "/Zi",           // Full debug info
      "/MDd",          // Debug runtime
      "/W4",           // Warning level 4
      "/EHsc",         // Exception handling
      "/std:c++17",    // C++17 standard
      "/RTC1",         // Runtime checks
      "/GS",           // Buffer security check
      "/sdl"           // Security development lifecycle
    ],
    "defines": [
      "DEBUG",
      "_DEBUG",
      "ENABLE_ASSERTS",
      "ENABLE_LOGGING",
      "ENABLE_TRACING"
    ]
  },
  
  "linker": {
    "flags": [
      "/DEBUG",        // Generate debug info
      "/INCREMENTAL",  // Incremental linking
      "/SUBSYSTEM:CONSOLE"  // Console subsystem for debugging
    ]
  },
  
  "masm": {
    "flags": [
      "/c",            // Compile only
      "/W3",           // Warning level 3
      "/Zi",           // Debug info
      "/Zd"            // Line number info
    ]
  }
}
```

### Release Profile

```json
{
  "name": "release",
  "description": "Optimized release build",
  
  "compiler": {
    "flags": [
      "/O2",           // Maximize speed
      "/Ob2",          // Inline any suitable
      "/Oi",           // Intrinsic functions
      "/Ot",           // Favor fast code
      "/Oy",           // Omit frame pointer
      "/GL",           // Whole program optimization
      "/Gw",           // Optimize global data
      "/MD",           // Release runtime
      "/W4",
      "/EHsc",
      "/std:c++17",
      "/GS",
      "/sdl",
      "/guard:cf"      // Control flow guard
    ],
    "defines": [
      "NDEBUG",
      "RELEASE",
      "ENABLE_OPTIMIZATIONS"
    ]
  },
  
  "linker": {
    "flags": [
      "/OPT:REF",      // Remove unreferenced
      "/OPT:ICF",      // Identical COMDAT folding
      "/LTCG",         // Link-time code generation
      "/SUBSYSTEM:WINDOWS",
      "/RELEASE",      // Set checksum
      "/GUARD:CF"      // Enable CFG
    ]
  }
}
```

### Profile Profile

```json
{
  "name": "profile",
  "description": "Release build with profiling instrumentation",
  
  "inherits": "release",
  
  "compiler": {
    "flags": [
      "/Gh",           // _penter hook
      "/GH"            // _pexit hook
    ],
    "defines": [
      "PROFILE",
      "ENABLE_PROFILING"
    ]
  },
  
  "linker": {
    "flags": [
      "/DEBUG"         // Keep debug info for profiling
    ]
  }
}
```

---

## Compiler Options

### C/C++ Compiler Flags

| Flag | Description | Usage |
|------|-------------|-------|
| `/Od` | Disable optimization | Debug |
| `/O1` | Minimize size | Release |
| `/O2` | Maximize speed | Release |
| `/Ox` | Full optimization | Release |
| `/W0` | No warnings | - |
| `/W3` | Level 3 warnings | Standard |
| `/W4` | Level 4 warnings | Recommended |
| `/Wall` | All warnings | Strict |
| `/WX` | Treat warnings as errors | CI |
| `/EHsc` | C++ exception handling | Always |
| `/std:c++17` | C++17 standard | Always |
| `/MD` | Multi-threaded DLL | Release |
| `/MDd` | Multi-threaded debug DLL | Debug |
| `/Zi` | Program database | Debug |
| `/Z7` | Old-style debug info | - |
| `/GS` | Buffer security check | Always |
| `/sdl` | Security checks | Always |
| `/D<name>` | Define macro | - |
| `/U<name>` | Undefine macro | - |
| `/I<path>` | Include path | - |
| `/Fo<path>` | Object file output | - |
| `/Fd<path>` | PDB file output | - |
| `/Fp<path>` | Precompiled header | - |

### MASM Assembler Flags

| Flag | Description |
|------|-------------|
| `/c` | Assemble only, no link |
| `/W3` | Warning level 3 |
| `/Zi` | Debug info |
| `/Zd` | Line number info only |
| `/Fo<path>` | Object file output |
| `/I<path>` | Include path |
| `/D<name>` | Define symbol |
| `/nologo` | Suppress copyright |

---

## Linker Options

### Linker Flags

| Flag | Description | Usage |
|------|-------------|-------|
| `/OUT:<file>` | Output file name | Always |
| `/SUBSYSTEM:WINDOWS` | Windows subsystem | GUI |
| `/SUBSYSTEM:CONSOLE` | Console subsystem | Debug |
| `/ENTRY:<symbol>` | Entry point | Custom |
| `/OPT:REF` | Remove unreferenced | Release |
| `/OPT:ICF` | Identical COMDAT folding | Release |
| `/OPT:NOREF` | Keep unreferenced | Debug |
| `/LTCG` | Link-time code generation | Release |
| `/DEBUG` | Generate debug info | Debug |
| `/INCREMENTAL` | Incremental linking | Debug |
| `/LARGEADDRESSAWARE` | >2GB address space | Always |
| `/RELEASE` | Set checksum | Release |
| `/GUARD:CF` | Control flow guard | Security |
| `/DYNAMICBASE` | ASLR compatible | Security |
| `/NXCOMPAT` | DEP compatible | Security |
| `/LIBPATH:<path>` | Library search path | - |
| `/VERBOSE` | Print link steps | Debug |

### Library Manager Flags

| Flag | Description |
|------|-------------|
| `/OUT:<file>` | Output library name |
| `/NOLOGO` | Suppress copyright |
| `/VERBOSE` | Print operations |
| `/LTCG` | Link-time code generation |

---

## Platform-Specific Settings

### Windows Settings

```json
{
  "platform": "windows",
  "architecture": "x64",
  
  "system_libraries": [
    "kernel32.lib",
    "user32.lib",
    "gdi32.lib",
    "shell32.lib",
    "ole32.lib",
    "oleaut32.lib",
    "uuid.lib",
    "advapi32.lib",
    "comctl32.lib",
    "comdlg32.lib",
    "ws2_32.lib",
    "shlwapi.lib"
  ],
  
  "manifest": {
    "enabled": true,
    "file": "resources/app.manifest",
    "dpi_aware": true,
    "ui_access": false
  },
  
  "version_info": {
    "enabled": true,
    "file": "resources/version.rc",
    "company": "Sovereign Systems",
    "product": "Sovereign IDE",
    "version": "1.0.0.0",
    "copyright": "Copyright 2026"
  }
}
```

### Linux Settings

```json
{
  "platform": "linux",
  "architecture": "x64",
  
  "compiler": {
    "c": "gcc",
    "cpp": "g++",
    "flags": [
      "-std=c++17",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-fPIC",
      "-pthread"
    ]
  },
  
  "linker": {
    "command": "g++",
    "flags": [
      "-pthread",
      "-Wl,--no-undefined",
      "-Wl,-rpath,$ORIGIN"
    ]
  },
  
  "system_libraries": [
    "pthread",
    "dl",
    "rt",
    "m"
  ]
}
```

### macOS Settings

```json
{
  "platform": "macos",
  "architecture": "x64",
  
  "compiler": {
    "c": "clang",
    "cpp": "clang++",
    "flags": [
      "-std=c++17",
      "-Wall",
      "-Wextra",
      "-stdlib=libc++",
      "-mmacosx-version-min=12.0"
    ]
  },
  
  "linker": {
    "command": "clang++",
    "flags": [
      "-stdlib=libc++",
      "-framework Cocoa",
      "-framework Foundation",
      "-mmacosx-version-min=12.0"
    ]
  }
}
```

---

## Advanced Configuration

### Precompiled Headers

```json
{
  "precompiled_headers": {
    "enabled": true,
    "header": "src/pch.h",
    "source": "src/pch.cpp",
    "output": "build/obj/pch.pch",
    
    "for_targets": ["backend", "seg", "gui", "batches"],
    
    "compiler_flags": [
      "/Yu"pch.h"",
      "/Fp"build/obj/pch.pch""
    ]
  }
}
```

### Unity Build

```json
{
  "unity_build": {
    "enabled": true,
    "batch_size": 8,
    
    "for_targets": ["batches"],
    
    "exclusions": [
      "src/batches/batch_1/main.cpp",
      "src/batches/batch_49/agentic_main.cpp"
    ]
  }
}
```

### Custom Build Steps

```json
{
  "custom_steps": [
    {
      "name": "generate_version",
      "phase": "pre_build",
      "command": "python scripts/generate_version.py > src/version.h"
    },
    {
      "name": "copy_resources",
      "phase": "post_link",
      "command": "xcopy /E /I resources build/bin/resources"
    },
    {
      "name": "sign_binary",
      "phase": "post_build",
      "command": "signtool sign /f cert.pfx /p password build/bin/SovereignIDE.exe",
      "condition": "release"
    }
  ]
}
```

### Conditional Compilation

```json
{
  "conditions": [
    {
      "if": "config.profile == 'debug'",
      "then": {
        "defines": ["EXTRA_DEBUG_CHECKS"]
      }
    },
    {
      "if": "env.CI == 'true'",
      "then": {
        "compiler_flags": ["/WX"],
        "warnings_as_errors": true
      }
    },
    {
      "if": "platform == 'windows'",
      "then": {
        "defines": ["WINDOWS", "WIN32", "_WINDOWS"]
      },
      "else": {
        "defines": ["POSIX", "UNIX"]
      }
    }
  ]
}
```

---

## Summary

The Build Configuration Reference provides:

- ✅ **Complete configuration schema** with all options
- ✅ **Build profiles** (Debug, Release, Profile)
- ✅ **Compiler options** reference for C/C++/MASM
- ✅ **Linker options** reference
- ✅ **Platform-specific settings** (Windows, Linux, macOS)
- ✅ **Advanced features** (PCH, Unity builds, custom steps)

**Status:** ✅ Complete

---

*End of Build Configuration Reference*

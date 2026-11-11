# Frequently Asked Questions (FAQ)

**RAWRXD Compiler Driver v1.0.0**

---

## General Questions

### Q: What is RAWRXD Compiler Driver?

**A:** RAWRXD Compiler Driver is a unified compiler system that lets you compile C, Assembly, and C# code using a single tool with a consistent interface.

### Q: Why should I use this instead of individual compilers?

**A:** Benefits include:
- One command for all languages
- Consistent error messages
- Unified configuration
- IDE integration
- Zero dependencies

### Q: Is this free to use?

**A:** Yes! It's released under the MIT License, which means it's free for personal and commercial use.

### Q: What platforms are supported?

**A:** 
- Windows (primary)
- Linux (via Makefile)
- macOS (via Makefile)

---

## Installation Questions

### Q: Do I need to install anything else?

**A:** No! The RAWRXD Compiler Driver has zero external dependencies. You just need:
- Windows: Visual Studio 2019+ or the compiler executables
- Linux/macOS: GCC or Clang

### Q: How do I install it?

**A:** Three ways:
1. Run `install.bat` for system-wide installation
2. Copy `bin\rawrxd-compiler.exe` anywhere
3. Use the ZIP distribution

### Q: Can I use it without installing?

**A:** Yes! Just copy `bin\rawrxd-compiler.exe` to any folder and run it directly.

### Q: How do I uninstall?

**A:** Run `uninstall.bat` or simply delete the files.

---

## Usage Questions

### Q: What file types are supported?

**A:**
- C: `.c`, `.h`
- Assembly: `.asm`, `.s`, `.nasm`
- C#: `.cs`, `.csharp`

### Q: How do I compile a file?

**A:**
```batch
rawrxd-compiler compile hello.c
rawrxd-compiler compile program.asm
rawrxd-compiler compile app.cs
```

### Q: Can I specify the output file name?

**A:** Yes:
```batch
rawrxd-compiler compile -o myapp.exe hello.c
```

### Q: How do I enable optimization?

**A:**
```batch
rawrxd-compiler compile -O hello.c
```

### Q: Can I compile multiple files at once?

**A:** Yes:
```batch
rawrxd-compiler build file1.c file2.c file3.c
```

---

## Technical Questions

### Q: Does it actually compile the code?

**A:** Yes! It wraps the actual compilers:
- C: Uses `c_compiler_working.exe`
- Assembly: Uses `real_assembler.exe`
- C#: Uses `RoslynCLI_Test.exe`

### Q: Is it fast?

**A:** Yes! Typical compilation times:
- Small files: ~50ms
- Medium files: ~200ms
- Large files: ~1000ms

### Q: Does it work offline?

**A:** Yes! Once installed, no internet connection is required.

### Q: Can I add support for other languages?

**A:** Yes! The modular backend architecture makes it easy to add new compilers. See `CONTRIBUTING.md`.

### Q: Is it thread-safe?

**A:** Yes, the core driver is designed to be thread-safe.

---

## Troubleshooting

### Q: I get "compiler not found" error

**A:** Make sure:
1. The wrapped compilers are installed
2. They're in the expected paths
3. Or set the path in configuration

### Q: The VS Code extension doesn't work

**A:** Check:
1. Extension is installed correctly
2. `rawrxd-compiler` is in PATH
3. VS Code version is 1.74.0+

### Q: Tests are failing

**A:** Make sure:
1. All dependencies are installed
2. You're running from the correct directory
3. The compiler is built

### Q: Build fails with "cl not recognized"

**A:** Run from "x64 Native Tools Command Prompt for VS 2019+"

---

## Development Questions

### Q: How do I build from source?

**A:**
```batch
cd d:\rawrxd\tools\compiler_driver
build.bat
```

### Q: Can I contribute?

**A:** Yes! See `CONTRIBUTING.md` for guidelines.

### Q: What license is the code under?

**A:** MIT License - very permissive.

### Q: Where can I report bugs?

**A:** GitHub Issues

### Q: How do I request features?

**A:** GitHub Discussions or Issues

---

## Comparison Questions

### Q: How is this different from CMake?

**A:** CMake is a build system generator. RAWRXD is a compiler driver. They're complementary - you can use both!

### Q: How is this different from Make?

**A:** Make is a build automation tool. RAWRXD is a compiler driver. RAWRXD can be called from Makefiles.

### Q: Is this a replacement for Visual Studio?

**A:** No, it's a complement. Use VS for development, RAWRXD for quick compiles.

---

## Future Questions

### Q: Will you add more languages?

**A:** Yes! Planned: C++, JavaScript, Python, LLVM IR

### Q: Is there a roadmap?

**A:** Yes, see `CHANGELOG.md` and `RAWRXD_COMPILER_NEXT_STEPS.md`

### Q: Will it always be free?

**A:** Yes, MIT License ensures it stays free forever.

---

## Still Have Questions?

- 📖 Check the documentation in `docs/`
- 🐛 Report issues on GitHub
- 💬 Start a discussion on GitHub
- 📧 Contact the maintainers

---

*Last updated: 2026-07-19*

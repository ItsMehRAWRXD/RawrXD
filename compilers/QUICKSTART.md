# RawrXD Toolchain - Quick Start Guide

## 🚀 Get Started in 30 Seconds

### 1. Open Terminal
```batch
cd d:\rawrxd\compilers
```

### 2. Run Test Suite
```batch
rawrxd_ide_cli_v2.bat test
```
**Expected:** All tests pass ✅

### 3. Compile Your First Program

#### Assembly:
```batch
cd native_toolchain
echo _start: > hello.asm
echo     mov rax, 42 >> hello.asm
echo     ret >> hello.asm

compile_asm.bat hello.asm hello.exe
hello.exe
echo Exit code: %ERRORLEVEL%
```

#### C:
```batch
cd native_toolchain
echo int main(){return 42;} > hello.c

compile_c.bat hello.c hello.exe
hello.exe
echo Exit code: %ERRORLEVEL%
```

---

## 📚 Command Reference

### CLI Commands
| Command | Description | Example |
|---------|-------------|---------|
| `rawrxd_ide_cli_v2.bat <file>` | Compile any file | `rawrxd_ide_cli_v2.bat test.c` |
| `rawrxd_ide_cli_v2.bat test` | Run test suite | `rawrxd_ide_cli_v2.bat test` |
| `rawrxd_ide_cli_v2.bat list` | List compilers | `rawrxd_ide_cli_v2.bat list` |
| `rawrxd_ide_cli_v2.bat help` | Show help | `rawrxd_ide_cli_v2.bat help` |

### Direct Compilation
| Script | Input | Output | Example |
|--------|-------|--------|---------|
| `compile_asm.bat` | `.asm` | `.exe` | `compile_asm.bat test.asm out.exe` |
| `compile_c.bat` | `.c` | `.exe` | `compile_c.bat test.c out.exe` |

---

## 🛠️ Troubleshooting

### "Cannot create output file"
**Fix:** Check file permissions, use different output name

### "Assembly failed"
**Fix:** Check assembly syntax, ensure proper formatting

### "Linker failed"
**Fix:** Check object file was created, check PE headers

### "Exit code not 42"
**Fix:** Check program logic, ensure proper return value

---

## 📁 File Locations

```
d:\rawrxd\compilers\
├── native_toolchain\
│   ├── rawrxd_native_assembler.exe    (147 KB)
│   ├── rawrxd_native_linker_v2.exe    (64 KB)
│   ├── c_compiler_working.exe         (72 KB)
│   ├── compile_asm.bat                (ASM → EXE)
│   └── compile_c.bat                  (C → EXE)
├── rawrxd_ide_cli_v2.bat              (Unified CLI)
├── MILESTONE_85_PERCENT.md            (This milestone)
└── QUICKSTART.md                      (This file)
```

---

## ✅ Verification Checklist

- [ ] Test suite passes
- [ ] Can compile assembly
- [ ] Can compile C
- [ ] Executables run correctly
- [ ] Exit codes are correct

**All checked? You're ready to go!** 🎉

---

## 🎯 Next Steps

1. **Try the examples above**
2. **Write your own programs**
3. **Explore the documentation**
4. **Build something cool!**

---

**Questions?** Check `MANIFEST_INTEGRATION_STATUS.md` for full details.

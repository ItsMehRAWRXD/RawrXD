# START HERE - RAWRXD Compiler Driver

**Welcome!** This is your entry point to the RAWRXD Compiler Driver.

## ⚡ 30-Second Quick Start

```batch
# 1. Build
cd d:\rawrxd\tools\compiler_driver
build.bat

# 2. Test
cd tests
smoke_test.bat

# 3. Use
..\bin\rawrxd-compiler.exe compile hello.c
```

## 📚 Documentation Map

| Document | Purpose | Read This If... |
|----------|---------|-----------------|
| **START_HERE.md** | Entry point | You're new here |
| [RAWRXD_COMPILER_GETTING_STARTED.md](RAWRXD_COMPILER_GETTING_STARTED.md) | Tutorial | You want a guided tour |
| [README.md](README.md) | User guide | You need reference docs |
| [RAWRXD_COMPILER_QUICK_REFERENCE.md](RAWRXD_COMPILER_QUICK_REFERENCE.md) | Cheat sheet | You need quick lookup |
| [RAWRXD_COMPILER_BUILD_GUIDE.md](RAWRXD_COMPILER_BUILD_GUIDE.md) | Build instructions | You're building from source |
| [RAWRXD_COMPILER_INTEGRATION_SPEC_v1.0.md](RAWRXD_COMPILER_INTEGRATION_SPEC_v1.0.md) | Full spec | You need deep technical details |
| [RAWRXD_COMPILER_TROUBLESHOOTING.md](RAWRXD_COMPILER_TROUBLESHOOTING.md) | Problem solving | Something's not working |
| [RAWRXD_COMPILER_API_EXAMPLES.md](RAWRXD_COMPILER_API_EXAMPLES.md) | Code samples | You want to use the API |

## 🎯 What Is This?

The **RAWRXD Compiler Driver** is a unified compiler system that lets you compile C, Assembly, and C# code using a single tool.

**Key Features:**
- ✅ One command for all languages
- ✅ Auto-detects language from file extension
- ✅ Consistent error messages
- ✅ VS Code integration
- ✅ Cross-platform support

## 🚀 Common Tasks

### Compile Code
```batch
# Any supported language
rawrxd-compiler compile file.c
rawrxd-compiler compile file.asm
rawrxd-compiler compile file.cs
```

### Create New Project
```batch
tools\new-project.bat myproject c
cd myproject
rawrxd-compiler compile src\main.c
```

### Run Tests
```batch
cd tests
smoke_test.bat
```

## 📂 Project Structure

```
compiler_driver/
├── START_HERE.md          ← You are here
├── README.md              ← Main documentation
├── include/               ← API header
├── src/                   ← Source code
│   ├── compiler_driver.c  ← Core driver
│   ├── main.c             ← CLI
│   ├── config.c           ← Configuration
│   └── backends/          ← Language backends
├── tests/                 ← Test suite
├── examples/              ← Sample projects
├── tools/                 ← Utilities
├── scripts/               ← Build scripts
└── vscode-extension/      ← IDE integration
```

## 🆘 Need Help?

1. **Check the docs** - See Documentation Map above
2. **Run diagnostics** - `rawrxd-compiler list-backends`
3. **Check examples** - `examples/hello_world/`
4. **Read troubleshooting** - [RAWRXD_COMPILER_TROUBLESHOOTING.md](RAWRXD_COMPILER_TROUBLESHOOTING.md)

## 💡 Next Steps

1. **New User?** → Read [RAWRXD_COMPILER_GETTING_STARTED.md](RAWRXD_COMPILER_GETTING_STARTED.md)
2. **Developer?** → Read [RAWRXD_COMPILER_INTEGRATION_SPEC_v1.0.md](RAWRXD_COMPILER_INTEGRATION_SPEC_v1.0.md)
3. **Building?** → Read [RAWRXD_COMPILER_BUILD_GUIDE.md](RAWRXD_COMPILER_BUILD_GUIDE.md)
4. **API User?** → Read [RAWRXD_COMPILER_API_EXAMPLES.md](RAWRXD_COMPILER_API_EXAMPLES.md)

---

**Ready?** Pick a document from the map above and dive in! 🚀

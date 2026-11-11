# RAWRXD Compiler Driver - VS Code Extension

**Zero-Dependency Extension** - Works out of the box, no npm/build required!

---

## 🚀 Installation (No Build Required!)

### Method 1: Direct Install (Recommended)

1. Copy this entire `vscode-extension/` folder to your VS Code extensions directory:
   - Windows: `%USERPROFILE%\.vscode\extensions\rawrxd-compiler-1.0.0`
   - Linux/macOS: `~/.vscode/extensions/rawrxd-compiler-1.0.0`

2. Restart VS Code

3. Done! The extension is ready to use.

### Method 2: VSIX Package

```batch
# Create VSIX (optional)
cd vscode-extension
# Zip the folder and rename to .vsix

# Install in VS Code
# Ctrl+Shift+P -> "Extensions: Install from VSIX"
```

---

## ✨ Features

- **Zero Dependencies** - Pure JavaScript, no npm/node required
- **Compile on Save** - Optional auto-compile
- **Problem Detection** - Shows errors/warnings in Problems panel
- **Task Integration** - Build tasks for projects
- **Keybindings** - `Ctrl+Shift+B` to compile

---

## 🎮 Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| `RAWRXD: Compile Current File` | `Ctrl+Shift+B` | Compile open file |
| `RAWRXD: Build Project` | - | Build entire project |
| `RAWRXD: Clean Build` | - | Remove build artifacts |
| `RAWRXD: List Backends` | - | Show available compilers |

---

## ⚙️ Configuration

Open VS Code settings (`Ctrl+,`) and search for "RAWRXD":

```json
{
  "rawrxd.compilerPath": "rawrxd-compiler",
  "rawrxd.optimize": false,
  "rawrxd.debugInfo": true,
  "rawrxd.verbose": false
}
```

---

## 📝 Usage

1. Open a `.c`, `.asm`, or `.cs` file
2. Press `Ctrl+Shift+B` to compile
3. View output in Output panel ("RAWRXD Compiler")
4. View diagnostics in Problems panel

---

## 🔧 Requirements

- VS Code 1.74.0 or later
- RAWRXD Compiler Driver installed and in PATH

**No Node.js or npm required!**

---

## 📁 Files

```
vscode-extension/
├── extension.js      # Main extension code (pure JS)
├── package.json      # Extension manifest
└── README.md         # This file
```

---

## 🐛 Troubleshooting

### Extension not loading?
- Check VS Code version (>= 1.74.0)
- Verify folder is in extensions directory
- Restart VS Code

### Compiler not found?
- Set `rawrxd.compilerPath` to full path
- Ensure RAWRXD compiler is installed

### No output?
- Check Output panel (View -> Output -> RAWRXD Compiler)
- Enable verbose mode in settings

---

## 📄 License

MIT License - See LICENSE file

---

**Zero dependencies. Zero build steps. Just works.** ✅

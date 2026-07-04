# RawrXD-Script VS Code Extension

Language support for RawrXD-Script — a high-performance JavaScript engine with native x64 MASM interpreter, full LSP integration, and native debugging support.

## Features

- **Language Server Protocol (LSP)**: Real-time symbol analysis, hover info, completions, go-to-definition
- **Debug Adapter Protocol (DAP)**: Native debugging with register-level inspection (r0-r15)
- **Golden Master Validation**: Execution fingerprinting for deterministic testing
- **Trace Visualizer**: Interactive execution trace analysis

## Requirements

The extension requires the RawrXD-Script binaries to function. These are **not** bundled with the extension and must be provided separately.

### Required Binaries

1. **RawrXD_LSPServer.exe** — Language Server for IntelliSense
2. **RawrXDScriptDAPAdapter.exe** — Debug Adapter for debugging

### Binary Path Resolution

The extension will automatically search for binaries in the following locations (in order):

1. **Custom path** (if set in settings): `rawrxd-script.lsp.serverPath` / `rawrxd-script.debug.adapterPath`
2. **Extension `bin/` folder**: `<extension>/bin/RawrXD_*.exe`
3. **Development build**: `../../build/RawrXD_*.exe`
4. **Source tree**: `../../src/{lsp,script/debug}/RawrXD_*.exe`

### Setting Up Binaries

#### Option A: Copy to Extension Folder (Recommended)

```powershell
# After building RawrXD, copy binaries to extension
Copy-Item d:\rawrxd\build\RawrXD_LSPServer.exe d:\rawrxd\vscode-extension\bin\
Copy-Item d:\rawrxd\build\RawrXDScriptDAPAdapter.exe d:\rawrxd\vscode-extension\bin\
```

#### Option B: Configure Absolute Paths

Open VS Code Settings (Ctrl+,) and search for "RawrXD-Script":

- `rawrxd-script.lsp.serverPath`: `d:\rawrxd\build\RawrXD_LSPServer.exe`
- `rawrxd-script.debug.adapterPath`: `d:\rawrxd\build\RawrXDScriptDAPAdapter.exe`

#### Option C: Development Setup

If developing the extension alongside the RawrXD source tree, ensure your folder structure is:

```
rawrxd/
├── src/
│   ├── lsp/RawrXD_LSPServer.exe
│   └── script/debug/RawrXDScriptDAPAdapter.exe
└── vscode-extension/    <-- Extension development folder
```

## Extension Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `rawrxd-script.lsp.enabled` | Enable Language Server | `true` |
| `rawrxd-script.lsp.serverPath` | Path to LSP executable (auto-detected if empty) | `""` |
| `rawrxd-script.debug.trace` | Enable DAP protocol tracing | `false` |
| `rawrxd-script.debug.goldenMaster` | Enable Golden Master validation by default | `false` |
| `rawrxd-script.debug.adapterPath` | Path to DAP executable (auto-detected if empty) | `""` |

## Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| `rawrxd-script.run` | `Ctrl+Shift+R` | Run current script in terminal |
| `rawrxd-script.debug` | `F5` | Start debugging session |
| `rawrxd-script.runWithGoldenMaster` | — | Run with Golden Master validation |
| `rawrxd-script.openTraceVisualizer` | — | Open execution trace visualizer |
| `rawrxd-script.showRegisterView` | — | Show register inspection panel |
| `rawrxd-script.restartLSP` | — | Restart Language Server |

## Debugging

The extension provides full debugging support for RawrXD-Script:

1. Set breakpoints in `.rxs` files
2. Press `F5` to start debugging
3. Use standard VS Code debugging controls (Continue, Step Over, Step Into, etc.)
4. View live register values (r0-r15) in the "RawrXD Registers" debug panel
5. See NaN-boxed values decoded to their JavaScript types

## Troubleshooting

### "LSP server not found" error

The extension couldn't locate `RawrXD_LSPServer.exe`. Either:
- Copy the binary to the extension's `bin/` folder
- Set `rawrxd-script.lsp.serverPath` to the absolute path

### "Debug adapter not found" error

Same as above, but for `RawrXDScriptDAPAdapter.exe`. Set `rawrxd-script.debug.adapterPath`.

### Check the Output Panel

View > Output > "RawrXD-Script" for detailed logs showing where the extension is searching for binaries.

## Building from Source

See the main RawrXD repository build instructions. After building:

```powershell
cd vscode-extension
npm install
npm run compile
vsce package
```

Install the resulting `.vsix` file in VS Code.

## License

MIT — See main RawrXD repository for full license text.

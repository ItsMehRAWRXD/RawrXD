# RawrXD VS Code Extension — Integration Guide

## Overview

This extension provides AI-powered code completion via the RawrXD SuperNode cluster backend. It communicates with the native MASM LSP client which handles JSON-RPC protocol and pipes to the cluster.

## Architecture

```
VS Code <-> Extension Host <-> TypeScript Provider <-> MASM LSP Client <-> HAProxy <-> SuperNode Cluster
```

## Prerequisites

- VS Code 1.85+
- Node.js 18+
- RawrXD SuperNode cluster running (see cluster setup)
- MASM LSP Client built (`..\src\masm\LSPClient.exe`)

## Quick Start

### 1. Build Extension

```powershell
cd d:\RawrXD\vscode-extension
.\build.ps1 -Install
```

### 2. Configure Cluster Endpoint

Open VS Code settings (Ctrl+,) and search for "RawrXD":

```json
{
  "rawrxd.enabled": true,
  "rawrxd.clusterEndpoint": "http://localhost:8080",
  "rawrxd.maxTokens": 128,
  "rawrxd.temperature": 0.2
}
```

### 3. Verify Installation

1. Open a Python/JavaScript/C++ file
2. Type a function name and wait for completions
3. Check Output panel → "RawrXD LSP" for logs

## Development

### File Structure

```
vscode-extension/
├── package.json          # Extension manifest
├── tsconfig.json         # TypeScript config
├── build.ps1            # Build script
├── src/
│   ├── extension.ts      # Entry point
│   ├── completionProvider.ts  # Completion logic
│   └── clusterClient.ts      # HTTP client
└── out/                 # Compiled output
```

### Build Commands

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Watch mode
npm run watch

# Package for distribution
npm run vscode:prepublish
npx vsce package
```

### Debug Extension

1. Press F5 in VS Code (opens Extension Development Host)
2. Open a test file
3. Set breakpoints in `src/completionProvider.ts`
4. Trigger completion to hit breakpoints

## Configuration Options

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `rawrxd.enabled` | boolean | true | Enable/disable completion |
| `rawrxd.clusterEndpoint` | string | "http://localhost:8080" | HAProxy URL |
| `rawrxd.maxTokens` | number | 128 | Max completion tokens |
| `rawrxd.temperature` | number | 0.2 | Sampling temperature |

## Commands

| Command | Description |
|---------|-------------|
| `RawrXD: Enable Completion` | Turn on AI completion |
| `RawrXD: Disable Completion` | Turn off AI completion |
| `RawrXD: Show Cluster Status` | Display cluster health |

## Troubleshooting

### "RawrXD LSP spawn failed"

**Cause:** MASM LSP client not built

**Fix:**
```powershell
cd ..\src\masm
ml64 /c /W3 /nologo /Zi /Fo RawrXD_LSPClient.obj RawrXD_LSPClient.asm
link /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:LSPClient.exe `
    RawrXD_LSPClient.obj kernel32.lib
```

### "Request timeout"

**Cause:** Cluster not running or unreachable

**Fix:**
```powershell
# Check cluster status
curl http://localhost:8080/health

# Start cluster if needed
..\deploy_staging_cluster.ps1
```

### "No completions shown"

**Check:**
1. Extension is enabled in settings
2. File type is supported (Python, JS, TS, C, C++, ASM)
3. Cluster has available capacity
4. Check Output panel for errors

### "High latency"

**Tuning:**
- Reduce `maxTokens` to 64
- Check network to cluster endpoint
- Verify cluster TPS is > 1000

## Testing

### Unit Tests

```bash
npm test
```

### Integration Test

```powershell
# Start test cluster
..\deploy_staging_cluster.ps1

# Run extension tests
npm run test:integration
```

### Manual Test Checklist

- [ ] Extension activates on startup
- [ ] Completions appear after typing `.`
- [ ] Completions show confidence scores
- [ ] Disable/enable commands work
- [ ] Status command shows cluster info
- [ ] Works with Python files
- [ ] Works with JavaScript files
- [ ] Works with C++ files

## Distribution

### Create VSIX Package

```powershell
.\build.ps1 -Package
```

### Install from VSIX

```bash
code --install-extension rawrxd-lsp-client-0.1.0.vsix
```

### Publish to Marketplace

```bash
npx vsce publish
```

## Performance Monitoring

Enable debug logging in VS Code settings:

```json
{
  "rawrxd.debug": true
}
```

Check Output panel → "RawrXD LSP" for:
- Request latency
- Cache hit rates
- Cluster response times

## Security Considerations

- Extension communicates only with configured `clusterEndpoint`
- No data leaves local network by default
- Source code is never transmitted (only tokenized context)
- All communication over HTTP (upgrade to HTTPS for production)

## Support

For issues or feature requests:
1. Check troubleshooting section above
2. Review cluster logs: `..\logs\`
3. File issue with extension logs attached

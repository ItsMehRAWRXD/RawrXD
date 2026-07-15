# RawrXD MCP Server

A pure x64 MASM (Microsoft Macro Assembler) implementation of a Model Context Protocol (MCP) server.

## Overview

This MCP server provides AI assistants with access to the RawrXD codebase through three core tools:
- **echo**: Echoes input text back
- **read_file**: Reads file contents from the filesystem
- **list_dir**: Lists directory contents

## Architecture

- **Language**: Pure x64 MASM (no C runtime dependencies)
- **Protocol**: JSON-RPC 2.0 over stdio with HTTP-style framing (Content-Length headers)
- **Platform**: Windows x64 only
- **Size**: ~32KB standalone executable

## Build

```batch
:: Assemble
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /W3 /nologo /Zi /Fo RawrXD_MCPServer.obj RawrXD_MCPServer.asm

:: Link
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe /SUBSYSTEM:CONSOLE /ENTRY:RawrXD_MCPServer_Entry /LARGEADDRESSAWARE:NO /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /OUT:RawrXD_MCPServer.exe RawrXD_MCPServer.obj kernel32.lib
```

## Configuration

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "rawrxd-masm": {
      "command": "d:\\rawrxd\\src\\asm\\RawrXD_MCPServer.exe",
      "args": [],
      "env": {}
    }
  }
}
```

## Tools

### echo
Echoes input text back to the caller.

**Input Schema:**
```json
{
  "text": "string to echo"
}
```

### read_file
Reads the contents of a file.

**Input Schema:**
```json
{
  "path": "absolute or relative path to file"
}
```

### list_dir
Lists the contents of a directory.

**Input Schema:**
```json
{
  "path": "absolute or relative path to directory"
}
```

## Protocol

The server implements the Model Context Protocol (MCP) specification:

1. **Initialize**: Server responds to `initialize` method with capabilities
2. **Tools/List**: Returns available tools (echo, read_file, list_dir)
3. **Tools/Call**: Executes the requested tool with provided arguments
4. **Shutdown**: Graceful shutdown on `shutdown` method

## Implementation Details

- Single-threaded HTTP request handler
- JSON-RPC 2.0 message format
- HTTP-style Content-Length framing
- Pure Windows API (kernel32.lib only)
- No external dependencies

## Files

- `RawrXD_MCPServer.asm` - Main server implementation (~1100 lines)
- `RawrXD_MCPServer.exe` - Compiled executable (32KB)
- `mcp-config.json` - MCP client configuration

## Status

✅ Built and linked successfully
✅ Ready for testing with MCP clients

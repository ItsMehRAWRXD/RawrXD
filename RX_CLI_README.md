# RawrXD CLI (rx) - Command Line Interface

**Quick Start:** Use `rx` command to interact with RawrXD agentically

## Usage

```batch
rx [model-name] [command]
rx [special-command]
```

## Examples

### Agentic Mode (Natural Language)
```batch
rx qwen "compile this C project"
rx gpt4 "fix the errors in main.c"
rx local "analyze my codebase"
rx default "create a hello world program"
```

### Special Commands
```batch
rx list        - List available models
rx status      - Show system status
rx compile     - Quick compile mode
rx demo        - Run demonstration
rx test        - Run test suite
rx update      - Update toolchain
rx help        - Show help
```

## How It Works

1. **Intent Detection** - The CLI analyzes your natural language command
2. **Tool Selection** - Automatically selects appropriate tools
3. **Execution** - Runs the task autonomously
4. **Reporting** - Shows results and next steps

## Actions Supported

| Command Contains | Action Taken |
|------------------|--------------|
| "compile", "build" | Compiles source files found in current directory |
| "fix", "repair" | Shows diagnostic suggestions |
| "analyze", "review" | Lists and analyzes files |
| "generate", "create" | Creates template files |
| "test", "run" | Runs test suite |

## Setup

Add to your PATH:
```batch
set PATH=%PATH%;D:\rawrxd
```

Or use full path:
```batch
D:\rawrxd\rx.bat qwen "compile this project"
```

## Files

- `rx.bat` - Main CLI launcher (this file)
- `rawrxd.bat` - Alternative launcher with more features
- Located in: `D:\rawrxd\`

## Troubleshooting

**"This app can't run on your PC"**
- The executable may be blocked by Windows Defender
- Right-click → Properties → Unblock
- Or rebuild: `rx update`

**"Command not found"**
- Add `D:
awrxd` to your PATH
- Or use full path: `D:
awrxd
x.bat`

**Build fails**
- Check status: `rx status`
- Update toolchain: `rx update`
- Run tests: `rx test`

## Integration with Win32IDE

The same commands work in Win32IDE:
```
/native-compile file.c
/native-assemble file.asm
/native-link file.obj
```

Or use the agentic CLI:
```
rx qwen "compile the current project"
```

# RawrXD AI Control Bridge — Quick Start

## 🎯 Overview

The AI Control Bridge transforms RawrXD IDE into an **AI-controllable research platform**. It provides:

- **Telemetry Output**: Real-time IDE state in JSON format
- **Command Input**: External AI can send commands to control the IDE
- **Headless Mode**: Run without GUI for automated testing

---

## 🚀 Quick Start

### 1. Enable the Bridge

Add to your `rawrxd.config.json`:

```json
{
  "agentBridge": {
    "enabled": true,
    "telemetryPath": "rawrxd_telemetry.json",
    "commandInputPath": "ai_control.json",
    "responseOutputPath": "ai_response.json",
    "logPath": "rawrxd_agent.log",
    "telemetryIntervalMs": 500,
    "commandPollIntervalMs": 100
  }
}
```

### 2. Launch RawrXD

```powershell
.\RawrXD-Win32IDE.exe
```

### 3. Monitor Telemetry

In VS Code terminal:

```powershell
# Watch telemetry in real-time
Get-Content rawrxd_telemetry.json -Wait -Tail 10

# Or use tail equivalent
while ($true) { Get-Content rawrxd_telemetry.json; Start-Sleep -Milliseconds 500; Clear-Host }
```

### 4. Send Commands

Create `ai_control.json`:

```json
{
  "type": "getState",
  "commandId": 1,
  "parameters": {}
}
```

RawrXD will process and write response to `ai_response.json`.

---

## 📡 Telemetry Format

`rawrxd_telemetry.json`:

```json
{
  "timestamp": 1234567890,
  "processId": 1234,
  "memory": {
    "workingSetBytes": 52428800,
    "virtualMemoryBytes": 104857600,
    "peakWorkingSetBytes": 55000000
  },
  "gdi": {
    "objects": 245,
    "userObjects": 120,
    "peakObjects": 250
  },
  "window": {
    "width": 1600,
    "height": 1000,
    "isMinimized": false,
    "isForeground": true
  },
  "editor": {
    "width": 1200,
    "height": 800,
    "cursorLine": 42,
    "cursorColumn": 15,
    "totalLines": 1500,
    "currentFile": "src/main.cpp"
  },
  "lsp": {
    "connected": true,
    "serverName": "clangd",
    "pendingRequests": 2,
    "diagnosticsCount": 5
  },
  "performance": {
    "lastFrameTimeMs": 16.67,
    "avgFrameTimeMs": 15.2,
    "messagesPerSecond": 60
  },
  "agent": {
    "running": false,
    "queueSize": 0,
    "lastAction": "completion"
  },
  "errors": {
    "count": 0,
    "lastError": ""
  }
}
```

---

## 🎮 Command Reference

### Navigation

```json
{ "type": "openFile", "parameters": { "path": "src/main.cpp" } }
{ "type": "closeFile" }
{ "type": "saveFile" }
{ "type": "gotoLine", "parameters": { "line": "42" } }
```

### Search

```json
{ "type": "findText", "parameters": { "text": "createEditor", "caseSensitive": "false" } }
{ "type": "replaceText", "parameters": { "find": "old", "replace": "new" } }
```

### LSP

```json
{ "type": "requestHover", "parameters": { "line": "10", "column": "5" } }
{ "type": "requestCompletion", "parameters": { "line": "10", "column": "5" } }
{ "type": "resetLsp" }
```

### Debug

```json
{ "type": "setBreakpoint", "parameters": { "line": "42" } }
{ "type": "clearBreakpoint", "parameters": { "line": "42" } }
{ "type": "runDebug" }
{ "type": "stopDebug" }
{ "type": "runBuild" }
```

### IDE Control

```json
{ "type": "resize", "parameters": { "width": "1600", "height": "900" } }
{ "type": "setFocus" }
{ "type": "executeCommand", "parameters": { "commandId": "1001" } }
{ "type": "dumpLayout" }
{ "type": "getState" }
{ "type": "shutdown" }
```

### AI Agent

```json
{ "type": "agentPrompt", "parameters": { "prompt": "Optimize this function for performance" } }
```

---

## 🤖 AI Workflow Example

### Step 1: AI Reads Telemetry

```python
import json
import time

def read_telemetry():
    with open('rawrxd_telemetry.json', 'r') as f:
        return json.load(f)

# Monitor for issues
while True:
    data = read_telemetry()
    if data['memory']['workingSetBytes'] > 200_000_000:
        print(f"WARNING: High memory usage: {data['memory']['workingSetBytes']} bytes")
    if data['gdi']['objects'] > 500:
        print(f"WARNING: High GDI object count: {data['gdi']['objects']}")
    time.sleep(1)
```

### Step 2: AI Sends Command

```python
import json

def send_command(cmd_type, params=None):
    cmd = {
        "type": cmd_type,
        "commandId": 1,
        "parameters": params or {}
    }
    with open('ai_control.json', 'w') as f:
        json.dump(cmd, f, indent=2)

# Open a file
send_command("openFile", {"path": "src/main.cpp"})

# Wait for response
import time
time.sleep(0.5)

with open('ai_response.json', 'r') as f:
    response = json.load(f)
    print(f"Success: {response['success']}, Message: {response['message']}")
```

### Step 3: AI Diagnoses Performance

```python
def analyze_performance():
    data = read_telemetry()
    
    issues = []
    
    if data['performance']['avgFrameTimeMs'] > 33:
        issues.append(f"Low FPS: {1000/data['performance']['avgFrameTimeMs']:.1f}")
    
    if data['lsp']['pendingRequests'] > 10:
        issues.append(f"LSP backlog: {data['lsp']['pendingRequests']} requests")
    
    if data['errors']['count'] > 0:
        issues.append(f"Errors: {data['errors']['lastError']}")
    
    return issues

issues = analyze_performance()
if issues:
    print("Performance issues detected:")
    for issue in issues:
        print(f"  - {issue}")
```

---

## 🧪 Headless Mode

For automated testing:

```powershell
# Set environment variable
$env:RAWRXD_HEADLESS = "1"

# Run headless
.\RawrXD-Win32IDE.exe --headless

# Or use config
{
  "headless": true
}
```

In headless mode:
- No GUI is created
- LSP still runs
- Commands still processed
- Telemetry still generated
- Perfect for CI/CD testing

---

## 📊 Integration with VS Code

### Task to Monitor RawrXD

`.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Monitor RawrXD Telemetry",
      "type": "shell",
      "command": "Get-Content rawrxd_telemetry.json -Wait -Tail 10",
      "problemMatcher": [],
      "isBackground": true
    }
  ]
}
```

### Extension to Send Commands

Create a simple VS Code extension that:
1. Reads `rawrxd_telemetry.json`
2. Displays status in status bar
3. Sends commands via `ai_control.json`

---

## 🔧 Troubleshooting

### Telemetry file not updating
- Check that `agentBridge.enabled` is `true`
- Verify file paths are absolute or relative to working directory
- Check `rawrxd_agent.log` for errors

### Commands not executing
- Ensure `ai_control.json` is being written correctly
- Check that JSON is valid
- Verify command type is supported

### High CPU usage
- Increase `telemetryIntervalMs` to 1000 or higher
- Reduce `commandPollIntervalMs` if not needed

---

## 🎯 Use Cases

1. **Automated Testing**: Run headless, send commands, verify responses
2. **Performance Monitoring**: Track memory/GDI over time
3. **Remote Debugging**: AI analyzes telemetry, suggests fixes
4. **CI/CD Integration**: Headless builds with telemetry validation
5. **AI Pair Programming**: AI reads state, suggests commands

---

**The bridge is now open. RawrXD is ready to be driven by AI.** 🚀

# AgentTools (PowerShell)

A lightweight local tools server exposing file and command operations over HTTP for agent integration on Windows.

Endpoints (POST JSON to http://127.0.0.1:8765):
- `/fs/read`: `{ path, startLine?, endLine?, encoding?, maxBytes? }`
- `/fs/write`: `{ path, content, encoding? }`
- `/fs/append`: `{ path, content, encoding? }`
- `/fs/list`: `{ path, recurse? }`
- `/fs/delete`: `{ path, recurse? }`
- `/fs/copy`: `{ source, destination, recurse? }`
- `/fs/move`: `{ source, destination }`
- `/grep/search`: `{ path, pattern, isRegex?, include?, maxResults? }`
- `/cmd/run`: `{ command, arguments?, cwd?, timeoutSec?, background? }`

Safety:
- Access limited to: `C:\Users\HiH8e\OneDrive\Desktop\`, `D:\`, `E:\`.
- Requests/Responses are JSON. All errors return `{ ok:false, error:"..." }` with HTTP 500.

## Quickstart

Start the server (PowerShell 7+ recommended):

```powershell
# From the AgentTools directory
pwsh -NoProfile -ExecutionPolicy Bypass -File .\AgentToolsServer.ps1 -Port 8765
```

Test with Invoke-RestMethod:

```powershell
$base = 'http://127.0.0.1:8765'

# List desktop
Invoke-RestMethod -Method Post -Uri "$base/fs/list" -Body (@{ path = "C:\\Users\\HiH8e\\OneDrive\\Desktop" } | ConvertTo-Json) -ContentType 'application/json'

# Read file
Invoke-RestMethod -Method Post -Uri "$base/fs/read" -Body (@{ path = "C:\\Users\\HiH8e\\OneDrive\\Desktop\\Powershield\\2-LINE-OFFSET-FIX.md" } | ConvertTo-Json) -ContentType 'application/json'

# Write file
Invoke-RestMethod -Method Post -Uri "$base/fs/write" -Body (@{ path = "D:\\temp\\example.txt"; content = "Hello world" } | ConvertTo-Json) -ContentType 'application/json'

# Run command
Invoke-RestMethod -Method Post -Uri "$base/cmd/run" -Body (@{ command = "pwsh"; arguments = @('-NoProfile','-Command','Get-ChildItem D:\\OllamaModels | Select-Object -First 3') } | ConvertTo-Json) -ContentType 'application/json'
```

## Example client script
See `examples/Test-Requests.ps1` for a minimal test.

## Notes
- Background command runs return `{ JobId, State }`. Use PowerShell to manage jobs: `Get-Job`, `Receive-Job`, `Stop-Job`.
- To change allowed roots, edit `AllowedRoots` in `AgentTools.psm1`.
- This server is local-only (127.0.0.1). Do not expose to untrusted networks.

# RawrXD-QtShell Pure MASM Agentic Feature Test Script
# Purpose: Validate MASM-only IDE runtime features (panes, themes, drag/dock)
# and collect metrics suitable for comparison against other IDE assistants.
#
# Usage (PowerShell):
#   pwsh -File scripts/test_pure_masm_agentic.ps1
#   pwsh -File scripts/test_pure_masm_agentic.ps1 -ExePath "C:\Path\RawrXD-QtShell.exe"
#
# Notes:
# - No external modules required; uses Add-Type P/Invoke for User32.
# - Measures startup time, theme switching latency, pane drag simulation.
# - Reads optional benchmarks from benchmarks\agentic_compare.json for comparisons.

param(
  [string]$ExePath = "C:\Users\HiH8e\Downloads\RawrXD-production-lazy-init\build\bin\Release\RawrXD-QtShell.exe",
  [int]$LaunchTimeoutSec = 20
)

$ErrorActionPreference = "Stop"

# Constants
$WM_COMMAND   = 0x0111
$WM_LBUTTONDOWN = 0x0201
$WM_MOUSEMOVE   = 0x0200
$WM_LBUTTONUP   = 0x0202
$SW_SHOW = 5

# Theme command IDs (from project docs)
$IDM_THEME_LIGHT = 2022
$IDM_THEME_DARK  = 2023
$IDM_THEME_AMBER = 2024
$IDM_AGENT_PERSIST_THEME = 2102

# P/Invoke User32 helpers
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class U32 {
  [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
  public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool PostMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool UpdateWindow(IntPtr hWnd);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool EnumChildWindows(IntPtr hWnd, EnumChildProc lpEnumFunc, IntPtr lParam);
  public delegate bool EnumChildProc(IntPtr hWnd, IntPtr lParam);
}
"@

function Get-MainWindowHandle {
  param([System.Diagnostics.Process]$proc, [int]$timeoutSec = 20)
  $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSec)
  while ([DateTime]::UtcNow -lt $deadline) {
    $proc.Refresh()
    if ($proc.MainWindowHandle -ne 0) { return [IntPtr]$proc.MainWindowHandle }
    Start-Sleep -Milliseconds 200
  }
  throw "MainWindowHandle not available within $timeoutSec seconds"
}

function Measure-Action {
  param([string]$name, [scriptblock]$action)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $result = &$action
  $sw.Stop()
  return [PSCustomObject]@{ Name=$name; Milliseconds=[math]::Round($sw.Elapsed.TotalMilliseconds,2); Result=$result }
}

function Send-MenuCommand {
  param([IntPtr]$hWnd, [int]$commandId)
  [void][U32]::SendMessage($hWnd, $WM_COMMAND, [IntPtr]$commandId, [IntPtr]::Zero)
}

function Simulate-Drag {
  param([IntPtr]$hWnd, [int]$x1, [int]$y1, [int]$x2, [int]$y2)
  # lParam encodes x (low word) and y (high word)
  $lpDown = [IntPtr]([int](($y1 -band 0xFFFF) -shl 16) -bor ($x1 -band 0xFFFF))
  $lpMove = [IntPtr]([int](($y2 -band 0xFFFF) -shl 16) -bor ($x2 -band 0xFFFF))
  $lpUp   = $lpMove
  [void][U32]::PostMessage($hWnd, $WM_LBUTTONDOWN, [IntPtr]1, $lpDown)
  Start-Sleep -Milliseconds 30
  [void][U32]::PostMessage($hWnd, $WM_MOUSEMOVE,   [IntPtr]0, $lpMove)
  Start-Sleep -Milliseconds 30
  [void][U32]::PostMessage($hWnd, $WM_LBUTTONUP,   [IntPtr]0, $lpUp)
}

Write-Host "Launching RawrXD-QtShell..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $ExePath -PassThru

$startup = Measure-Action -name "IDE Startup" -action {
  Get-MainWindowHandle -proc $proc -timeoutSec $LaunchTimeoutSec
}
$hWnd = [IntPtr]$startup.Result

# Ensure window is shown and updated
[void][U32]::ShowWindow($hWnd, $SW_SHOW)
[void][U32]::UpdateWindow($hWnd)

# Enumerate child windows count
$childCount = 0
$callback = [U32+EnumChildProc]{ param([IntPtr]$c,[IntPtr]$p) $script:childCount++; $true }
[void][U32]::EnumChildWindows($hWnd, $callback, [IntPtr]::Zero)

# Theme switching latency
$themeDark  = Measure-Action -name "Theme → Dark"  -action { Send-MenuCommand -hWnd $hWnd -commandId $IDM_THEME_DARK }
$themeLight = Measure-Action -name "Theme → Light" -action { Send-MenuCommand -hWnd $hWnd -commandId $IDM_THEME_LIGHT }
$themeAmber = Measure-Action -name "Theme → Amber" -action { Send-MenuCommand -hWnd $hWnd -commandId $IDM_THEME_AMBER }
$themePersist = Measure-Action -name "Theme Persist" -action { Send-MenuCommand -hWnd $hWnd -commandId $IDM_AGENT_PERSIST_THEME }

# Pane drag simulation (generic coords; IDE handles hit-testing internally)
$drag1 = Measure-Action -name "Pane Drag 1" -action { Simulate-Drag -hWnd $hWnd -x1 120 -y1 160 -x2 420 -y2 240 }
$drag2 = Measure-Action -name "Pane Drag 2" -action { Simulate-Drag -hWnd $hWnd -x1 320 -y1 480 -x2 160 -y2 180 }

# Optional: Layout file presence check (user may need to trigger save in UI)
$layoutFile = Join-Path (Split-Path $ExePath -Parent) "ide_layout.json"
$layoutExists = Test-Path $layoutFile
$layoutSizeKB = if ($layoutExists) { [math]::Round((Get-Item $layoutFile).Length/1024,2) } else { 0 }

# Collate results
$results = @(
  [PSCustomObject]@{ Metric="Startup";    Value="$($startup.Milliseconds) ms";  Detail="Main window handle OK" },
  [PSCustomObject]@{ Metric="ChildWindows";Value="$childCount";              Detail="Component handles enumerated" },
  [PSCustomObject]@{ Metric=$themeDark.Name;   Value="$($themeDark.Milliseconds) ms";   Detail="WM_COMMAND $IDM_THEME_DARK" },
  [PSCustomObject]@{ Metric=$themeLight.Name;  Value="$($themeLight.Milliseconds) ms";  Detail="WM_COMMAND $IDM_THEME_LIGHT" },
  [PSCustomObject]@{ Metric=$themeAmber.Name;  Value="$($themeAmber.Milliseconds) ms";  Detail="WM_COMMAND $IDM_THEME_AMBER" },
  [PSCustomObject]@{ Metric=$themePersist.Name;Value="$($themePersist.Milliseconds) ms";Detail="Persist to ide_theme.cfg" },
  [PSCustomObject]@{ Metric=$drag1.Name;       Value="$($drag1.Milliseconds) ms";       Detail="WM_LBUTTONDOWN/MOVE/UP" },
  [PSCustomObject]@{ Metric=$drag2.Name;       Value="$($drag2.Milliseconds) ms";       Detail="WM_LBUTTONDOWN/MOVE/UP" },
  [PSCustomObject]@{ Metric="LayoutFile";     Value=($layoutExists ? "Present" : "Missing"); Detail="Size: $layoutSizeKB KB" }
)

# Comparison (optional): read benchmarks/agentic_compare.json
$comparePath = "C:\Users\HiH8e\Downloads\RawrXD-production-lazy-init\benchmarks\agentic_compare.json"
$comparison = $null
if (Test-Path $comparePath) {
  try { $comparison = Get-Content $comparePath | ConvertFrom-Json } catch {}
}

Write-Host "\nRawrXD-QtShell MASM Feature Metrics" -ForegroundColor Green
$results | Format-Table -AutoSize

if ($comparison -ne $null) {
  Write-Host "\nExternal Benchmarks (Cursor / Copilot)" -ForegroundColor Yellow
  $comparison | Format-Table -AutoSize
}

Write-Host "\nDone. Close the IDE manually to end the session." -ForegroundColor Cyan

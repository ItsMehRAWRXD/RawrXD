$Script:ErrorActionPreference = 'Stop'

$Script:w = New-Object -ComObject WScript.Shell
$Script:startMenu = Join-Path ${env:APPDATA} "Microsoft\Windows\Start Menu\Programs"

function New-Shortcut {
  param(
    [Parameter(Mandatory=$true)][string]$name,
    [Parameter(Mandatory=$true)][string]$root,
    [Parameter(Mandatory=$true)][string]$pattern
  )
  if (-not (Test-Path -LiteralPath $root)) { Write-Warning "Skip $($name): $root not found"; return }

$Script:exe = Get-ChildItem -LiteralPath $root -Filter $pattern -File -Recurse -ErrorAction SilentlyContinue |
         Sort-Object -Property Length -Descending |
         Select-Object -First 1
  if (-not $exe) {
$Script:exe = Get-ChildItem -LiteralPath $root -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue |
           Sort-Object -Property LastWriteTime -Descending |
           Select-Object -First 1
  }
  if (-not $exe -and (Test-Path -LiteralPath 'D:\\AmazonQ-IDE.exe') -and $name -eq 'Amazon Q IDE') {
$Script:exe = Get-Item -LiteralPath 'D:\\AmazonQ-IDE.exe'
  }
  if (-not $exe) { Write-Warning "Skip $($name): no EXE in $root"; return }

$Script:lnk = Join-Path $startMenu ("{0}.lnk" -f $name)
$Script:s = $w.CreateShortcut($lnk)
  $s.TargetPath = $exe.FullName
  $s.WorkingDirectory = $root
  $s.Save()
  Write-Host "Shortcut created: $lnk -> $($exe.Name)"
}

$Script:amazonRoot = ${env:AMAZONQ_HOME};     if (-not $amazonRoot)    { $amazonRoot    = "D:\amazonq-ide" }
$Script:mycopilotRoot = ${env:MYCOPILOT_HOME};   if (-not $mycopilotRoot) { $mycopilotRoot = "D:\MyCoPilot-Complete-Portable" }

New-Shortcut -name "Amazon Q IDE"  -root $amazonRoot    -pattern "*AmazonQ*.exe"
New-Shortcut -name "MyCoPilot IDE" -root $mycopilotRoot -pattern "*Copilot*.exe"

[CmdletBinding()]
param(
    [string]$Exe = 'F:\rawrxd\kartgib\build\msvc\Release\KartGib.exe',
    [string]$OutputRoot = 'F:\rawrxd\kartgib\diagnostics',
    [int]$TimeoutSeconds = 45,
    [int]$Seed = 20261025,
    [string]$Biome = 'tropical',
    [string]$CdbPath = '',
    [switch]$FullDump
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { throw "Executable not found: $Exe" }
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out = Join-Path $OutputRoot "startup_$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null

if (-not $CdbPath) {
    $cmd = Get-Command cdb.exe -ErrorAction SilentlyContinue
    if ($cmd) { $CdbPath = $cmd.Source }
    if (-not $CdbPath) {
        $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe", "$env:ProgramFiles\Windows Kits\10\Debuggers\x64\cdb.exe")
        $CdbPath = $roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    }
}
if (-not $CdbPath -or -not (Test-Path -LiteralPath $CdbPath)) {
    throw "cdb.exe not found. Install 'Debugging Tools for Windows' from Windows SDK or pass -CdbPath. Evidence directory: $out"
}

$hash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash
$meta = [ordered]@{
    timestamp = (Get-Date).ToString('o'); exe = $Exe; sha256 = $hash
    debugger = $CdbPath; timeout_seconds = $TimeoutSeconds
    seed = $Seed; biome = $Biome; cwd = (Split-Path -Parent $Exe)
    computer = $env:COMPUTERNAME; os = [Environment]::OSVersion.VersionString
}
$meta | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'metadata.json') -Encoding UTF8

$dumpPath = (Join-Path $out 'kartgib_exception.dmp')
$dumpFlag = if ($FullDump) { '/ma' } else { '/m' }
$onException = ".echo === KARTGIB_EXCEPTION ===; .exr -1; .ecxr; kv; ~* k; lm; .dump $dumpFlag `"$dumpPath`"; q"
$commands = ".symfix; .reload; sxe -c `"$onException`" av; sxe -c `"$onException`" 0xc0000409; sxe -c `"$onException`" 0xc000001d; sxe -c `"$onException`" 0xc0000094; sxe -c `"$onException`" 0xc00000fd; g"

$stdout = Join-Path $out 'cdb_stdout.log'
$stderr = Join-Path $out 'cdb_stderr.log'
$cmdFile = Join-Path $out 'debugger_commands.txt'
Set-Content -LiteralPath $cmdFile -Value $commands -Encoding ASCII
$debuggerArgs = @('-logo', ('"' + (Join-Path $out 'cdb_session.log') + '"'), '-cf', ('"' + $cmdFile + '"'), ('"' + $Exe + '"'), '--seed', "$Seed", '--biome', $Biome)
Write-Host "[KartGib] EXE: $Exe"
Write-Host "[KartGib] SHA256: $hash"
Write-Host "[KartGib] Evidence: $out"
Write-Host "[KartGib] Starting under CDB (timeout ${TimeoutSeconds}s)..."
$proc = Start-Process -FilePath $CdbPath -ArgumentList $debuggerArgs -WorkingDirectory (Split-Path -Parent $Exe) -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$completed = $proc.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)
$status = 'EXITED'
if (-not $completed) {
    $status = 'TIMEOUT_OR_HANG'
    Write-Warning 'Timeout: attempting non-invasive hang capture before terminating debugger.'
    Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('KartGib.exe','cdb.exe') } |
        Select-Object ProcessId,ParentProcessId,Name,CommandLine |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'processes_at_timeout.json')
    try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch { Write-Warning $_ }
    Start-Sleep -Milliseconds 800
    Get-CimInstance Win32_Process -Filter "name='KartGib.exe'" |
        Where-Object { $_.CommandLine -match [regex]::Escape($Exe) } |
        ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force } catch { Write-Warning $_ } }
} else {
    $proc.Refresh()
    $meta.debugger_exit_code = $proc.ExitCode
}
$meta.result = $status
$meta | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'metadata.json') -Encoding UTF8
Write-Host "[KartGib] Status: $status"
Write-Host "[KartGib] Logs: $out"
Write-Host "[KartGib] Look for KARTGIB_EXCEPTION, .exr, .ecxr, and ~* k in cdb_session.log"
Write-Host "[KartGib] If TIMEOUT_OR_HANG, use WinDbg GUI: File > Attach to Process > KartGib.exe; Debug > Break; enter ~* k and .dump /ma <path>."

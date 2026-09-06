# Phase B — CRT break-on-alloc for heap corruption localization (same EXE, no rebuild).
# Usage (before repro):
#   .\run_heap_alloc_break.ps1 -AllocNumber 534381
# Requires: Windows SDK Debugging Tools (gflags + cdb) OR Visual Studio native debugger.

param(
    [long]$AllocNumber = 534381,
    [string]$Exe = 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe',
    [switch]$DisablePageHeap
)

$ErrorActionPreference = 'Stop'
$outDir = Join-Path $PSScriptRoot 'HEAP_CORRUPT_001'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$allocLog = Join-Path $outDir 'ALLOC_BREAK.txt'

function Find-Tool([string]$name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSIsContainer }
    foreach ($k in $kits) {
        $p = Join-Path $k.FullName "$name.exe"
        if (Test-Path $p) { return $p }
    }
    return $null
}

$gflags = Find-Tool 'gflags'
$cdb = Find-Tool 'cdb'
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

if ($DisablePageHeap) {
    if (-not $gflags) { throw 'gflags not found' }
    & $gflags /p /disable (Split-Path $Exe -Leaf) | Out-String | Write-Host
    exit 0
}

$lines = @(
    "ALLOC_BREAK session $stamp",
    "EXE=$Exe",
    "ALLOC_NUMBER=$AllocNumber",
    ''
)

if ($gflags) {
    $leaf = Split-Path $Exe -Leaf
    & $gflags /p /enable $leaf /full | Out-String | Add-Content -Path $allocLog
    $lines += "PageHeap: enabled via gflags /p /enable $leaf /full"
    $lines += 'Repro Work Mode chat; on break save call stack to this file.'
    $lines += "Disable: .\\run_heap_alloc_break.ps1 -DisablePageHeap"
} else {
    $lines += 'PageHeap: gflags not installed.'
}

$lines += ''
$lines += 'CRT _CrtSetBreakAlloc (Visual Studio native, same binary):'
$lines += "  1. Debug -> Start Debugging (F5) on existing EXE"
$lines += "  2. Immediate: _CrtSetBreakAlloc($AllocNumber)"
$lines += '  3. Repro; on alloc break set data breakpoint (write) on returned pointer'
$lines += '  4. Save first writer stack here'

if ($cdb -and $gflags) {
    $lines += ''
    $lines += "cdb=$cdb"
    $lines += 'Launch: cdb -g -G -o -p <pid>  (attach after manual IDE start; no harness kill)'
}

$lines += ''
$lines += 'Agent note: writer statically sealed as utf8w OOB — see WRITER_VERDICT.txt.'
$lines += 'Re-run this script only if post-fix regression suspected.'

$lines | Set-Content -Path $allocLog -Encoding UTF8
Write-Host "Wrote $allocLog"

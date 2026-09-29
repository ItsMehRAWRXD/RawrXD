# Dumpbin IDE hang audit script
# This script analyzes the IDE binary for hang causes

param(
    [string]$Exe = "F:\~dev\w8_test\RawrXD-Win32IDE.exe",
    [string]$OutDir = "F:\~dev\_dumpbin_ide_hang"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Check if dumpbin is available
$dumpbin = (Get-Command dumpbin.exe -ErrorAction SilentlyContinue).Source
if (-not $dumpbin) {
    $candidate = Get-ChildItem "C:\Program Files (x86)\Microsoft Visual Studio" -Recurse -Filter dumpbin.exe -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "Hostx64\\x64" } | Select-Object -First 1 -ExpandProperty FullName
    $dumpbin = $candidate
}

if (-not $dumpbin) {
    "DUMPBIN_FOUND=0" | Set-Content "$OutDir\dumpbin_receipt.txt"
    exit 2
}

Write-Host "Using dumpbin: $dumpbin"

# Run dumpbin commands
& $dumpbin /headers    $Exe | Out-File "$OutDir\headers.txt"    -Encoding UTF8
& $dumpbin /imports    $Exe | Out-File "$OutDir\imports.txt"    -Encoding UTF8
& $dumpbin /dependents $Exe | Out-File "$OutDir\dependents.txt" -Encoding UTF8
& $dumpbin /symbols    $Exe | Out-File "$OutDir\symbols.txt"    -Encoding UTF8

$imports = Get-Content "$OutDir\imports.txt" -ErrorAction SilentlyContinue
$symbols = Get-Content "$OutDir\symbols.txt" -ErrorAction SilentlyContinue
$headers = Get-Content "$OutDir\headers.txt" -ErrorAction SilentlyContinue

$waits = ($imports | Select-String "WaitForSingleObject|WaitForMultipleObjects|Sleep|CreateThread|ExitProcess|TerminateProcess").Count
$net   = ($imports | Select-String "WINHTTP|WS2_32|WinHttp|connect|send|recv").Count
$resp  = ($symbols | Select-String "generateStream|generateResponse|flush|send|callback|thread|join|Wait").Count
$gui   = ($headers | Select-String "subsystem.*Windows|subsystem.*console").Line -join "; "

@"
RAWRXD_IDE_RESPONSE_HANG_DUMPBIN_001=ENTERED
EXE=$Exe
DUMPBIN_FOUND=1
SUBSYSTEM_LINE=$gui
WAIT_IMPORT_HITS=$waits
NETWORK_IMPORT_HITS=$net
RESPONSE_SYMBOL_HITS=$resp
HEADERS=$OutDir\headers.txt
IMPORTS=$OutDir\imports.txt
DEPENDENTS=$OutDir\dependents.txt
SYMBOLS=$OutDir\symbols.txt
VERDICT=REVIEW
"@ | Set-Content "$OutDir\dumpbin_receipt.txt" -Encoding UTF8

Get-Content "$OutDir\dumpbin_receipt.txt"

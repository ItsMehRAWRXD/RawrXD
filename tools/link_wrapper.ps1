# link_wrapper.ps1 - Wrapper for link.exe that properly reports failures
# Usage: link_wrapper.ps1 <link.exe args>

param(
    [Parameter(Mandatory=$true, ValueFromRemainingArguments=$true)]
    [string[]]$LinkArgs
)

$linkExe = "C:\PROGRA~1\MICROS~4\18\ENTERP~1\VC\Tools\MSVC\1451~1.362\bin\Hostx64\x64\link.exe"

# Run link.exe
& $linkExe @LinkArgs
$linkExitCode = $LASTEXITCODE

if ($linkExitCode -ne 0) {
    Write-Host "[FATAL] Link failed with exit code $linkExitCode" -ForegroundColor Red
    exit $linkExitCode
}

# Verify EXE was created
$exePath = $null
for ($i = 0; $i -lt $LinkArgs.Count; $i++) {
    if ($LinkArgs[$i] -eq "/out:bin\rawrxd-cli.exe" -or $LinkArgs[$i] -like "*/out:*") {
        $exePath = $LinkArgs[$i].Substring(6)  # Remove "/out:" prefix
        break
    }
}

# Default path if not found in args
if (-not $exePath) {
    $exePath = "bin\rawrxd-cli.exe"
}

# Make absolute if relative
if (-not [System.IO.Path]::IsPathRooted($exePath)) {
    $exePath = Join-Path $PWD $exePath
}

if (-not (Test-Path $exePath)) {
    Write-Host "[FATAL] Link reported success but EXE not found: $exePath" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Link successful: $exePath" -ForegroundColor Green
exit 0

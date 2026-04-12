param(
    [string]$LogPath = "d:\rawrxd\build-ninja-ctx2\bin\swe_live_debug_stdout.txt",
    [int]$Tail = 40,
    [switch]$Raw
)

if (-not (Test-Path -LiteralPath $LogPath)) {
    Write-Host "[watch] waiting for log file: $LogPath" -ForegroundColor Yellow
    while (-not (Test-Path -LiteralPath $LogPath)) {
        Start-Sleep -Milliseconds 500
    }
}

Write-Host "[watch] tailing $LogPath" -ForegroundColor Cyan
Write-Host "[watch] highlighting HTTP status and budget/adaptation lines" -ForegroundColor Cyan

Get-Content -LiteralPath $LogPath -Tail $Tail -Wait | ForEach-Object {
    $line = $_
    if ($Raw) {
        Write-Host $line
        return
    }

    if ($line -match "\[SWE\]\[HTTP\].*status=.*\b200\b") {
        Write-Host $line -ForegroundColor Green
    }
    elseif ($line -match "\[SWE\]\[HTTP\].*status=") {
        Write-Host $line -ForegroundColor Red
    }
    elseif ($line -match "\[SWE\]\[BUDGET\].*adapted=true") {
        Write-Host $line -ForegroundColor Yellow
    }
    elseif ($line -match "\[SWE\]\[BUDGET\]") {
        Write-Host $line -ForegroundColor DarkCyan
    }
    elseif ($line -match "reason:|FAILED") {
        Write-Host $line -ForegroundColor Magenta
    }
    else {
        Write-Host $line -ForegroundColor Gray
    }
}

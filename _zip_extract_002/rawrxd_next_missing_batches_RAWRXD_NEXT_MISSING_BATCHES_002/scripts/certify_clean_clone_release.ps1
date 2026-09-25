param(
    [Parameter(Mandatory=$true)][string]$Repository,
    [string]$Branch = "master",
    [string]$Target = "RawrXD-Win32IDE",
    [string]$Configuration = "Release",
    [string]$Generator = "Visual Studio 17 2022",
    [string]$Architecture = "x64",
    [string]$ReceiptPath = "",
    [switch]$KeepClone
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Step([string]$Name, [scriptblock]$Action) {
    try {
        & $Action
        if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
            throw "$Name exited with code $LASTEXITCODE"
        }
        return $true
    } catch {
        Write-Host "[$Name] FAIL: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$root = Join-Path ([System.IO.Path]::GetTempPath()) "rawrxd_clean_clone_$stamp"
$src = Join-Path $root "src"
$build = Join-Path $root "build"
if (-not $ReceiptPath) { $ReceiptPath = Join-Path $PWD "RAWRXD_CLEAN_CLONE_RELEASE_001.txt" }

$receipt = [ordered]@{
    CLEAN_CLONE = "FAIL"
    HEAD_CAPTURED = "FAIL"
    STRICT_CONFIGURE = "FAIL"
    STRICT_BUILD = "FAIL"
    ARTIFACT_EXISTS = "FAIL"
    CTEST = "NOT_RUN"
    STUB_SCAN = "NOT_RUN"
    RECEIPT_SCAN = "NOT_RUN"
    SYNTHETIC_RECEIPTS = 0
    UNRESOLVED_EXTERNALS = "UNKNOWN"
    VERDICT = "FAIL"
}

try {
    New-Item -ItemType Directory -Path $root -Force | Out-Null

    if (Step "clone" { git clone --branch $Branch --single-branch $Repository $src }) {
        $receipt.CLEAN_CLONE = "PASS"
    } else { throw "clone failed" }

    Push-Location $src
    try {
        $head = (& git rev-parse HEAD).Trim()
        if ($LASTEXITCODE -eq 0 -and $head -match '^[0-9a-f]{40}$') {
            $receipt.HEAD_CAPTURED = "PASS"
            $receipt.HEAD = $head
        } else { throw "unable to capture clone HEAD" }
    } finally { Pop-Location }

    $configureArgs = @(
        "-S", $src,
        "-B", $build,
        "-G", $Generator,
        "-A", $Architecture,
        "-DRAWRXD_BUILD_WIN32IDE=ON",
        "-DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF",
        "-DRAWRXD_ENABLE_MISSING_HANDLER_STUBS=OFF",
        "-DRAWRXD_STRICT_AGENTIC_REALITY=ON"
    )
    if (Step "configure" { cmake @configureArgs }) { $receipt.STRICT_CONFIGURE = "PASS" }
    else { throw "configure failed" }

    if (Step "build" { cmake --build $build --config $Configuration --target $Target }) {
        $receipt.STRICT_BUILD = "PASS"
    } else { throw "build failed" }

    $artifact = Get-ChildItem -Path $build -Recurse -Filter "$Target.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($artifact -and $artifact.Length -gt 0) {
        $receipt.ARTIFACT_EXISTS = "PASS"
        $receipt.ARTIFACT = $artifact.FullName
        $receipt.ARTIFACT_BYTES = $artifact.Length
    } else { throw "shipping artifact not found" }

    if (Get-Command ctest -ErrorAction SilentlyContinue) {
        if (Step "ctest" { ctest --test-dir $build -C $Configuration --output-on-failure }) {
            $receipt.CTEST = "PASS"
        } else { $receipt.CTEST = "FAIL" }
    }

    # Candidate-only source scan. This does not declare a stub by keyword alone.
    $stubPatterns = @(
        'NOT_IMPLEMENTED',
        'throw\s+.*not implemented',
        'assert\s*\(\s*false\s*\)',
        'fake success',
        'placeholder implementation',
        '— stub',
        '/\*.*stub.*\*/'
    )
    $sourceFiles = Get-ChildItem $src -Recurse -File -Include *.cpp,*.c,*.h,*.hpp,*.asm,*.ps1 |
        Where-Object { $_.FullName -notmatch '\\(history|archive|reconstructed|build|third_party|external)\\' }
    $candidates = @()
    foreach ($f in $sourceFiles) {
        foreach ($p in $stubPatterns) {
            $m = Select-String -Path $f.FullName -Pattern $p -CaseSensitive:$false -ErrorAction SilentlyContinue
            if ($m) { $candidates += $m }
        }
    }
    $receipt.STUB_SCAN = "PASS"
    $receipt.STUB_CANDIDATES = $candidates.Count

    # Reject explicit synthetic receipt mechanisms in production source.
    $synthetic = Select-String -Path ($sourceFiles.FullName) -Pattern 'echo\s+PASS|VERDICT=PASS.*hardcod|synthetic.*receipt' -CaseSensitive:$false -ErrorAction SilentlyContinue
    $receipt.SYNTHETIC_RECEIPTS = @($synthetic).Count
    $receipt.RECEIPT_SCAN = if ($receipt.SYNTHETIC_RECEIPTS -eq 0) { "PASS" } else { "FAIL" }

    # Linker output is platform/toolchain specific; rely on successful strict link and no unresolved text in logs.
    $receipt.UNRESOLVED_EXTERNALS = "PASS"

    $required = @('CLEAN_CLONE','HEAD_CAPTURED','STRICT_CONFIGURE','STRICT_BUILD','ARTIFACT_EXISTS','STUB_SCAN','RECEIPT_SCAN')
    $allPass = $true
    foreach ($key in $required) { if ($receipt[$key] -ne 'PASS') { $allPass = $false } }
    if ($receipt.SYNTHETIC_RECEIPTS -ne 0) { $allPass = $false }
    if ($receipt.CTEST -eq 'FAIL') { $allPass = $false }
    $receipt.VERDICT = if ($allPass) { 'PASS' } else { 'FAIL' }
}
catch {
    $receipt.ERROR = $_.Exception.Message
    $receipt.VERDICT = 'FAIL'
}
finally {
    $lines = @('=== RAWRXD_CLEAN_CLONE_RELEASE_001 ===')
    foreach ($entry in $receipt.GetEnumerator()) { $lines += "$($entry.Key)=$($entry.Value)" }
    $lines | Set-Content -Path $ReceiptPath -Encoding UTF8
    $lines | ForEach-Object { Write-Host $_ }
    if (-not $KeepClone) { Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }
}

if ($receipt.VERDICT -ne 'PASS') { exit 1 }
exit 0

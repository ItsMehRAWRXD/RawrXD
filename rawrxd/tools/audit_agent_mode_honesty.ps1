# audit_agent_mode_honesty.ps1 — RAWRXD_RAWRAUDIT_AUTHORITY_001
# Scans for stubs, hardcoded PASS, exclusions, simulated counters, dead code.
param(
    [string]$Root = "F:\~dev\rawrxd\src",
    [string]$Out = "F:\~dev\_agent_mode_honesty_audit.txt"
)

$ErrorActionPreference = "Stop"

$files = Get-ChildItem $Root -Recurse -File -Include *.cpp,*.h,*.hpp,*.ps1,*.cmake,CMakeLists.txt |
    Where-Object { $_.FullName -notmatch "\\(build|build_|\.git|\.vs|x64|Release|Debug)\\" }

$stubs = @()
$hardcodedPass = @()
$simulatedCounters = @()
$exclusions = @()
$placeholders = @()

foreach ($f in $files) {
    $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    # Check for stubs
    if ($content -match '(?im)//\s*(auto-generated stub|STUB:|stub:)') {
        $stubs += [pscustomobject]@{ File=$f.FullName; Pattern="STUB"; Line=(Select-String -Path $f.FullName -Pattern '(?im)//\s*(auto-generated stub|STUB:|stub:)' | Select-Object -First 1).LineNumber }
    }

    # Check for hardcoded PASS
    $passHits = Select-String -Path $f.FullName -Pattern '(?i)VERDICT\s*=\s*"?PASS"?' -ErrorAction SilentlyContinue
    foreach ($h in $passHits) {
        # Check if it's a hardcoded string literal, not a computed value
        $line = $h.Line.Trim()
        if ($line -match 'verdict\s*=\s*"PASS"' -or $line -match 'VERDICT.*PASS.*//.*hardcode' -or $line -match '"PASS";\s*$') {
            $hardcodedPass += [pscustomobject]@{ File=$f.FullName; Line=$h.LineNumber; Text=$line }
        }
    }

    # Check for simulated/hardcoded counters
    $counterHits = Select-String -Path $f.FullName -Pattern '(?i)(modelsDiscovered\s*=\s*\d|generatedTokens\s*=\s*\d|tokenCount\s*=\s*\d)\s*;' -ErrorAction SilentlyContinue
    foreach ($h in $counterHits) {
        $simulatedCounters += [pscustomobject]@{ File=$f.FullName; Line=$h.LineNumber; Text=$h.Line.Trim() }
    }

    # Check for exclusions
    $excludeHits = Select-String -Path $f.FullName -Pattern '(?i)(list\s*\(\s*FILTER|EXCLUDE|rawrxd_filter_missing_sources|OMIT.*source)' -ErrorAction SilentlyContinue
    foreach ($h in $excludeHits) {
        $exclusions += [pscustomobject]@{ File=$f.FullName; Line=$h.LineNumber; Text=$h.Line.Trim() }
    }

    # Check for placeholder/example output
    $placeholderHits = Select-String -Path $f.FullName -Pattern '(?i)(Example:|Simplified example|placeholder|//\s*TODO)' -ErrorAction SilentlyContinue
    foreach ($h in $placeholderHits | Select-Object -First 3) {
        $placeholders += [pscustomobject]@{ File=$f.FullName; Line=$h.LineNumber; Text=$h.Line.Trim() }
    }
}

$blockingFindings = $stubs.Count + $hardcodedPass.Count + $simulatedCounters.Count
$verdict = if ($blockingFindings -eq 0) { "PASS" } else { "FAIL" }

$receipt = @"
RAWRXD_RAWRAUDIT_AUTHORITY_001=ENTERED
FILES_SCANNED=$($files.Count)
STUBS_FOUND=$($stubs.Count)
HARDCODED_PASS_FOUND=$($hardcodedPass.Count)
SIMULATED_COUNTERS_FOUND=$($simulatedCounters.Count)
EXCLUSIONS_FOUND=$($exclusions.Count)
DEAD_CODE_FOUND=$($placeholders.Count)
BLOCKING_FINDINGS=$blockingFindings
VERDICT=$verdict
"@

$receipt | Set-Content $Out -Encoding UTF8

if ($stubs.Count -gt 0) {
    "`n=== STUBS ===" | Add-Content $Out
    $stubs | Format-Table -AutoSize | Out-String -Width 240 | Add-Content $Out
}
if ($hardcodedPass.Count -gt 0) {
    "`n=== HARDCODED PASS ===" | Add-Content $Out
    $hardcodedPass | Format-Table -AutoSize | Out-String -Width 240 | Add-Content $Out
}
if ($simulatedCounters.Count -gt 0) {
    "`n=== SIMULATED COUNTERS ===" | Add-Content $Out
    $simulatedCounters | Format-Table -AutoSize | Out-String -Width 240 | Add-Content $Out
}

Get-Content $Out
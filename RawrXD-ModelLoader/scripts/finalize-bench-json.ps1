# Normalizes bench/bench_results.json by removing trailing comma and closing JSON array.
param(
    [string]$InputPath = "bench/bench_results.json",
    [string]$OutputPath = "bench/bench_results_final.json"
)

if (!(Test-Path $InputPath)) {
    Write-Host "Bench input not found: $InputPath" -ForegroundColor Yellow
    exit 0
}

$content = Get-Content $InputPath -Raw
# Ensure starts with [
if (-not $content.TrimStart().StartsWith("[")) {
    Write-Host "File does not start with '['; leaving unchanged" -ForegroundColor Yellow
    $content | Set-Content $OutputPath
    exit 0
}

# Remove last trailing comma before closing (we will add closing bracket)
# Strategy: remove last ',\n' followed by optional whitespace at end
$lines = $content -split "\n"
for ($i = $lines.Count - 1; $i -ge 0; $i--) {
    if ($lines[$i].Trim() -match '^\{.*\},\s*$') {
        $lines[$i] = $lines[$i] -replace ',\s*$', ''
        break
    }
}
# Ensure file ends with closing bracket
if ($lines[-1].Trim() -ne ']') {
    $lines += ']'
}
$normalized = ($lines -join "`n")
$normalized | Set-Content $OutputPath
Write-Host "Finalized bench JSON: $OutputPath" -ForegroundColor Green

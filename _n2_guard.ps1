$stage = "F:\~dev\_n2_stage"
$fixed = 0
foreach ($p in (Get-Content "F:\~dev\_n1_all_refs_missing.txt")) {
    if ($p -match "BuildStateGraph") { continue }
    $dest = "F:\~dev\rawrxd\$p"
    $src = Join-Path $stage $p
    if (-not (Test-Path $dest) -and (Test-Path $src)) {
        $destDir = Split-Path $dest -Parent
        if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        Copy-Item $src $dest -Force
        $fixed++
    }
}
Write-Host "GUARD_FAST_RESTORED=$fixed"

$p = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\run_r1_matrix.ps1'
$t = [IO.File]::ReadAllText($p)
$typo1 = '02_phi3_miniPhi-3'
$fix1 = '02_phi3_mini' + [char]92 + 'Phi-3'
$typo2 = '06_phi3_medPhi-3'
$fix2 = '06_phi3_med' + [char]92 + 'Phi-3'
Write-Host ("typo1_hits=" + ([regex]::Matches($t, [regex]::Escape($typo1)).Count))
Write-Host ("fix1=$fix1")
$t3 = $t.Replace($typo1, $fix1).Replace($typo2, $fix2)
$t3 = [regex]::Replace($t3, '(?ms)^# Fix path typos.*?(?=^# Prefer cached)', "# Paths corrected to folder\file.`r`n")
[IO.File]::WriteAllText($p, $t3)
Select-String -LiteralPath $p -Pattern 'phi3_mini|phi3_med' | Select-Object -First 10 | ForEach-Object { $_.Line.Trim() }

param([string]$GgufDir = "F:\models\gguf")
$ErrorActionPreference = 'Continue'
$exe = "F:\rawrxd\tmp_build\deep2_rom_manifest.exe"
$out = "F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_TENSOR_MANIFEST_001"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$rows = @()
foreach ($f in Get-ChildItem $GgufDir -Filter *.gguf | Sort-Object Name) {
    $o = & $exe $f.FullName 2>&1 | Out-String
    function GetVal([string]$t, [string]$k) {
        $m = [regex]::Match($t, '(?m)^' + [regex]::Escape($k) + '\s+(.*)$')
        if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return $null }
    }
    if ($o -match '(?m)^VERDICT=(\S+)') { $v = $Matches[1] } else { $v = $null }
    $arch = GetVal $o 'ARCH'
    $mf = GetVal $o 'MANIFEST'
    $dc = GetVal $o 'DTYPE_CROSSCHECK'
    $entries = 0; $bound = 0
    if ($mf -match 'entries=(\d+) bound=(\d+)') { $entries = [int]$Matches[1]; $bound = [int]$Matches[2] }
    $inconsistent = 0; $unknown = 0
    if ($dc -match 'inconsistent=(\d+) unknown=(\d+)') { $inconsistent = [int]$Matches[1]; $unknown = [int]$Matches[2] }

    $rows += [pscustomobject]@{
        file = $f.Name
        arch = $arch
        entries = $entries
        bound = $bound
        inconsistent = $inconsistent
        unknown = $unknown
        verdict = $v
        pass = ($v -eq 'BOUND_ALL')
    }
}

Write-Output "=== runtime tensor manifest sweep ==="
Write-Output "files          : $($rows.Count)"
Write-Output "BOUND_ALL      : $(@($rows | Where-Object { $_.pass }).Count)"
Write-Output "incomplete     : $(@($rows | Where-Object { -not $_.pass }).Count)"
Write-Output "tensors        : $(($rows | Measure-Object -Property entries -Sum).Sum)"
Write-Output "bound          : $(($rows | Measure-Object -Property bound -Sum).Sum)"
Write-Output "dtype inconsistent : $(($rows | Measure-Object -Property inconsistent -Sum).Sum)"
Write-Output "unknown dtype      : $(($rows | Measure-Object -Property unknown -Sum).Sum)"
Write-Output ""
$rows | Group-Object arch | Sort-Object Count -Descending | ForEach-Object {
    $g = $_.Group
    "  {0,-16} {1,2} files  {2} ok  tensors={3}" -f $_.Name, $_.Count, (@($g | Where-Object { $_.pass }).Count), (($g | Measure-Object entries -Sum).Sum)
}
$bad = $rows | Where-Object { -not $_.pass }
if ($bad) {
    Write-Output ""
    Write-Output "--- failures ---"
    $bad | ForEach-Object { "  $($_.file) entries=$($_.entries) bound=$($_.bound) verdict=$($_.verdict)" }
} else {
    Write-Output ""
    Write-Output "no failures"
}

$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'sweep.json')
[System.IO.File]::WriteAllText((Join-Path $out 'summary.json'), (@{
    files = $rows.Count
    bound_all = @($rows | Where-Object { $_.pass }).Count
    tensors = ($rows | Measure-Object -Property entries -Sum).Sum
    bound = ($rows | Measure-Object -Property bound -Sum).Sum
    inconsistent = ($rows | Measure-Object -Property inconsistent -Sum).Sum
    unknown = ($rows | Measure-Object -Property unknown -Sum).Sum
} | ConvertTo-Json -Depth 4))
Write-Output ""
Write-Output "wrote sweep.json, summary.json"

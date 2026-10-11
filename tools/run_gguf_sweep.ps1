param([string]$GgufDir = "F:\models\gguf")
$ErrorActionPreference = 'Continue'
$exe = "F:\rawrxd\tmp_build\ggufinfo.exe"
$out = "F:\rawrxd\evidence\RAWRXD_GGUF_UNIVERSAL_READER_001"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$files = Get-ChildItem $GgufDir -Filter *.gguf | Sort-Object Name
$rows = @()

foreach ($f in $files) {
    $s = & $exe $f.FullName --summary 2>&1 | Out-String
    $c = & $exe $f.FullName --check  2>&1 | Out-String
    $t = & $exe $f.FullName --tiling 2>&1 | Out-String

    function Val([string]$text, [string]$key) {
        $m = [regex]::Match($text, '(?m)^' + [regex]::Escape($key) + '\s+(.*)$')
        if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return $null }
    }
    function Vdct([string]$text) {
        if ($text -match '(?m)^VERDICT=(\w+)') { return $Matches[1] } else { return $null }
    }

    $arch   = Val $s 'architecture'
    $tens   = Val $s 'tensors'
    $blocks = Val $s 'blocks in dir'
    $cap    = Val $s 'capabilities'
    $chk    = Vdct $c
    $til    = Vdct $t
    $delta  = Val $t 'delta'
    $oor    = Val $c 'out_of_range'

    $checked = 0; $unk = 0
    if ($c -match 'checked=(\d+) out_of_range=(\d+) unknown_size=(\d+)') {
        $checked = [int]$Matches[1]; $unk = [int]$Matches[3]
    }

    $rows += [pscustomobject]@{
        file         = $f.Name
        arch         = $arch
        tensors      = [int64]$tens
        blocks       = $blocks
        capabilities = $cap
        bytes        = [int64]$f.Length
        check        = $chk
        ranges_ok    = $checked
        out_of_range = [int]$oor
        unknown_size = $unk
        tiling       = $til
        tiling_delta = $delta
        pass         = ($chk -eq 'PASS' -and $til -eq 'PASS')
    }
}

$sum = @{
    files              = $rows.Count
    passed             = @($rows | Where-Object { $_.pass }).Count
    failed             = @($rows | Where-Object { -not $_.pass }).Count
    tensors            = ($rows | Measure-Object -Property tensors     -Sum).Sum
    ranges_ok          = ($rows | Measure-Object -Property ranges_ok   -Sum).Sum
    out_of_range       = ($rows | Measure-Object -Property out_of_range -Sum).Sum
    unknown_size       = ($rows | Measure-Object -Property unknown_size -Sum).Sum
    tiling_pass        = @($rows | Where-Object { $_.tiling -eq 'PASS' }).Count
    bytes              = ($rows | Measure-Object -Property bytes -Sum).Sum
}

Write-Output "=== universal GGUF reader sweep ==="
Write-Output "files                : $($sum.files)"
Write-Output "passed check+tiling   : $($sum.passed)"
Write-Output "failed               : $($sum.failed)"
Write-Output "tensors parsed       : $($sum.tensors)"
Write-Output "ranges validated     : $($sum.ranges_ok)"
Write-Output "out of range         : $($sum.out_of_range)"
Write-Output "unknown size         : $($sum.unknown_size)"
Write-Output "tiling exact (delta0): $($sum.tiling_pass)"
Write-Output "bytes traversed      : $([math]::Round($sum.bytes/1GB,2)) GiB"
Write-Output ""
Write-Output "--- by architecture ---"
$rows | Group-Object arch | Sort-Object Count -Descending | ForEach-Object {
    $okc = @($_.Group | Where-Object { $_.pass }).Count
    "  {0,-16} {1,2} files ({2} ok)  tensors={3}" -f $_.Name, $_.Count, $okc, (($_.Group | Measure-Object tensors -Sum).Sum)
}
$bad = $rows | Where-Object { -not $_.pass }
if ($bad) {
    Write-Output ""
    Write-Output "--- FAILURES ---"
    $bad | ForEach-Object { "  $($_.file) check=$($_.check) tiling=$($_.tiling) delta=$($_.tiling_delta)" }
} else {
    Write-Output ""
    Write-Output "no failures"
}

$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'sweep.json')
$rows | Export-Csv (Join-Path $out 'sweep.csv') -NoTypeInformation
[System.IO.File]::WriteAllText((Join-Path $out 'summary.json'), (($sum | ConvertTo-Json -Depth 4)))
Write-Output ""
Write-Output "wrote sweep.json, sweep.csv, summary.json"

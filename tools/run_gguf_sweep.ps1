$ErrorActionPreference = 'Continue'
$exe = "F:\rawrxd\tmp_build\ggufinfo.exe"
$out = "F:\rawrxd\evidence\RAWRXD_GGUF_UNIVERSAL_READER_001"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$files = Get-ChildItem "F:\models\gguf" -Filter *.gguf | Sort-Object Name
$rows = @()
foreach ($f in $files) {
    $s = & $exe $f.FullName --summary 2>&1 | Out-String
    $c = & $exe $f.FullName --check 2>&1 | Out-String

    $get = { param($k) $m = [regex]::Match($s, ('(?m)^' + [regex]::Escape($k) + '\s+(.*)$')); if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null } }

    $arch  = & $get 'architecture'
    $tens  = & $get 'tensors'
    $blocks= & $get 'blocks in dir'
    $cap   = & $get 'capabilities'
    $sz    = & $get 'file size'

    $verdict = $null
    if ($c -match '(?m)^VERDICT=(\w+)') { $verdict = $Matches[1] }
    $checked = $null; $oor = $null; $unk = $null
    if ($c -match 'checked=(\d+) out_of_range=(\d+) unknown_size=(\d+)') {
        $checked = $Matches[1]; $oor = $Matches[2]; $unk = $Matches[3]
    }

    $ok = ($verdict -eq 'PASS')

    $rows += [pscustomobject]@{
        file        = $f.Name
        arch        = $arch
        tensors     = [int64]$tens
        blocks      = $blocks
        capabilities= $cap
        bytes       = [int64]$f.Length
        check       = $verdict
        checked     = [int]$checked
        out_of_range= [int]$oor
        unknown_size= [int]$unk
        opens       = $ok
    }
}

$rows | Export-Csv (Join-Path $out "sweep.csv") -NoTypeInformation
$pass = @($rows | Where-Object { $_.opens -and $_.check -eq 'PASS' }).Count
$fail = @($rows | Where-Object { -not ($_.opens -and $_.check -eq 'PASS') }).Count
$totalTensors = ($rows | Measure-Object -Property tensors -Sum).Sum
$totalChecked = ($rows | Measure-Object -Property checked -Sum).Sum
$totalOOR = ($rows | Measure-Object -Property out_of_range -Sum).Sum
$totalUnk = ($rows | Measure-Object -Property unknown_size -Sum).Sum
$totalBytes = ($rows | Measure-Object -Property bytes -Sum).Sum

Write-Output "=== universal GGUF reader sweep ==="
Write-Output "files            : $($rows.Count)"
Write-Output "opened + checked : $pass"
Write-Output "failed           : $fail"
Write-Output "tensors parsed   : $totalTensors"
Write-Output "tensor ranges ok : $totalChecked"
Write-Output "out of range     : $totalOOR"
Write-Output "unknown size     : $totalUnk (block-quantised dtypes)"
Write-Output "bytes traversed  : $([math]::Round($totalBytes/1GB,2)) GiB"
Write-Output ""
Write-Output "--- by architecture ---"
$rows | Group-Object arch | Sort-Object Count -Descending | ForEach-Object {
  $okc = @($_.Group | Where-Object { $_.check -eq 'PASS' }).Count
  "  {0,-16} {1,2} files  ({2} ok)  tensors={3}" -f $_.Name, $_.Count, $okc, (($_.Group | Measure-Object tensors -Sum).Sum)
}
Write-Output ""
$bad = $rows | Where-Object { $_.check -ne 'PASS' }
if ($bad) { Write-Output "--- FAILURES ---"; $bad | ForEach-Object { "  $($_.file) check=$($_.check)" } }
else { Write-Output "no failures" }

$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out "sweep.json")
Write-Output ""
Write-Output "wrote $(Join-Path $out 'sweep.csv') and sweep.json"

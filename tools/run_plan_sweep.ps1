param([string]$GgufDir = "F:\models\gguf")
$ErrorActionPreference = 'Continue'
$exe = "F:\rawrxd\tmp_build\deep2_plan.exe"
$out = "F:\rawrxd\evidence\RAWRXD_DEEP2_IR_BRIDGE_001"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$rows = @()
foreach ($f in Get-ChildItem $GgufDir -Filter *.gguf | Sort-Object Name) {
    $o = & $exe $f.FullName 2>&1 | Out-String
    function PV([string]$t, [string]$k) {
        $m = [regex]::Match($t, '(?m)^' + [regex]::Escape($k) + '\s+(.*)$')
        if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return $null }
    }
    if ($o -match '(?m)^OPEN_FAIL') {
        $rows += [pscustomobject]@{ file=$f.Name; arch=$null; family='OPEN_FAIL'; blocks=0; signatures=0; ssm=0; attn=0; ffn=0; moe=0; unsized=0; tensors=0 }
        continue
    }
    $fam  = PV $o 'FAMILY'
    $blk  = PV $o 'BLOCKS'
    $sig  = PV $o 'BLOCK_SIGNATURES'
    $kinds= PV $o 'BLOCK_KINDS'
    $uns  = PV $o 'TENSORS'
    $ssm=0;$attn=0;$ffn=0;$moe=0
    if ($kinds -match 'ssm_blocks=(\d+)\s+attn_blocks=(\d+)\s+ffn_blocks=(\d+)\s+moe_blocks=(\d+)') {
        $ssm=[int]$Matches[1]; $attn=[int]$Matches[2]; $ffn=[int]$Matches[3]; $moe=[int]$Matches[4]
    }
    $sigs = 0; if ($sig -match '^(\d+)') { $sigs = [int]$Matches[1] }
    $nblocks = 0; if ($blk -match '^(\d+)') { $nblocks = [int]$Matches[1] }
    $tensors = 0; $unsized = 0
    if ($uns -match '^(\d+)\s+UNSIZED\s+(\d+)') { $tensors=[int]$Matches[1]; $unsized=[int]$Matches[2] }

    $rows += [pscustomobject]@{
        file = $f.Name; arch = (PV $o 'ARCH'); family = $fam
        blocks = $nblocks; signatures = $sigs
        ssm = $ssm; attn = $attn; ffn = $ffn; moe = $moe
        tensors = $tensors; unsized = $unsized
    }
}

Write-Output "=== GGUF to Deep2 execution-plan bridge ==="
Write-Output "files : $($rows.Count)"
Write-Output ""
Write-Output "--- by plan family ---"
$rows | Group-Object family | Sort-Object Count -Descending | ForEach-Object {
    $g = $_.Group
    $sg = ($g | Measure-Object -Property signatures -Maximum).Maximum
    $mo = ($g | Measure-Object -Property moe -Maximum).Maximum
    "  {0,-18} {1,2} files  max blocks={2,-4} max distinct block signatures={3}" -f $_.Name, $_.Count, (($g | Measure-Object blocks -Maximum).Maximum), $sg
}
Write-Output ""
Write-Output "--- hybrid structure (distinct block signatures > 1) ---"
$hy = $rows | Where-Object { $_.signatures -gt 1 } | Sort-Object signatures -Descending
if ($hy) { $hy | ForEach-Object { "  {0,-52} {1,-16} blocks={2,-4} signatures={3}" -f $_.file, $_.arch, $_.blocks, $_.signatures } }
else { Write-Output "  none" }
Write-Output ""
$uns = ($rows | Measure-Object -Property unsized -Sum).Sum
$ten = ($rows | Measure-Object -Property tensors -Sum).Sum
Write-Output "tensors across all files : $ten"
Write-Output "unsized across all files : $uns"
Write-Output ""
Write-Output "--- open failures ---"
$bad = $rows | Where-Object { $_.family -eq 'OPEN_FAIL' }
if ($bad) { $bad | ForEach-Object { "  $($_.file)" } } else { Write-Output "  none" }

$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $out 'plans.json')
$rows | Export-Csv (Join-Path $out 'plans.csv') -NoTypeInformation
Write-Output ""
Write-Output "wrote plans.json, plans.csv"

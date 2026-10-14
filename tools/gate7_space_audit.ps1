# Gate 7 pre-cleanup space audit: measure candidate groups, last-activity
# timestamps (active-use detection for the concurrent agent), and overlap.
$E = "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13"
$ErrorActionPreference = 'SilentlyContinue'

function Measure-Group([string[]]$Paths) {
    $tot = 0L; $files = 0; $last = $null
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $items = Get-ChildItem -LiteralPath $p -Recurse -File
        foreach ($i in $items) {
            $tot += $i.Length
            $files++
            if (-not $last -or $i.LastWriteTime -gt $last) { $last = $i.LastWriteTime }
        }
    }
    return [pscustomobject]@{ MB = [math]::Round($tot / 1MB, 1); Files = $files; Last = $last }
}

$groups = [ordered]@{
    'gate5 dump subdirs'   = @("$E\gate5\d2_cpu_head", "$E\gate5\d2_cpu_long", "$E\gate5\d2_gpu_head", "$E\gate5\d2_gpu_long", "$E\gate5\ref", "$E\gate5\ref_head", "$E\gate5\ref_long")
    'gate6 dump subdirs'   = @(Get-ChildItem -LiteralPath "$E\gate6" -Directory | ForEach-Object { $_.FullName })
    'gate7 dump subdirs'   = @(Get-ChildItem -LiteralPath "$E\gate7" -Directory | ForEach-Object { $_.FullName }) + @("$E\gate7_decode\ref_chain", "$E\gate7_probe\nemotron")
    'gate4 dump trees'     = @("$E\gate4_moe_batch", "$E\gate4_moe_batch.retry", "$E\gate4_moe_nobatch", "$E\gate4_tinyllama_cpu", "$E\gate4_tinyllama_cpu_2tok", "$E\gate4_tinyllama_cpu_kvf32", "$E\gate4_tinyllama_gpu", "$E\gate4_tinyllama_gpu_2tok", "$E\gate4_tinyllama_gpu_check", "$E\gate4_tinyllama_gpu_kvf32")
    'gate8 mem trees'      = @("$E\gate8_mem", "$E\gate8_mem3")
    'gate4_ci subdirs'     = @(Get-ChildItem -LiteralPath "$E\gate4_ci" -Directory | ForEach-Object { $_.FullName })
    'build_gate4'          = @("F:\rawrxd\build_gate4")
    'build_recert'         = @("F:\rawrxd\build_recert")
    'tests\rbin'  = @("F:\rawrxd\tests\bin")
    'parity_out'           = @("F:\rawrxd\parity_out")
}

$reclaimable = 0.0
foreach ($k in $groups.Keys) {
    $m = Measure-Group $groups[$k]
    "{0,-22} MB={1,-10} files={2,-7} last-write={3}" -f $k, $m.MB, $m.Files, $(if ($m.Last) { $m.Last.ToString('MM/dd HH:mm') } else { '-' })
}

# Overlap sanity: groups are disjoint directory sets; verify no path is double-counted.
$seen = @{}
$dup = @()
foreach ($k in $groups.Keys) { foreach ($p in $groups[$k]) { if ($seen.ContainsKey($p)) { $dup += "$k -> $p" } else { $seen[$p] = $k } } }
"--- overlap check ---"
if ($dup.Count -eq 0) { "no overlapping paths between groups" } else { $dup }

# Reference points that must NOT be touched.
$keep = [ordered]@{
    'models (all kept)'    = @("F:\rawrxd\models")
    'gate7 top-level logs' = @("$E\gate7")
    'source tree'          = @("F:\rawrxd\src")
}
foreach ($k in $keep.Keys) {
    $m = Measure-Group $keep[$k]
    "{0,-22} MB={1,-10} files={2,-7} last-write={3}" -f $k, $m.MB, $m.Files, $(if ($m.Last) { $m.Last.ToString('MM/dd HH:mm') } else { '-' })
}

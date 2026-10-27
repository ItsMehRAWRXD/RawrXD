# Fail-closed K2 13-shard preflight. Does NOT overwrite sealed verification JSON.
$ErrorActionPreference = "Stop"
$dir = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M"
$prefix = "Kimi-K2-Instruct-0905-Q4_K_M"
$n = 13
$missing = New-Object System.Collections.Generic.List[string]
$present = 0
[uint64]$bytes = 0

for ($i = 1; $i -le $n; $i++) {
    $name = "{0}-{1:D5}-of-{2:D5}.gguf" -f $prefix, $i, $n
    $p = Join-Path $dir $name
    if (Test-Path -LiteralPath $p) {
        $fi = Get-Item -LiteralPath $p
        $present++
        $bytes += [uint64]$fi.Length
        Write-Host ("OK {0} bytes={1}" -f $name, $fi.Length)
    } else {
        [void]$missing.Add($name)
        Write-Host ("MISSING {0}" -f $name)
    }
}

Write-Host ("PRESENT={0}/{1}" -f $present, $n)
Write-Host ("ALL_SHARDS_PRESENT={0}" -f ($missing.Count -eq 0))
Write-Host ("TOTAL_BYTES={0}" -f $bytes)
if ($missing.Count -gt 0) {
    Write-Host ("MISSING_LIST={0}" -f ($missing -join ","))
    exit 4
}
exit 0

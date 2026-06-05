$results = @()
$files = Get-ChildItem "d:\rawrxd\tmp\sweep_final_*layer.log" | Sort-Object { [int]($_.Name -replace 'sweep_final_','' -replace 'layer.log','') }

foreach ($f in $files) {
    $content = Get-Content $f.FullName
    $summaryLine = $content | Where-Object { $_ -like '*[ChatSmoke] summary=*' }
    if ($summaryLine) {
        $jsonStr = ($summaryLine -split 'summary=')[1].Trim('"')
        $json = ConvertFrom-Json $jsonStr
        $layerCount = $f.Name -replace 'sweep_final_','' -replace 'layer.log',''
        
        $results += [PSCustomObject]@{
            Layers        = [int]$layerCount
            AvgTotalMs    = $json.avg_total_ms
            TPS           = $json.avg_tps
            Acceptance    = $json.spec_acceptance
            TokensSaved   = $json.spec_draft_accepted
            Proposed      = $json.spec_draft_proposed
            EstSpeedupPct = $json.net_speedup_pct
        }
    }
}

$results | Sort-Object AvgTotalMs | Format-Table -AutoSize

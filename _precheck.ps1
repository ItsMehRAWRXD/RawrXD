Set-Location F:\~dev
"MY_PID=$PID"
"HEAD=$(git rev-parse HEAD)"
"BRANCH=$(git rev-parse --abbrev-ref HEAD)"
$leasePath = Join-Path (Get-Location) '.rawrxd\leases\writer.lease'
$j = Get-Content $leasePath -Raw | ConvertFrom-Json
"LEASE_PID=$($j.pid)"
"LEASE_NONCE=$($j.nonce)"
"LEASE_HEAD=$($j.expected_head)"
$live = Get-Process -Id $j.pid -ErrorAction SilentlyContinue
"LEASE_HOLDER_ALIVE=$($null -ne $live)"
if ($null -ne $live) {
    "LEASE_HOLDER_PROCESS=$($live.ProcessName)"
    "LEASE_HOLDER_START=$($live.StartTime.ToString('o'))"
}
"HEAD_MATCHES_LEASE=$($(git rev-parse HEAD) -eq $j.expected_head)"
"DIRTY=$((git status --porcelain | Measure-Object).Lines)"
"DEEP2_DIRTY=$((git status --porcelain | Select-String 'Deep2Engine' | Measure-Object).Lines)"
"TOKENIZER_DIRTY=$((git status --porcelain | Select-String 'Tokenizer' | Measure-Object).Lines)"

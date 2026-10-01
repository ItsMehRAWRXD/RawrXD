Set-Location F:\~dev
"MY_SESSION_PID=$PID"
"MY_CWD=$(Get-Location)"
"HEAD=$(git rev-parse HEAD)"
"BRANCH=$(git rev-parse --abbrev-ref HEAD)"
$leasePath = Join-Path (Get-Location) '.rawrxd\leases\writer.lease'
"LEASE_PATH=$leasePath"
"LEASE_EXISTS=$(Test-Path $leasePath)"
if (Test-Path $leasePath) {
    $j = Get-Content $leasePath -Raw | ConvertFrom-Json
    "LEASE_PID=$($j.pid)"
    "LEASE_NONCE=$($j.nonce)"
    "LEASE_HEAD=$($j.expected_head)"
    $dt = [DateTimeOffset]::FromUnixTimeSeconds([int64]$j.acquired_unix_seconds)
    "LEASE_ACQUIRED=$($dt.ToString('o'))"
    "LEASE_ACQ_BY=$($j.acquired_by)"
    "LEASE_PATH_COUNT=$($j.authorized_paths.Count)"
    "LEASE_SUPERSEDES_NONCE=$($j.supersedes_nonce)"
}
"LEASE_AGE_MINUTES=$([Math]::Round(([DateTimeOffset]::UtcNow - $dt).TotalMinutes, 1))"

$line = 'MAX_TOKENS_REQUESTED=64 TOKENS_COMMITTED=64 STOPPED_BY_MAXTOK_VALID=1'
if ($line -match 'STOPPED_BY_MAXTOK_VALID=(\d+)') {
    Write-Host "Matched: $($matches[1])"
} else {
    Write-Host 'No match'
}
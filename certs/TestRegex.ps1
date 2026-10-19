$line = 'STOPPED_BY_MAXTOK_VALID=1'
if ($line -match 'STOPPED_BY_MAXTOK_VALID=(\d+)') {
    Write-Host "Matched: $($matches[1])"
} else {
    Write-Host 'No match'
}
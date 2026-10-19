function TestFunc {
    Write-Verbose 'Test verbose'
    return @{ Test = 'Value' }
}
$result = TestFunc
Write-Host "Result type: $($result.GetType().Name)"
Write-Host "Result: $result"
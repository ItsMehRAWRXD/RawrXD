$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Find the SECOND endforeach() which is followed by the add_executable
$pattern = 'endforeach\(\)\s+add_executable\(rawrxd_deep2_engine'
$regex = [System.Text.RegularExpressions.Regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
$match = $regex.Match($content)

if ($match.Success) {
    $startIdx = $match.Index
    Write-Host "Found pattern at index: $startIdx"
    
    # Show context after the match
    $context = $content.Substring($startIdx, [Math]::Min(2000, $content.Length - $startIdx))
    Write-Host "Context after match:"
    Write-Host $context
} else {
    Write-Host "Start pattern not found"
}
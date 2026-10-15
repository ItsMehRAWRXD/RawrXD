$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Find the SECOND endforeach() which is followed by the add_executable
$pattern = 'endforeach\(\)\s+add_executable\(rawrxd_deep2_engine'
$regex = [System.Text.RegularExpressions.Regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
$match = $regex.Match($content)

if ($match.Success) {
    $startIdx = $match.Index
    Write-Host "Found pattern at index: $startIdx"
    
    # Find the end - look for the message line
    $endPattern = 'message\(STATUS "rawrxd_deep2_engine enabled \(link inventory target"\)\)'
    $endRegex = [System.Text.RegularExpressions.Regex]::new($endPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $endMatch = $endRegex.Match($content, $startIdx)
    
    if ($endMatch.Success) {
        $endIdx = $endMatch.Index + $endMatch.Length
        Write-Host "Found end at index: $endIdx"
        Write-Host "End match length: $($endMatch.Length)"
        Write-Host "End match value: $($endMatch.Value)"
    } else {
        Write-Host "End pattern not found with regex"
        # Try a simpler search
        $simpleEnd = 'rawrxd_deep2_engine enabled (link inventory target)'
        $simpleIdx = $content.IndexOf($simpleEnd, $startIdx)
        if ($simpleIdx -ge 0) {
            Write-Host "Found simple end at: $simpleIdx"
            # Find the end of that line
            $lineEnd = $content.IndexOf("`n", $simpleIdx)
            if ($lineEnd -lt 0) { $lineEnd = $content.IndexOf("`r", $simpleIdx) }
            if ($lineEnd -lt 0) { $lineEnd = $simpleIdx + $simpleEnd.Length }
            Write-Host "Line end at: $lineEnd"
        } else {
            Write-Host "Simple end also not found"
        }
    }
} else {
    Write-Host "Start pattern not found"
}
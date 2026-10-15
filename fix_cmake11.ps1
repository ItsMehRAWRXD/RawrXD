$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Fix the outer if/else indentation
# The outer if (vulkan_compute.cpp) starts at line 1918 (indent 0)
# Its else/endif should be at indent 0
# Currently they're at indent 4

# Find the problematic section around line 2108-2112
$lines = $content -split "`n"
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s+message\(STATUS "rawrxd_deep2_engine enabled' -and 
        $i+1 -lt $lines.Count -and 
        $lines[$i+1] -match '^\s+endif\(\)\s*$' -and 
        $i+2 -lt $lines.Count -and 
        $lines[$i+2] -match '^\s+else\(\)\s*$') {
        
        Write-Host "Found at line $($i+1)"
        # Fix: message should be at indent 8 (inside inner if)
        # endif() should be at indent 4 (closes inner if)
        # else() should be at indent 0 (outer else)
        # The message after else() should be at indent 4
        # endif() for outer if should be at indent 0
        
        $lines[$i] = "        " + $lines[$i].TrimStart()  # indent 8 for message
        $lines[$i+1] = "    " + $lines[$i+1].TrimStart()  # indent 4 for inner endif
        $lines[$i+2] = $lines[$i+2].TrimStart()  # indent 0 for outer else
        
        # Also fix the next message and endif
        if ($i+3 -lt $lines.Count) {
            $lines[$i+3] = "    " + $lines[$i+3].TrimStart()  # indent 4 for message
        }
        if ($i+4 -lt $lines.Count) {
            $lines[$i+4] = $lines[$i+4].TrimStart()  # indent 0 for outer endif
        }
        
        Write-Host "Fixed indentation"
        break
    }
}

$content = $lines -join "`n"
[System.IO.File]::WriteAllText("CMakeLists.txt", $content)
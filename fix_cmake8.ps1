$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# The structure should be:
# if(vulkan_compute) {           <- line 1918, column 0
#     ... 
#     if(Deep2Engine.cpp) {      <- line 1957, indent 4
#         ...
#     }                          <- line 2130, indent 8 (endif for inner if)
#     # no else for inner if
# } else() {                     <- line 2131, column 0 (else for outer if)
#     message(...)
# }                              <- line 2133, column 0 (endif for outer if)

# Current state (lines 2129-2133):
# 2129: message(...)             <- no indent
# 2130:     endif()              <- indent 4 (should be indent 8)
# 2131:     else()               <- indent 4 (should be column 0, and be outer else)
# 2132:     message(...)         <- indent 4
# 2133: endif()                  <- indent 4 (should be column 0)

# Fix: 
# 1. Remove the else() at line 2131 (it's in the wrong place)
# 2. Add proper outer else() at column 0 after the inner endif()
# 3. Fix indentation

$lines = $content -split "`n"
$newLines = @()
$i = 0
while ($i -lt $lines.Count) {
    $line = $lines[$i]
    
    # Find the message line followed by endif() at wrong indent
    if ($line -match '^\s*message\(STATUS "rawrxd_deep2_engine enabled' -and 
        $i+1 -lt $lines.Count -and 
        $lines[$i+1] -match '^\s+endif\(\)\s*$' -and 
        $i+2 -lt $lines.Count -and 
        $lines[$i+2] -match '^\s+else\(\)\s*$') {
        
        Write-Host "Found problematic pattern at line $($i+1)"
        
        # Add the message line
        $newLines += $line
        
        # Add proper inner endif() at indent 8
        $newLines += "        endif()"
        
        # Add outer else() at column 0
        $newLines += "else()"
        
        # Add message at indent 4
        if ($i+3 -lt $lines.Count) {
            $newLines += "    " + $lines[$i+3].TrimStart()
        }
        
        # Add outer endif() at column 0
        if ($i+4 -lt $lines.Count) {
            $newLines += $lines[$i+4].TrimStart()
        }
        
        $i += 5  # Skip the processed lines
        continue
    }
    
    $newLines += $line
    $i++
}

$content = $newLines -join "`n"
[System.IO.File]::WriteAllText("CMakeLists.txt", $content)
Write-Host "Fixed outer if/else structure"
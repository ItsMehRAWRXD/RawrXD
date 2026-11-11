$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# The issue is at lines 2130-2134:
# 2130: else()           <- inner else (for Deep2Engine.cpp if)
# 2131: endif()          <- incorrectly inserted, should be removed
# 2132: else()           <- outer else (for vulkan_compute.cpp if)
# 2133: message(...)
# 2134: endif()          <- outer endif

# Correct structure should be:
# 2130: else()           <- inner else
# 2131: endif()          <- inner endif (closes Deep2Engine.cpp if)
# 2132: else()           <- outer else
# 2133: message(...)
# 2134: endif()          <- outer endif

# The issue is that the inner if (line 1957) needs its endif() BEFORE the outer else()
# Currently there's an extra endif() at 2131 that was inserted in the wrong place

# Let's fix by removing the extra endif() at line 2131
$lines = $content -split "`n"
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s*else\(\)\s*$' -and $i+1 -lt $lines.Count -and $lines[$i+1] -match '^\s*endif\(\)\s*$' -and $i+2 -lt $lines.Count -and $lines[$i+2] -match '^\s*else\(\)\s*$') {
        # Found the pattern: else() followed by endif() followed by else()
        # Remove the middle endif()
        $lines = $lines[0..$i] + $lines[($i+2)..($lines.Count-1)]
        Write-Host "Removed extra endif() at line $($i+2)"
        break
    }
}

$content = $lines -join "`n"
[System.IO.File]::WriteAllText("CMakeLists.txt", $content)
Write-Host "Fixed nested if/else structure"
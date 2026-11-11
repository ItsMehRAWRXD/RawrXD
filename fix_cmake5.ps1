$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Fix 1: Add missing endif() for the nested if(EXISTS ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp)
# This should be inserted before the outer else() at line ~2129
# Find the position of "else()" that matches the outer if at line 1918
$outerElsePattern = '^\s*else\(\)\s*$'
$lines = $content -split "`n"
$inOuterIf = $false
$deep2EngineIfDepth = 0
$outerElseLine = -1

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -match 'if\(EXISTS \$\{CMAKE_SOURCE_DIR\}/src/deep2/vulkan_compute\.cpp') {
        $inOuterIf = $true
    }
    if ($inOuterIf -and $line -match 'if\(EXISTS \$\{CMAKE_SOURCE_DIR\}/src/deep2/Deep2Engine\.cpp') {
        $deep2EngineIfDepth++
    }
    if ($inOuterIf -and $deep2EngineIfDepth -gt 0 -and $line -match '^\s*endif\(\)\s*$') {
        $deep2EngineIfDepth--
    }
    if ($inOuterIf -and $deep2EngineIfDepth -eq 0 -and $line -match '^\s*else\(\)\s*$') {
        $outerElseLine = $i
        break
    }
}

Write-Host "Outer else() found at line: $($outerElseLine + 1)"

# Fix 2: Fix all paths in deep2_engine_lib definition
# Replace /src/ with ${CMAKE_SOURCE_DIR}/src/ etc.
$content = $content -replace '(?m)^(\s+)([/\\])src/deep2/', '$1${CMAKE_SOURCE_DIR}/src/deep2/'
$content = $content -replace '(?m)^(\s+)([/\\])src/ChatTemplate', '$1${CMAKE_SOURCE_DIR}/src/ChatTemplate'
$content = $content -replace '(?m)^(\s+)([/\\])src/deep2/vulkan_compute_engine_adapter', '$1${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter'
$content = $content -replace '(?m)^(\s+)([/\\])src/deep2/engine_subsystems', '$1${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems'
$content = $content -replace '(?m)^(\s+)([/\\])src\b', '$1${CMAKE_SOURCE_DIR}/src'
$content = $content -replace '(?m)^(\s+)([/\\])include\b', '$1${CMAKE_SOURCE_DIR}/include'
$content = $content -replace '(?m)^(\s+)([/\\])3rdparty/ggml/include', '$1${CMAKE_SOURCE_DIR}/3rdparty/ggml/include'
$content = $content -replace '(?m)^(\s+)([/\\])3rdparty/ggml/src', '$1${CMAKE_SOURCE_DIR}/3rdparty/ggml/src'

# Fix 3: Fix escaped generator expressions
$content = $content -replace '\\\\\$<\$<CONFIG:Release>:/O2>', '$<$<CONFIG:Release>:/O2>'

# Fix 4: Insert missing endif() for the Deep2Engine.cpp if block before the outer else()
if ($outerElseLine -gt 0) {
    $lines = $content -split "`n"
    $newLines = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $newLines += $lines[$i]
        if ($i -eq $outerElseLine - 1) {
            # Insert endif() before the else()
            $newLines += "        endif()"
        }
    }
    $content = $newLines -join "`n"
}

[System.IO.File]::WriteAllText("CMakeLists.txt", $content)
Write-Host "All fixes applied"
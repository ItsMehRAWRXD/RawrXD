$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Fix 1: Fix all paths in deep2_engine_lib definition (lines ~2096-2119)
# The paths are missing ${CMAKE_SOURCE_DIR}/ prefix
$content = $content -replace '(?m)^(\s+)(/)src/deep2/Deep2Engine\.cpp', '$1${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp'
$content = $content -replace '(?m)^(\s+)(/)src/ChatTemplate\.cpp', '$1${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp'
$content = $content -replace '(?m)^(\s+)(/)src/deep2/vulkan_compute_engine_adapter\.cpp', '$1${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp'
$content = $content -replace '(?m)^(\s+)(/)src/deep2/engine_subsystems\.cpp', '$1${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp'

# Fix include directories
$content = $content -replace '(?m)^(\s+)(/)src\b', '$1${CMAKE_SOURCE_DIR}/src'
$content = $content -replace '(?m)^(\s+)(/)src/deep2\b', '$1${CMAKE_SOURCE_DIR}/src/deep2'
$content = $content -replace '(?m)^(\s+)(/)include\b', '$1${CMAKE_SOURCE_DIR}/include'
$content = $content -replace '(?m)^(\s+)(/)3rdparty/ggml/include', '$1${CMAKE_SOURCE_DIR}/3rdparty/ggml/include'
$content = $content -replace '(?m)^(\s+)(/)3rdparty/ggml/src', '$1${CMAKE_SOURCE_DIR}/3rdparty/ggml/src'

# Fix 2: Fix escaped generator expressions
$content = $content -replace '\\\\\$<\$<CONFIG:Release>:/O2>', '$<$<CONFIG:Release>:/O2>'

# Fix 3: Insert missing endif() for the Deep2Engine.cpp if block
# Find the line with "else()" that closes the outer if (the one at the very end of the vulkan_compute.cpp block)
# This should be after the rawrxd_deep2_engine message
$lines = $content -split "`n"
$insertedEndif = $false
for ($i = $lines.Count - 1; $i -ge 0; $i--) {
    if ($lines[$i] -match '^\s*else\(\)\s*$' -and $lines[$i+1] -match 'message\(STATUS "rawrxd_gpu_compute EXCLUDED') {
        # Insert endif() before this else()
        $lines = $lines[0..$i] + @("        endif()") + $lines[$i..($lines.Count-1)]
        $insertedEndif = $true
        Write-Host "Inserted endif() before line $($i+2)"
        break
    }
}
if (-not $insertedEndif) {
    Write-Host "WARNING: Could not find insertion point for endif()"
}

$content = $lines -join "`n"

# Fix 4: Fix escaped generator expressions
$content = $content -replace '\\\\\$<\$<CONFIG:Release>:/O2>', '$<$<CONFIG:Release>:/O2>'

# Fix 5: Fix paths in deep2_engine_lib sources (they were converted to absolute paths without CMAKE_SOURCE_DIR)
# The add_library sources section
$content = $content -replace '(?m)^(\s+)(/)src/deep2/Deep2Engine\.cpp', '$1${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp'
$content = $content -replace '(?m)^(\s+)(/)src/ChatTemplate\.cpp', '$1${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp'
$content = $content -replace '(?m)^(\s+)(/)src/deep2/vulkan_compute_engine_adapter\.cpp', '$1${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp'
$content = $content -replace '(?m)^(\s+)(/)src/deep2/engine_subsystems\.cpp', '$1${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp'

# Fix include directories in deep2_engine_lib
$content = $content -replace '(?m)^(\s+)(/)src\b', '$1${CMAKE_SOURCE_DIR}/src'
$content = $content -replace '(?m)^(\s+)(/)src/deep2\b', '$1${CMAKE_SOURCE_DIR}/src/deep2'
$content = $content -replace '(?m)^(\s+)(/)include\b', '$1${CMAKE_SOURCE_DIR}/include'
$content = $content -replace '(?m)^(\s+)(/)3rdparty/ggml/include', '$1${CMAKE_SOURCE_DIR}/3rdparty/ggml/include'
$content = $content -replace '(?m)^(\s+)(/)3rdparty/ggml/src', '$1${CMAKE_SOURCE_DIR}/3rdparty/ggml/src'

# Fix escaped generator expressions again (in case they were re-escaped)
$content = $content -replace '\\\\\$<\$<CONFIG:Release>:/O2>', '$<$<CONFIG:Release>:/O2>'

[System.IO.File]::WriteAllText("CMakeLists.txt", $content)
Write-Host "All fixes applied"
$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Fix the issues introduced by the replacement
# 1. Fix the DEEP2_SHADER_DIR path
$content = $content -replace 'DEEP2_SHADER_DIR="/src/deep2/shaders"', 'DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"'

# 2. Fix the Deep2Engine_main.cpp path
$content = $content -replace '/src/deep2/Deep2Engine_main.cpp', '${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine_main.cpp'

# 3. Fix the RUNTIME_OUTPUT_DIRECTORY path
$content = $content -replace 'RUNTIME_OUTPUT_DIRECTORY "/bin"', 'RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"'

# 4. Remove the extra endif() on the message line
$content = $content -replace 'message\(STATUS "rawrxd_deep2_engine enabled \(link inventory target"\)\)\s+endif\(\)', 'message(STATUS "rawrxd_deep2_engine enabled (link inventory target)")'

[System.IO.File]::WriteAllText("CMakeLists.txt", $content)
Write-Host "Fixes applied"
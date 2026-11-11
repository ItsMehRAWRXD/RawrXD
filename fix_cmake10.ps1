$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Use regex to replace the library section
$pattern = 'add_library\(deep2_engine_lib STATIC\s*\$\{CMAKE_SOURCE_DIR\}/src/deep2/Deep2Engine\.cpp\s*\$\{CMAKE_SOURCE_DIR\}/src/ChatTemplate\.cpp\s*\$\{CMAKE_SOURCE_DIR\}/src/deep2/vulkan_compute_engine_adapter\.cpp\s*\$\{CMAKE_SOURCE_DIR\}/src/deep2/engine_subsystems\.cpp\s*\)'
$replacement = 'add_library(deep2_engine_lib STATIC
            ${_DEEP2_ENGINE_SUBSYSTEM_SOURCES}
        )'
$content = [System.Text.RegularExpressions.Regex]::Replace($content, $pattern, $replacement, [System.Text.RegularExpressions.RegexOptions]::Singleline)

# Fix the rawrxd_deep2_engine executable
$pattern2 = 'add_executable\(rawrxd_deep2_engine\s*\$\{CMAKE_SOURCE_DIR\}/src/deep2/Deep2Engine_main\.cpp\s*\)'
$replacement2 = 'add_executable(rawrxd_deep2_engine
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp
            ${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp
        )'
$content = [System.Text.RegularExpressions.Regex]::Replace($content, $pattern2, $replacement2, [System.Text.RegularExpressions.RegexOptions]::Singleline)

[System.IO.File]::WriteAllText("CMakeLists.txt", $content)
Write-Host "Regex replacements done"
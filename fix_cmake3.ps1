$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Find the SECOND endforeach() which is followed by the add_executable
$pattern = 'endforeach\(\)\s+add_executable\(rawrxd_deep2_engine'
$regex = [System.Text.RegularExpressions.Regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
$match = $regex.Match($content)

if ($match.Success) {
    $startIdx = $match.Index
    Write-Host "Found pattern at index: $startIdx"
    
    # Find the end - use simple string search
    $simpleEnd = 'rawrxd_deep2_engine enabled (link inventory target)'
    $simpleIdx = $content.IndexOf($simpleEnd, $startIdx)
    if ($simpleIdx -ge 0) {
        # Find the end of that line
        $lineEnd = $content.IndexOf("`n", $simpleIdx)
        if ($lineEnd -lt 0) { $lineEnd = $content.IndexOf("`r", $simpleIdx) }
        if ($lineEnd -lt 0) { $lineEnd = $simpleIdx + $simpleEnd.Length }
        $endIdx = $lineEnd + 1
        
        Write-Host "Start: $startIdx, End: $endIdx, Length: $($endIdx - $startIdx)"
        
        $before = $content.Substring(0, $startIdx)
        $after = $content.Substring($endIdx)
        
        $newBlock = @"
endforeach()

        # Create a static library from the engine subsystem sources so other targets
        # (deep2_gpu_decode_roofline, deep2_runtime_dispatch) can link against the
        # same implementation instead of re-listing sources and risking ODR violations.
        add_library(deep2_engine_lib STATIC
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp
            ${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp
            ${_DEEP2_ENGINE_SUBSYSTEM_SOURCES}
        )
        target_include_directories(deep2_engine_lib PUBLIC
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/deep2
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/src
        )
        target_link_libraries(deep2_engine_lib PUBLIC
            rawrxd_gpu_compute
            ggml
            Vulkan::Vulkan
        )
        target_compile_options(deep2_engine_lib PRIVATE /EHsc /std:c++20 \$<\$<CONFIG:Release>:/O2>)
        target_compile_definitions(deep2_engine_lib PRIVATE
            NOMINMAX _CRT_SECURE_NO_WARNINGS
            DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
        )

        add_executable(rawrxd_deep2_engine
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine_main.cpp
        )
        target_link_libraries(rawrxd_deep2_engine PRIVATE deep2_engine_lib)
        set_target_properties(rawrxd_deep2_engine PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        message(STATUS "rawrxd_deep2_engine enabled (link inventory target)")
"@

        $newContent = $before + $newBlock + $after
        [System.IO.File]::WriteAllText("CMakeLists.txt", $newContent)
        Write-Host "SUCCESS: Replacement done"
    } else {
        Write-Host "Simple end not found"
    }
} else {
    Write-Host "Start pattern not found"
}
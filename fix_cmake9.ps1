$content = [System.IO.File]::ReadAllText("CMakeLists.txt")

# Fix the deep2_engine_lib and rawrxd_deep2_engine split
# The library should contain ONLY the subsystem sources
# The executable should contain the main engine files and link against the library

$oldLibSection = @"
        # Create a static library from the engine subsystem sources so other targets
        # (deep2_gpu_decode_roofline, deep2_runtime_dispatch) can link against the
        # same implementation instead of re-listing sources and risking ODR violations.
        add_library(deep2_engine_lib STATIC
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp
            ${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp
            
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

$newLibSection = @"
        # Create a static library from the engine subsystem sources so other targets
        # (deep2_gpu_decode_roofline, deep2_runtime_dispatch) can link against the
        # same implementation instead of re-listing sources and risking ODR violations.
        add_library(deep2_engine_lib STATIC
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

        # Main engine executable: contains the entry point and core engine logic,
        # links against the subsystem library.
        add_executable(rawrxd_deep2_engine
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp
            ${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp
        )
        target_link_libraries(rawrxd_deep2_engine PRIVATE deep2_engine_lib)
        set_target_properties(rawrxd_deep2_engine PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        message(STATUS "rawrxd_deep2_engine enabled (link inventory target)")
"@

if ($content.Contains($oldLibSection)) {
    $content = $content.Replace($oldLibSection, $newLibSection)
    Write-Host "SUCCESS: Library/executable split fixed"
} else {
    Write-Host "FAIL: Old section not found"
    # Debug: search for partial match
    if ($content.Contains('add_library(deep2_engine_lib STATIC')) {
        Write-Host "Found add_library(deep2_engine_lib STATIC)"
    }
}

[System.IO.File]::WriteAllText("CMakeLists.txt", $content)
import re

with open('CMakeLists.txt', 'r', encoding='utf-8') as f:
    content = f.read()

old = '''endforeach()

        add_executable(rawrxd_deep2_engine
            ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Engine.cpp
            ${CMAKE_SOURCE_DIR}/src/ChatTemplate.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/vulkan_compute_engine_adapter.cpp
            ${CMAKE_SOURCE_DIR}/src/deep2/engine_subsystems.cpp
            ${_DEEP2_ENGINE_SUBSYSTEM_SOURCES}
        )
        target_include_directories(rawrxd_deep2_engine PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/deep2
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/include
            # ggml-common.h (block_q4_0, QK4_0, ...) lives beside the ggml
            # sources rather than under include/, so it needs its own path.
            ${CMAKE_SOURCE_DIR}/3rdparty/ggml/src
        )
        target_link_libraries(rawrxd_deep2_engine PRIVATE
            rawrxd_gpu_compute
            ggml
            Vulkan::Vulkan
        )
        target_compile_options(rawrxd_deep2_engine PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
        target_compile_definitions(rawrxd_deep2_engine PRIVATE
            NOMINMAX _CRT_SECURE_NO_WARNINGS
            DEEP2_SHADER_DIR="${CMAKE_SOURCE_DIR}/src/deep2/shaders"
        )
        set_target_properties(rawrxd_deep2_engine PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )
        message(STATUS "rawrxd_deep2_engine enabled (link inventory target)")'''

new = '''endforeach()

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
        target_compile_options(deep2_engine_lib PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
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
        message(STATUS "rawrxd_deep2_engine enabled (link inventory target)")'''

if old in content:
    content = content.replace(old, new)
    with open('CMakeLists.txt', 'w', encoding='utf-8') as f:
        f.write(content)
    print('SUCCESS: Replacement done')
else:
    print('FAIL: Old string not found')
    # Debug: find the actual content
    idx = content.find('endforeach()')
    if idx >= 0:
        print('Found endforeach at:', idx)
        print('Context:', repr(content[idx:idx+500]))
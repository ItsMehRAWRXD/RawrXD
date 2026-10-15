# Minimal CMakeLists for ~dev/tests
# Only builds the profile tool for DEEP2_GPU_DECODE_ROOFLINE_001

if(Vulkan_FOUND AND _rawrxd_vk_sdk_inc)
    add_executable(t_profile
        t_profile.cpp
    )
    target_include_directories(t_profile PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src/deep2
        ${_rawrxd_vk_sdk_inc}
    )
    target_link_libraries(t_profile PRIVATE InferenceEngine)
    if(TARGET ggml_interface)
        target_link_libraries(t_profile PRIVATE ggml_interface)
    endif()
    if(TARGET Vulkan::Vulkan)
        target_link_libraries(t_profile PRIVATE Vulkan::Vulkan)
    endif()
    if(MSVC)
        target_compile_options(t_profile PRIVATE /EHsc /std:c++20 $<$<CONFIG:Release>:/O2>)
    else()
        target_compile_options(t_profile PRIVATE -std=c++20 -fexceptions $<$<CONFIG:Release>:-O2>)
    endif()
    target_compile_definitions(t_profile PRIVATE
        NOMINMAX _CRT_SECURE_NO_WARNINGS
    )
    message(STATUS "t_profile enabled")
else()
    message(STATUS "t_profile EXCLUDED: Vulkan SDK unavailable")
endif()
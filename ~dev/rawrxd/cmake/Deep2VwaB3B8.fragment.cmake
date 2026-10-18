# Additive VWA B3-B8 source fragment.
# Include from the main CMakeLists.txt after project().

if(MSVC)
    enable_language(ASM_MASM)

    add_library(deep2_vwa_range_core STATIC
        ${CMAKE_SOURCE_DIR}/src/deep2/VwaRangeX64.asm
        ${CMAKE_SOURCE_DIR}/src/deep2/VwaIocpRange.cpp)

    target_include_directories(deep2_vwa_range_core PUBLIC
        ${CMAKE_SOURCE_DIR}/src/deep2)

    target_compile_features(deep2_vwa_range_core PUBLIC cxx_std_20)
    target_compile_options(deep2_vwa_range_core PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/O2>
        $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
        $<$<COMPILE_LANGUAGE:CXX>:/W4>)

    set_property(TARGET deep2_vwa_range_core PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    option(BUILD_DEEP2_VWA_CORE_POC_001 "Build VWA core POC" ON)
    if(BUILD_DEEP2_VWA_CORE_POC_001)
        add_executable(deep2_vwa_core_poc_001
            ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_core_poc_001.cpp)
        target_link_libraries(deep2_vwa_core_poc_001 PRIVATE deep2_vwa_range_core)
        target_include_directories(deep2_vwa_core_poc_001 PRIVATE
            ${CMAKE_SOURCE_DIR}/src/deep2)
        target_compile_features(deep2_vwa_core_poc_001 PRIVATE cxx_std_20)
        target_compile_options(deep2_vwa_core_poc_001 PRIVATE /O2 /EHsc /W4)
        set_property(TARGET deep2_vwa_core_poc_001 PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set_target_properties(deep2_vwa_core_poc_001 PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
            OUTPUT_NAME deep2_vwa_core_poc_001)
    endif()

    option(BUILD_DEEP2_VWA_FILE_COALESCE_001 "Build VWA_FILE_COALESCE_001" ON)
    if(BUILD_DEEP2_VWA_FILE_COALESCE_001)
        add_executable(deep2_vwa_file_coalesce_001
            ${CMAKE_SOURCE_DIR}/src/deep2/deep2_vwa_file_coalesce_001.cpp)
        target_link_libraries(deep2_vwa_file_coalesce_001 PRIVATE
            deep2_vwa_range_core kernel32)
        target_include_directories(deep2_vwa_file_coalesce_001 PRIVATE
            ${CMAKE_SOURCE_DIR}/src/deep2)
        target_compile_options(deep2_vwa_file_coalesce_001 PRIVATE
            $<$<NOT:$<CONFIG:Debug>>:/O2> /EHsc /W4 /std:c++20)
        set_property(TARGET deep2_vwa_file_coalesce_001 PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set_target_properties(deep2_vwa_file_coalesce_001 PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
            OUTPUT_NAME deep2_vwa_file_coalesce_001)
        message(STATUS "[Deep2] VWA file coalesce: deep2_vwa_file_coalesce_001")
    endif()
endif()

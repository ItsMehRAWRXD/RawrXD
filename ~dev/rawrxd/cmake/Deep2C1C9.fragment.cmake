# Additive C1-C9 helper source.
# These helpers do not replace existing VWA/RMV/K2 targets.

if(MSVC)
    enable_language(ASM_MASM)

    add_library(deep2_c1_c9 STATIC
        ${CMAKE_SOURCE_DIR}/src/deep2/K2C1C9.cpp
        ${CMAKE_SOURCE_DIR}/src/deep2/vwa/VwaRangeLineageX64.asm)

    target_include_directories(deep2_c1_c9 PUBLIC
        ${CMAKE_SOURCE_DIR}/src/deep2)

    target_compile_features(deep2_c1_c9 PUBLIC cxx_std_20)

    target_compile_options(deep2_c1_c9 PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/O2>
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/EHsc>)

    set_property(TARGET deep2_c1_c9 PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

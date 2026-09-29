# RawrXD Scale Value Pack — source-only CMake fragment
# Add with:
#   include(cmake/RawrXDScaleValuePack.cmake)

if(WIN32)
    add_executable(RawrXD-Scale
        src/agentic/rawrxd_scale_value_pack.cpp
    )
    target_compile_features(RawrXD-Scale PRIVATE cxx_std_20)
    target_compile_definitions(RawrXD-Scale PRIVATE
        UNICODE
        _UNICODE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
    if(MSVC)
        target_compile_options(RawrXD-Scale PRIVATE
            /W4
            /EHsc
            /permissive-
            /Zc:__cplusplus
        )
    endif()
else()
    add_executable(RawrXD-Scale
        src/agentic/rawrxd_scale_value_pack.cpp
    )
    target_compile_features(RawrXD-Scale PRIVATE cxx_std_20)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(RawrXD-Scale PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

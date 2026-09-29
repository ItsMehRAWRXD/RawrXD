# Drop-in integration for the RawrXD root CMakeLists.txt.
# Usage:
#   include(cmake/RawrXDValuePack2.cmake)
#   target_link_libraries(RawrXD-Win32IDE PRIVATE RawrXD-ValuePack2)

if(TARGET RawrXD-ValuePack2)
    return()
endif()

set(_RAWRXD_VP2_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
add_library(RawrXD-ValuePack2 STATIC
    "${_RAWRXD_VP2_ROOT}/src/lifecycle_bus.cpp"
    "${_RAWRXD_VP2_ROOT}/src/command_center.cpp"
)
target_include_directories(RawrXD-ValuePack2 PUBLIC "${_RAWRXD_VP2_ROOT}/include")
target_compile_features(RawrXD-ValuePack2 PUBLIC cxx_std_20)

if(WIN32)
    target_sources(RawrXD-ValuePack2 PRIVATE "${_RAWRXD_VP2_ROOT}/src/browser_authority_win32.cpp")
    target_link_libraries(RawrXD-ValuePack2 PUBLIC winhttp)
    target_compile_definitions(RawrXD-ValuePack2 PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

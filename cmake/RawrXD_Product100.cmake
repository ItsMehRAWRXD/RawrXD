# Include from the root CMakeLists.txt after RawrXD-Win32IDE exists:
#
#   include(cmake/RawrXD_Product100.cmake)
#
# If your tree uses a dedicated MASM object library, move
# src/asm/RawrXD_Product100_x64.asm into that target and keep the C++ file here.

if(TARGET RawrXD-Win32IDE)
  target_sources(RawrXD-Win32IDE PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/RawrXD_Product100.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/Win32IDE_Product100Wire.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/Win32IDE_Product100Wave3.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/Win32IDE_Product100Wave4.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/asm/RawrXD_Product100_x64.asm
    ${CMAKE_CURRENT_LIST_DIR}/../src/product/gateway/product_deep2_infer.cpp
  )
  target_include_directories(RawrXD-Win32IDE PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../include
  )
  target_compile_definitions(RawrXD-Win32IDE PRIVATE RAWRXD_PRODUCT100=1)
  set_source_files_properties(
    ${CMAKE_CURRENT_LIST_DIR}/../src/asm/RawrXD_Product100_x64.asm
    PROPERTIES LANGUAGE ASM_MASM)
  message(STATUS "[Win32IDE] Product100 overlay linked (RAWRXD_PRODUCT100=1)")
else()
  message(FATAL_ERROR "RawrXD_Product100.cmake must be included after RawrXD-Win32IDE target is declared")
endif()


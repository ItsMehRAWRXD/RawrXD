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
    ${CMAKE_CURRENT_LIST_DIR}/../src/asm/RawrXD_Product100_x64.asm
  )
  target_include_directories(RawrXD-Win32IDE PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../include
  )
else()
  message(FATAL_ERROR "RawrXD_Product100.cmake must be included after RawrXD-Win32IDE target is declared")
endif()


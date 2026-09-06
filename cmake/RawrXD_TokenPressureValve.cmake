# TOKEN_PRESSURE_VALVE_001 build overlay.
# Include after the RawrXD-Win32IDE target exists.

if(TARGET RawrXD-Win32IDE)
  target_sources(RawrXD-Win32IDE PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../src/asm/RawrXD_TokenPressureValve_x64.asm
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/RawrXD_TokenPressureValveBridge.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/win32app/TokenPressure.cpp
  )
  target_compile_definitions(RawrXD-Win32IDE PRIVATE
    RAWRXD_TOKEN_PRESSURE_VALVE=1
  )
  target_include_directories(RawrXD-Win32IDE PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../include
  )
else()
  message(FATAL_ERROR "RawrXD_TokenPressureValve.cmake must be included after RawrXD-Win32IDE target creation")
endif()


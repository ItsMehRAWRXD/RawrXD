# ============================================================================
#  Linker certification suite
#
#  Builds a self-contained COFF fixture generator and runs the
#  RAWR_NATIVE_LINKER_CERT_001 checks against rawrxd_link.
# ============================================================================
cmake_minimum_required(VERSION 3.16)
project(phase2_tests C)

# ---- The fixture generator writes COFF objects with no external deps ----
add_executable(make_fixtures
  make_fixtures.c
)
target_include_directories(make_fixtures PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(WIN32)
  target_link_libraries(make_fixtures PRIVATE kernel32)
endif()

# ---- The certification runner ----
find_program(RAWR_PWSH_EXE pwsh)
if(NOT RAWR_PWSH_EXE)
  find_program(RAWR_PWSH_EXE powershell)
endif()

if(RAWR_PWSH_EXE)
  enable_testing()
  add_test(
    NAME RAWR_NATIVE_LINKER_CERT_001
    COMMAND ${RAWR_PWSH_EXE} -File
            ${CMAKE_CURRENT_SOURCE_DIR}/run_linker_cert.ps1
            -Linker $<TARGET_FILE:rawrxd_link>
            -Fixtures $<TARGET_FILE:make_fixtures>
            -WorkDir ${CMAKE_CURRENT_BINARY_DIR}/cert
  )
else()
  message(STATUS "pwsh not found: skipping the linker certification test")
endif()

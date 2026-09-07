# RawrBackgroundTerminals.fragment.cmake
option(BUILD_RAWR_BACKGROUND_TERMINALS "Background terminal host/termctl/cert" ON)
if(NOT BUILD_RAWR_BACKGROUND_TERMINALS)
  return()
endif()

set(RAWR_TERM_COMMON
  src/platform/rawr_win32_process.cpp
  src/cli/terminal/rawr_terminal_session.cpp
  src/cli/terminal/rawr_terminal_supervisor.cpp
  src/cli/terminal/rawr_terminal_host.cpp
  src/cli/terminal/rawr_terminal_client.cpp
  src/cli/terminal/rawr_terminal_commands.cpp
  src/cli/terminal/rawr_agent_terminal_tool.cpp
)

set(ML64 "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/ml64.exe")
set(RAWR_TERM_ASM_OBJ "${CMAKE_BINARY_DIR}/rawr_term_x64.obj")
add_custom_command(
  OUTPUT ${RAWR_TERM_ASM_OBJ}
  COMMAND "${ML64}" /c /Fo "${RAWR_TERM_ASM_OBJ}"
          "${CMAKE_SOURCE_DIR}/src/masm/rawr_term_x64.asm"
  DEPENDS "${CMAKE_SOURCE_DIR}/src/masm/rawr_term_x64.asm"
  COMMENT "Assemble rawr_term_x64.asm")
add_custom_target(rawr_term_x64_asm DEPENDS ${RAWR_TERM_ASM_OBJ})

add_executable(rawr_terminal_host
  src/cli/terminal/rawr_term_host_main.cpp ${RAWR_TERM_COMMON})
add_executable(rawr_termctl
  src/cli/terminal/rawr_termctl_main.cpp ${RAWR_TERM_COMMON})
add_executable(rawrxd_background_terminals_001
  certs/rawrxd_background_terminals_001.cpp ${RAWR_TERM_COMMON}
  ${RAWR_TERM_ASM_OBJ})
add_dependencies(rawrxd_background_terminals_001 rawr_term_x64_asm)

foreach(t rawr_terminal_host rawr_termctl rawrxd_background_terminals_001)
  target_include_directories(${t} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/cli
    ${CMAKE_SOURCE_DIR}/src/cli/terminal
    ${CMAKE_SOURCE_DIR}/src/platform)
  if(MSVC)
    target_compile_options(${t} PRIVATE /EHsc /W3 /std:c++20)
  endif()
  set_target_properties(${t} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endforeach()

message(STATUS "[Deep2] RAWRXD_BACKGROUND_TERMINALS kitchen-sink wired")

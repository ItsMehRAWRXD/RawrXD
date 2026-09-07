# RawrProductLayer.fragment.cmake — daily-use product surface on Deep2
option(BUILD_RAWR_PRODUCT_LAYER "Context/repo/complete/agent product layer" ON)
if(NOT BUILD_RAWR_PRODUCT_LAYER)
  return()
endif()

set(ML64 "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/ml64.exe")
set(RAWR_PRODUCT_ASM_OBJ "${CMAKE_BINARY_DIR}/rawr_product_x64.obj")
add_custom_command(
  OUTPUT ${RAWR_PRODUCT_ASM_OBJ}
  COMMAND "${ML64}" /c /Fo "${RAWR_PRODUCT_ASM_OBJ}"
          "${CMAKE_SOURCE_DIR}/src/masm/rawr_product_x64.asm"
  DEPENDS "${CMAKE_SOURCE_DIR}/src/masm/rawr_product_x64.asm"
  COMMENT "Assemble rawr_product_x64.asm")
add_custom_target(rawr_product_x64_asm DEPENDS ${RAWR_PRODUCT_ASM_OBJ})

set(RAWR_PIPE_ASM_OBJ "${CMAKE_BINARY_DIR}/rawr_product_pipe_x64.obj")
add_custom_command(
  OUTPUT ${RAWR_PIPE_ASM_OBJ}
  COMMAND "${ML64}" /c /Fo "${RAWR_PIPE_ASM_OBJ}"
          "${CMAKE_SOURCE_DIR}/src/masm/rawr_product_pipe_x64.asm"
  DEPENDS "${CMAKE_SOURCE_DIR}/src/masm/rawr_product_pipe_x64.asm"
  COMMENT "Assemble rawr_product_pipe_x64.asm")
add_custom_target(rawr_product_pipe_x64_asm DEPENDS ${RAWR_PIPE_ASM_OBJ})

set(RAWR_PRODUCT_ASM_OBJS ${RAWR_PRODUCT_ASM_OBJ} ${RAWR_PIPE_ASM_OBJ})

add_executable(rawrxd_product_layer_001
  certs/rawrxd_product_layer_001.cpp
  ${RAWR_PRODUCT_ASM_OBJS})
add_dependencies(rawrxd_product_layer_001 rawr_product_x64_asm rawr_product_pipe_x64_asm)
target_include_directories(rawrxd_product_layer_001 PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/product)
if(MSVC)
  target_compile_options(rawrxd_product_layer_001 PRIVATE /EHsc /W3 /std:c++20)
endif()
set_target_properties(rawrxd_product_layer_001 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(rawrxd_product_layer_002
  certs/rawrxd_product_layer_002.cpp
  ${RAWR_PRODUCT_ASM_OBJS})
add_dependencies(rawrxd_product_layer_002 rawr_product_x64_asm rawr_product_pipe_x64_asm)
target_include_directories(rawrxd_product_layer_002 PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/product
  ${CMAKE_SOURCE_DIR}/src/cli
  ${CMAKE_SOURCE_DIR}/src/cli/style)
if(MSVC)
  target_compile_options(rawrxd_product_layer_002 PRIVATE /EHsc /W3 /std:c++20)
endif()
set_target_properties(rawrxd_product_layer_002 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

function(rawr_product_cert name src)
  add_executable(${name} ${src} ${RAWR_PRODUCT_ASM_OBJS})
  add_dependencies(${name} rawr_product_x64_asm rawr_product_pipe_x64_asm)
  target_include_directories(${name} PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/product
    ${CMAKE_SOURCE_DIR}/src/cli
    ${CMAKE_SOURCE_DIR}/src/cli/style)
  if(MSVC)
    target_compile_options(${name} PRIVATE /EHsc /W3 /std:c++20)
  endif()
  target_link_libraries(${name} PRIVATE user32)
  set_target_properties(${name} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endfunction()

rawr_product_cert(rawrxd_win32_editor_surface_001
  certs/rawrxd_win32_editor_surface_001.cpp)
rawr_product_cert(rawrxd_rawr_pipe_001 certs/rawrxd_rawr_pipe_001.cpp)
rawr_product_cert(rawrxd_editor_agent_e2e_001
  certs/rawrxd_editor_agent_e2e_001.cpp)
rawr_product_cert(rawrxd_product_ghost_bind_001
  certs/rawrxd_product_ghost_bind_001.cpp)
rawr_product_cert(rawrxd_autocomplete_cancel_001
  certs/rawrxd_autocomplete_cancel_001.cpp)
rawr_product_cert(rawrxd_installer_clean_machine_001
  certs/rawrxd_installer_clean_machine_001.cpp)
rawr_product_cert(rawrxd_offline_demo_001
  certs/rawrxd_offline_demo_001.cpp)
rawr_product_cert(rawrxd_repeatable_demo_record_001
  certs/rawrxd_repeatable_demo_record_001.cpp)

if(TARGET rawr)
  target_include_directories(rawr PRIVATE
    ${CMAKE_SOURCE_DIR}/src/product)
endif()

message(STATUS "[Deep2] RAWRXD_PRODUCT_LAYER wired")

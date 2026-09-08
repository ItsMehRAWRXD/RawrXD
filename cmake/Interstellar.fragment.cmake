# Interstellar — choreography-first runtime (raw filesystem source)
option(BUILD_INTERSTELLAR "Build interstellar choreography runtime" ON)
if(NOT BUILD_INTERSTELLAR)
  return()
endif()

set(IS_ROOT ${CMAKE_SOURCE_DIR}/interstellar)

add_executable(interstellar
  ${IS_ROOT}/src/main.cpp
  ${IS_ROOT}/src/engine.cpp
  ${IS_ROOT}/src/engine_plugin.cpp
  ${IS_ROOT}/src/runtime_lane.cpp
  ${IS_ROOT}/src/persistence.cpp
  ${IS_ROOT}/src/decode.cpp
  ${IS_ROOT}/src/runtime.cpp
  ${CMAKE_SOURCE_DIR}/src/deep2/DualLaneChoreographer.cpp
  ${CMAKE_SOURCE_DIR}/src/deep2/Deep2DeviceManager.cpp
)
target_include_directories(interstellar PRIVATE
  ${IS_ROOT}/include
  ${IS_ROOT}/src
  ${IS_ROOT}
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/deep2)
if(MSVC)
  target_compile_options(interstellar PRIVATE /EHsc /W3 /std:c++20)
  target_link_libraries(interstellar PRIVATE dxgi)
endif()
set_target_properties(interstellar PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(rawrxd_engine SHARED ${IS_ROOT}/plugins/rawrxd_engine.cpp)
target_include_directories(rawrxd_engine PRIVATE
  ${IS_ROOT}/include
  ${IS_ROOT}/plugins
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/deep2)
target_compile_definitions(rawrxd_engine PRIVATE IS_ENGINE_BUILD)
if(MSVC)
  target_compile_options(rawrxd_engine PRIVATE /EHsc /W3 /std:c++20)
endif()
if(TARGET InferenceEngine)
  target_link_libraries(rawrxd_engine PRIVATE InferenceEngine dxgi)
endif()
set_target_properties(rawrxd_engine PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  PREFIX ""
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(rawrxd_choreography_unbounded_001
  ${CMAKE_SOURCE_DIR}/certs/rawrxd_choreography_unbounded_001.cpp
  ${CMAKE_SOURCE_DIR}/src/deep2/DualLaneChoreographer.cpp
  ${CMAKE_SOURCE_DIR}/src/deep2/Deep2DeviceManager.cpp)
target_include_directories(rawrxd_choreography_unbounded_001 PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/deep2
  ${IS_ROOT})
if(MSVC)
  target_compile_options(rawrxd_choreography_unbounded_001 PRIVATE /EHsc /W3 /std:c++20)
  target_link_libraries(rawrxd_choreography_unbounded_001 PRIVATE dxgi)
endif()
set_target_properties(rawrxd_choreography_unbounded_001 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(rawrxd_interstellar_deep2_e2e_001
  ${CMAKE_SOURCE_DIR}/certs/rawrxd_interstellar_deep2_e2e_001.cpp)
target_include_directories(rawrxd_interstellar_deep2_e2e_001 PRIVATE
  ${IS_ROOT}/include
  ${CMAKE_SOURCE_DIR}/src)
if(MSVC)
  target_compile_options(rawrxd_interstellar_deep2_e2e_001 PRIVATE /EHsc /W3 /std:c++20)
endif()
add_dependencies(rawrxd_interstellar_deep2_e2e_001 rawrxd_engine)
set_target_properties(rawrxd_interstellar_deep2_e2e_001 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(rawrxd_k2_o_proj_hotpath_001
  ${CMAKE_SOURCE_DIR}/certs/rawrxd_k2_o_proj_hotpath_001.cpp)
if(MSVC)
  target_compile_options(rawrxd_k2_o_proj_hotpath_001 PRIVATE /EHsc /W3 /std:c++20)
endif()
set_target_properties(rawrxd_k2_o_proj_hotpath_001 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(rawrxd_k2_qkv_shared_x_001
  ${CMAKE_SOURCE_DIR}/certs/rawrxd_k2_qkv_shared_x_001.cpp)
if(MSVC)
  target_compile_options(rawrxd_k2_qkv_shared_x_001 PRIVATE /EHsc /W3 /std:c++20)
endif()
set_target_properties(rawrxd_k2_qkv_shared_x_001 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(rawrxd_beaconism_variants_001
  ${CMAKE_SOURCE_DIR}/certs/rawrxd_beaconism_variants_001.cpp)
target_include_directories(rawrxd_beaconism_variants_001 PRIVATE
  ${CMAKE_SOURCE_DIR})
if(MSVC)
  target_compile_options(rawrxd_beaconism_variants_001 PRIVATE /EHsc /W3 /std:c++17)
endif()
set_target_properties(rawrxd_beaconism_variants_001 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(rawrxd_kva_q4k_spv_001
  ${CMAKE_SOURCE_DIR}/certs/rawrxd_kva_q4k_spv_001.cpp)
target_include_directories(rawrxd_kva_q4k_spv_001 PRIVATE
  ${CMAKE_SOURCE_DIR}/src/deep2
  ${CMAKE_SOURCE_DIR}/src/deep2/lavapath)
if(MSVC)
  target_compile_options(rawrxd_kva_q4k_spv_001 PRIVATE /EHsc /W3 /std:c++17)
endif()
set_target_properties(rawrxd_kva_q4k_spv_001 PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(nemotron_nano_poem_smoke
  ${CMAKE_SOURCE_DIR}/certs/nemotron_nano_poem_smoke.cpp)
target_include_directories(nemotron_nano_poem_smoke PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/deep2)
if(MSVC)
  target_compile_options(nemotron_nano_poem_smoke PRIVATE /EHsc /W3 /std:c++20)
endif()
if(TARGET InferenceEngine)
  target_link_libraries(nemotron_nano_poem_smoke PRIVATE InferenceEngine)
endif()
set_target_properties(nemotron_nano_poem_smoke PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

message(STATUS "[Deep2] Interstellar choreography + Deep2 plugin wired")

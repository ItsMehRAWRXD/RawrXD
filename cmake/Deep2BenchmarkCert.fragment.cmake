# Deep2Benchmark CLI — production decode path cert authority for K2_USEFUL_TPS_001
option(BUILD_DEEP2_BENCHMARK_CLI "Build deep2_benchmark.exe" ON)
if(NOT BUILD_DEEP2_BENCHMARK_CLI)
  return()
endif()
if(NOT TARGET InferenceEngine)
  message(STATUS "[Deep2] deep2_benchmark skipped (no InferenceEngine)")
  return()
endif()

add_executable(deep2_benchmark
  ${CMAKE_SOURCE_DIR}/src/deep2/Deep2Benchmark.cpp
  ${CMAKE_SOURCE_DIR}/src/deep2/deep2_benchmark_main.cpp
)
target_include_directories(deep2_benchmark PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/deep2
  ${CMAKE_SOURCE_DIR}/include
)
if(MSVC)
  target_compile_options(deep2_benchmark PRIVATE /EHsc /W3 /std:c++20)
endif()
target_link_libraries(deep2_benchmark PRIVATE InferenceEngine dxgi pdh psapi)
set_target_properties(deep2_benchmark PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
  OUTPUT_NAME deep2_benchmark
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT TARGET k2_useful_tps_001)
  add_executable(k2_useful_tps_001
    ${CMAKE_SOURCE_DIR}/certs/k2_useful_tps_001.cpp
  )
  set_target_properties(k2_useful_tps_001 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    OUTPUT_NAME k2_useful_tps_001
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(NOT TARGET mla_cert_001)
  add_executable(mla_cert_001
    ${CMAKE_SOURCE_DIR}/certs/mla_cert_001.cpp
  )
  target_include_directories(mla_cert_001 PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/deep2
    ${CMAKE_SOURCE_DIR}/include
  )
  if(MSVC)
    target_compile_options(mla_cert_001 PRIVATE /EHsc /W3 /std:c++20)
  endif()
  target_link_libraries(mla_cert_001 PRIVATE InferenceEngine dxgi)
  set_target_properties(mla_cert_001 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    OUTPUT_NAME mla_cert_001
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

message(STATUS "[Deep2] Benchmark cert CLI: deep2_benchmark + k2_useful_tps_001 + mla_cert_001")

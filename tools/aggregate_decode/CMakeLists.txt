cmake_minimum_required(VERSION 3.20)
project(aggregate_decode_smoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Deep2 link is applied by parent after deep2_engine_lib exists
# (-DAGGREGATE_DECODE_USE_DEEP2=ON). Standalone configure stays Ollama-only.
option(AGGREGATE_DECODE_USE_DEEP2
  "Compile AggregateDecodeDeep2Backend against deep2_engine_lib" OFF)

set(AGGDEC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../src/deep2")
set(AGGDEC_SRC
  ${AGGDEC_ROOT}/aggregate_decode/AggregateDecodeSession.cpp
  ${AGGDEC_ROOT}/aggregate_decode/AggregateDecodeMultiSession.cpp
  ${AGGDEC_ROOT}/aggregate_decode/AggregateDecodeOllamaBackend.cpp
  ${AGGDEC_ROOT}/aggregate_decode/AggregateDecodeDeep2Backend.cpp
)

add_library(aggregate_decode_lib STATIC ${AGGDEC_SRC})
target_include_directories(aggregate_decode_lib PUBLIC
  ${AGGDEC_ROOT}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../src
)
if(MSVC)
  target_compile_options(aggregate_decode_lib PRIVATE /EHsc /W3)
  target_compile_definitions(aggregate_decode_lib PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()
target_link_libraries(aggregate_decode_lib PUBLIC winhttp)

add_executable(aggregate_decode_single_smoke
  ${CMAKE_CURRENT_SOURCE_DIR}/../aggregate_decode_single_smoke.cpp)
target_link_libraries(aggregate_decode_single_smoke PRIVATE aggregate_decode_lib)
target_include_directories(aggregate_decode_single_smoke PRIVATE ${AGGDEC_ROOT})

add_executable(aggregate_decode_multi_smoke
  ${CMAKE_CURRENT_SOURCE_DIR}/../aggregate_decode_multi_smoke.cpp)
target_link_libraries(aggregate_decode_multi_smoke PRIVATE aggregate_decode_lib)
target_include_directories(aggregate_decode_multi_smoke PRIVATE ${AGGDEC_ROOT})

set_target_properties(aggregate_decode_single_smoke aggregate_decode_multi_smoke PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
)

# Standalone tree: only link Deep2 if parent already defined the target.
if(AGGREGATE_DECODE_USE_DEEP2 AND TARGET deep2_engine_lib)
  target_compile_definitions(aggregate_decode_lib PUBLIC AGGREGATE_DECODE_USE_DEEP2=1)
  target_link_libraries(aggregate_decode_lib PUBLIC deep2_engine_lib)
  message(STATUS "aggregate_decode: AGGREGATE_DECODE_USE_DEEP2=1 (subdir)")
elseif(AGGREGATE_DECODE_USE_DEEP2)
  message(STATUS "aggregate_decode: USE_DEEP2 requested; awaiting parent deep2_engine_lib link")
else()
  message(STATUS "aggregate_decode smokes enabled (OLLAMA_HTTP; Deep2 optional)")
endif()

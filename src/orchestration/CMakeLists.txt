cmake_minimum_required(VERSION 3.20)
project(RawrXDOrchestration)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 COMPONENTS Core Network Sql Multimedia REQUIRED)

add_library(RawrXDOrchestration STATIC
    llm_router.hpp
    llm_router.cpp
    agent_coordinator.hpp
    agent_coordinator.cpp
    voice_processor.hpp
    voice_processor.cpp
    qt6_audio_helper.hpp
    shard_router_metadata.hpp
    swarm_load_balancer.cpp
    k_replica_manager.hpp
    quadbuffer_pipeline.hpp
    dynamic_quantization_engine.hpp
)

# Adaptive Loading & Quantization
add_library(RawrXDQuantization STATIC
    ../loading/adaptive_model_loader.cpp
)
target_include_directories(RawrXDQuantization PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Testing & Benchmarking
add_executable(rawrxd_800b_benchmark ../testing/benchmark_800b_swarm.cpp)
add_executable(rawrxd_120b_benchmark ../testing/benchmark_120b_local.cpp)

target_link_libraries(rawrxd_800b_benchmark PRIVATE RawrXDOrchestration)
target_link_libraries(rawrxd_120b_benchmark PRIVATE RawrXDOrchestration RawrXDQuantization)

# MASM64 Sources
set(ASM_SOURCES
    ../asm/agentic_deep_thinking_kernels.asm
    ../asm/node_heartbeat.asm
    ../asm/p2p_shard_replicate.asm
    ../asm/quadbuffer_prefetch.asm
    ../asm/vram_pressure_monitor.asm
    ../asm/rawrxd_ui_dispatcher.asm
)

target_link_libraries(RawrXDOrchestration
    PUBLIC
        Qt6::Core
        Qt6::Network
        Qt6::Sql
        Qt6::Multimedia
)

target_include_directories(RawrXDOrchestration
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Enable warnings
if(MSVC)
    target_compile_options(RawrXDOrchestration PRIVATE /W4)
else()
    target_compile_options(RawrXDOrchestration PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Optimization
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(RawrXDOrchestration PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/O2>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O3>
    )
endif()

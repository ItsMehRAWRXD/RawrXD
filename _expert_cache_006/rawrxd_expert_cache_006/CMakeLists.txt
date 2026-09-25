cmake_minimum_required(VERSION 3.20)
project(RawrXDExpertCache006 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(rawrxd_expert_cache STATIC
  src/ExpertCache.cpp
  src/ExpertTensorCatalog.cpp
  src/PackedExpertSlicer.cpp
  src/Deep2ExpertCacheBridge.cpp
  src/HostStagingRing.cpp
  src/VulkanExpertTransport.cpp
  src/Deep2StackGuard.cpp
  src/ExpertScheduler.cpp
  src/Deep2MultiGpuExpertCache.cpp
  src/ExpertCacheBenchmark.cpp)
target_include_directories(rawrxd_expert_cache PUBLIC src)

add_executable(test_expert_cache_bridge tests/test_expert_cache_bridge.cpp)
target_link_libraries(test_expert_cache_bridge PRIVATE rawrxd_expert_cache)
add_executable(test_expert_cache_packed tests/test_expert_cache_packed.cpp)
target_link_libraries(test_expert_cache_packed PRIVATE rawrxd_expert_cache)
add_executable(test_expert_cache_async tests/test_expert_cache_async.cpp)
target_link_libraries(test_expert_cache_async PRIVATE rawrxd_expert_cache)
add_executable(test_batch005 tests/test_batch005.cpp)
target_link_libraries(test_batch005 PRIVATE rawrxd_expert_cache)
add_executable(test_batch006 tests/test_batch006.cpp)
target_link_libraries(test_batch006 PRIVATE rawrxd_expert_cache)

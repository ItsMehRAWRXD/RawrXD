cmake_minimum_required(VERSION 3.20)
project(RawrXDExpertCache004 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_library(rawrxd_expert_cache STATIC
  src/ExpertCache.cpp
  src/ExpertTensorCatalog.cpp
  src/PackedExpertSlicer.cpp
  src/Deep2ExpertCacheBridge.cpp
  src/HostStagingRing.cpp
  src/VulkanExpertTransport.cpp)
target_include_directories(rawrxd_expert_cache PUBLIC src)
add_executable(test_expert_cache_bridge tests/test_expert_cache_bridge.cpp)
target_link_libraries(test_expert_cache_bridge PRIVATE rawrxd_expert_cache)
add_executable(test_expert_cache_packed tests/test_expert_cache_packed.cpp)
target_link_libraries(test_expert_cache_packed PRIVATE rawrxd_expert_cache)
add_executable(test_expert_cache_async tests/test_expert_cache_async.cpp)
target_link_libraries(test_expert_cache_async PRIVATE rawrxd_expert_cache)

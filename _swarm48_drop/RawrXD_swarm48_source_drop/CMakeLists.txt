cmake_minimum_required(VERSION 3.20)
project(RawrXD_Swarm48_Core LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(rawrxd_swarm48 STATIC
    src/SharedModelRegistry.cpp
    src/PagedKVPool.cpp
    src/DeviceLeaseManager.cpp
    src/ContinuousBatcher.cpp
    src/TeamCoordinator.cpp
    src/ReceiptLedger.cpp
    src/SwarmRuntime.cpp)
target_include_directories(rawrxd_swarm48 PUBLIC include)

add_executable(swarm48_selftest tools/swarm48_selftest.cpp)
target_link_libraries(swarm48_selftest PRIVATE rawrxd_swarm48)

cmake_minimum_required(VERSION 3.16)
project(RawrXD_DistributedClusterExample)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find RawrXD
find_package(RawrXD REQUIRED)

# Distributed Cluster Example
add_executable(distributed_cluster_example
    main.cpp
    ClusterManager.cpp
    NodeDiscovery.cpp
)

target_link_libraries(distributed_cluster_example
    PRIVATE
        RawrXD::Runtime
        RawrXD::Distributed
)

# Install
install(TARGETS distributed_cluster_example
    RUNTIME DESTINATION bin/examples
)
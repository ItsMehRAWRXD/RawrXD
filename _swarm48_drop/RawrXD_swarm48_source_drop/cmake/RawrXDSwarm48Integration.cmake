# Include after the shipping target exists.
set(RAWRXD_SWARM48_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/../src/SharedModelRegistry.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/PagedKVPool.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/DeviceLeaseManager.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/ContinuousBatcher.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/TeamCoordinator.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/ReceiptLedger.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../src/SwarmRuntime.cpp)

function(rawrxd_enable_swarm48 target)
    if(NOT TARGET ${target})
        message(FATAL_ERROR "[Swarm48] target '${target}' does not exist")
    endif()
    target_sources(${target} PRIVATE ${RAWRXD_SWARM48_SOURCES})
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include)
    target_compile_features(${target} PRIVATE cxx_std_20)
    target_compile_definitions(${target} PRIVATE RAWRXD_SWARM48=1)
endfunction()

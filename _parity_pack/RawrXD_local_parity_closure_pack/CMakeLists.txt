cmake_minimum_required(VERSION 3.22)
project(RawrXDLocalParityClosure LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(rawrxd_local_parity_closure STATIC
    src/AgentOrchestrator.cpp
    src/BuildTestGate.cpp
    src/Certification.cpp
    src/ContextPlanner.cpp
    src/DevicePolicy.cpp
    src/EditTransaction.cpp
    src/PerformanceLedger.cpp
    src/ProcessRunner.cpp
    src/ToolGateway.cpp
    src/WorkspaceGuard.cpp
)
target_include_directories(rawrxd_local_parity_closure PUBLIC include)
if(MSVC)
    target_compile_options(rawrxd_local_parity_closure PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(rawrxd_local_parity_closure PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(rawrxd_closure_selftest tools/closure_selftest.cpp)
target_link_libraries(rawrxd_closure_selftest PRIVATE rawrxd_local_parity_closure)

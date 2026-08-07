cmake_minimum_required(VERSION 3.20)
project(VAL063_GateA VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================================
# Gate A: Identity Primitives Library
# ============================================================================
add_library(val063_identity STATIC
    execution_types.cpp
    hash_provider.cpp
    uuid_provider.cpp
    timestamp_provider.cpp
)

target_include_directories(val063_identity PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Gate A Tests
add_executable(execution_types_test
    execution_types_test.cpp
)

target_link_libraries(execution_types_test PRIVATE
    val063_identity
)

# ============================================================================
# Gate B: Gateway Binding Library
# ============================================================================
add_library(val063_gateway STATIC
    attestation_record.cpp
    execution_gateway.cpp
)

target_link_libraries(val063_gateway PUBLIC
    val063_identity
)

# Gate B Tests
add_executable(gateway_binding_test
    gateway_binding_test.cpp
)

target_link_libraries(gateway_binding_test PRIVATE
    val063_identity
    val063_gateway
)

# ============================================================================
# Gate C: Streaming Adapter Library
# ============================================================================
add_library(val063_streaming STATIC
    streaming_event.cpp
    bounded_event_queue.cpp
    streaming_adapter.cpp
)

target_link_libraries(val063_streaming PUBLIC
    val063_identity
    val063_gateway
)

# Gate C Tests
add_executable(streaming_adapter_test
    streaming_adapter_test.cpp
)

target_link_libraries(streaming_adapter_test PRIVATE
    val063_identity
    val063_gateway
    val063_streaming
)

# ============================================================================
# Gate D: Replay Harness Library
# ============================================================================
add_library(val063_replay STATIC
    replay_harness.cpp
)

target_link_libraries(val063_replay PUBLIC
    val063_identity
    val063_gateway
    val063_streaming
)

# Gate D Tests
add_executable(replay_harness_test
    replay_harness_test.cpp
)

target_link_libraries(replay_harness_test PRIVATE
    val063_identity
    val063_gateway
    val063_streaming
    val063_replay
)

# ============================================================================
# Testing
# ============================================================================
enable_testing()
add_test(NAME GateA_IdentityPrimitives COMMAND execution_types_test)
add_test(NAME GateB_GatewayBinding COMMAND gateway_binding_test)
add_test(NAME GateC_StreamingAdapter COMMAND streaming_adapter_test)
add_test(NAME GateD_ReplayHarness COMMAND replay_harness_test)

# ============================================================================
# Installation
# ============================================================================
install(TARGETS val063_identity val063_gateway val063_streaming val063_replay
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES
    execution_types.hpp
    hash_provider.hpp
    uuid_provider.hpp
    timestamp_provider.hpp
    attestation_record.hpp
    execution_gateway.hpp
    streaming_event.hpp
    bounded_event_queue.hpp
    streaming_adapter.hpp
    replay_harness.hpp
    certified_compiler.hpp
    meta_circular_vm.hpp
    ide_integration.hpp
    val064_host_fingerprint.hpp
    val065_evidence_signer.hpp
    val066_adversarial_testing.hpp
    DESTINATION include/val063
)

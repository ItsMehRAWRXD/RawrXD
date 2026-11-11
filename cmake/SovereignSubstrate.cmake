# Sovereign Substrate - CMake Configuration
# This module configures all components of the Sovereign Substrate

include_guard(GLOBAL)

# ============================================================================
# Feature Options
# ============================================================================

# Intent Guardrails
option(RAWR_INTENT_SYSTEM_ENABLED "Enable Intent Guardrails system" ON)
option(RAWR_INTENT_GUARD_ENABLED "Enable intent guard" ON)
option(RAWR_INTENT_VALIDATION_ENABLED "Enable intent validation" ON)
option(RAWR_PATCH_TRANSACTION_ENABLED "Enable patch transactions" ON)
option(RAWR_CAPABILITY_TOKENS_ENABLED "Enable capability tokens" ON)
option(RAWR_HOTPATCH_JOURNAL_ENABLED "Enable hotpatch journaling" ON)
option(RAWR_PATCH_FIREWALL_ENABLED "Enable patch firewall" ON)
option(RAWR_REFLECTOR_AGENT_ENABLED "Enable reflector agent" ON)
option(RAWR_ATOMIC_ACTIVATION_ENABLED "Enable atomic activation" ON)
option(RAWR_FIRST_CLASS_ROLLBACK_ENABLED "Enable first-class rollback" ON)
option(RAWR_MODEL_ADAPTER_ENABLED "Enable model adapter" ON)

# Emergency bypass (disables all guardrails)
option(RAWR_INTENT_EMERGENCY_BYPASS "Emergency bypass (disables all guardrails)" OFF)

# Agent Kernel
option(RAWR_AGENT_KERNEL_ENABLED "Enable Agent Kernel" ON)
option(RAWR_TELEMETRY_INJECTOR_ENABLED "Enable telemetry injector" ON)
option(RAWR_INTENT_REPLAY_ENABLED "Enable intent replay" ON)
option(RAWR_BUILD_TELEMETRY_ENABLED "Enable build telemetry" ON)

# Repository Memory Graph
option(RAWR_MEMORY_GRAPH_ENABLED "Enable Repository Memory Graph" ON)

# Control Plane UI
option(RAWR_CONTROL_PLANE_ENABLED "Enable Control Plane UI" ON)

# ============================================================================
# Compile Definitions
# ============================================================================

if(RAWR_INTENT_SYSTEM_ENABLED)
    add_compile_definitions(RAWR_INTENT_SYSTEM_ENABLED=1)
    
    if(RAWR_INTENT_GUARD_ENABLED)
        add_compile_definitions(RAWR_INTENT_GUARD_ENABLED=1)
    endif()
    
    if(RAWR_INTENT_VALIDATION_ENABLED)
        add_compile_definitions(RAWR_INTENT_VALIDATION_ENABLED=1)
    endif()
    
    if(RAWR_PATCH_TRANSACTION_ENABLED)
        add_compile_definitions(RAWR_PATCH_TRANSACTION_ENABLED=1)
    endif()
    
    if(RAWR_CAPABILITY_TOKENS_ENABLED)
        add_compile_definitions(RAWR_CAPABILITY_TOKENS_ENABLED=1)
    endif()
    
    if(RAWR_HOTPATCH_JOURNAL_ENABLED)
        add_compile_definitions(RAWR_HOTPATCH_JOURNAL_ENABLED=1)
    endif()
    
    if(RAWR_PATCH_FIREWALL_ENABLED)
        add_compile_definitions(RAWR_PATCH_FIREWALL_ENABLED=1)
    endif()
    
    if(RAWR_REFLECTOR_AGENT_ENABLED)
        add_compile_definitions(RAWR_REFLECTOR_AGENT_ENABLED=1)
    endif()
    
    if(RAWR_ATOMIC_ACTIVATION_ENABLED)
        add_compile_definitions(RAWR_ATOMIC_ACTIVATION_ENABLED=1)
    endif()
    
    if(RAWR_FIRST_CLASS_ROLLBACK_ENABLED)
        add_compile_definitions(RAWR_FIRST_CLASS_ROLLBACK_ENABLED=1)
    endif()
    
    if(RAWR_MODEL_ADAPTER_ENABLED)
        add_compile_definitions(RAWR_MODEL_ADAPTER_ENABLED=1)
    endif()
    
    if(RAWR_INTENT_EMERGENCY_BYPASS)
        add_compile_definitions(RAWR_INTENT_EMERGENCY_BYPASS=1)
        message(WARNING "RAWR_INTENT_EMERGENCY_BYPASS is enabled - all guardrails disabled!")
    endif()
else()
    add_compile_definitions(RAWR_INTENT_SYSTEM_ENABLED=0)
endif()

if(RAWR_AGENT_KERNEL_ENABLED)
    add_compile_definitions(RAWR_AGENT_KERNEL_ENABLED=1)
    
    if(RAWR_TELEMETRY_INJECTOR_ENABLED)
        add_compile_definitions(RAWR_TELEMETRY_INJECTOR_ENABLED=1)
    endif()
    
    if(RAWR_INTENT_REPLAY_ENABLED)
        add_compile_definitions(RAWR_INTENT_REPLAY_ENABLED=1)
    endif()
    
    if(RAWR_BUILD_TELEMETRY_ENABLED)
        add_compile_definitions(RAWR_BUILD_TELEMETRY_ENABLED=1)
    endif()
else()
    add_compile_definitions(RAWR_AGENT_KERNEL_ENABLED=0)
endif()

if(RAWR_MEMORY_GRAPH_ENABLED)
    add_compile_definitions(RAWR_MEMORY_GRAPH_ENABLED=1)
else()
    add_compile_definitions(RAWR_MEMORY_GRAPH_ENABLED=0)
endif()

if(RAWR_CONTROL_PLANE_ENABLED)
    add_compile_definitions(RAWR_CONTROL_PLANE_ENABLED=1)
else()
    add_compile_definitions(RAWR_CONTROL_PLANE_ENABLED=0)
endif()

# ============================================================================
# Source Files
# ============================================================================

set(SOVEREIGN_SUBSTRATE_SOURCES
    # Intent Guardrails
    ${CMAKE_SOURCE_DIR}/src/intent/intent_config.cpp
    ${CMAKE_SOURCE_DIR}/src/intent/intent_abi.cpp
    ${CMAKE_SOURCE_DIR}/src/guardrails/capability_policy.cpp
    ${CMAKE_SOURCE_DIR}/src/guardrails/patch_firewall.cpp
    ${CMAKE_SOURCE_DIR}/src/hotpatch/patch_transaction.cpp
    
    # Sovereign Puppeteer
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer/SymbolTableGenerator.cpp
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer/PuppeteerAPI.cpp
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer/VEH_Watchdog.cpp
    
    # Agent Kernel
    ${CMAKE_SOURCE_DIR}/src/kernel/AgentKernel.cpp
    ${CMAKE_SOURCE_DIR}/src/kernel/IntentExecutionPipeline.cpp
    ${CMAKE_SOURCE_DIR}/src/kernel/TelemetryInjector.cpp
    ${CMAKE_SOURCE_DIR}/src/kernel/IntentReplayEngine.cpp
    ${CMAKE_SOURCE_DIR}/src/kernel/BuildTelemetry.cpp
    
    # Repository Memory Graph
    ${CMAKE_SOURCE_DIR}/src/memory/RepositoryMemoryGraph.cpp
    
    # Control Plane UI
    ${CMAKE_SOURCE_DIR}/src/controlplane/ControlPlaneUI.cpp
)

set(SOVEREIGN_SUBSTRATE_HEADERS
    # Intent Guardrails
    ${CMAKE_SOURCE_DIR}/src/intent/intent_config.hpp
    ${CMAKE_SOURCE_DIR}/src/intent/intent_abi.hpp
    ${CMAKE_SOURCE_DIR}/src/intent/model_adapter.hpp
    ${CMAKE_SOURCE_DIR}/src/guardrails/capability_policy.hpp
    ${CMAKE_SOURCE_DIR}/src/guardrails/patch_firewall.hpp
    ${CMAKE_SOURCE_DIR}/src/hotpatch/patch_transaction.hpp
    
    # Sovereign Puppeteer
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer/SymbolTableGenerator.hpp
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer/PuppeteerAPI.hpp
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer/VEH_Watchdog.hpp
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer/JITAssembler.hpp
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer/AutonomousPuppeteer.hpp
    
    # Agent Kernel
    ${CMAKE_SOURCE_DIR}/src/kernel/AgentKernel.hpp
    ${CMAKE_SOURCE_DIR}/src/kernel/IntentExecutionPipeline.hpp
    ${CMAKE_SOURCE_DIR}/src/kernel/TelemetryInjector.hpp
    ${CMAKE_SOURCE_DIR}/src/kernel/IntentReplayEngine.hpp
    ${CMAKE_SOURCE_DIR}/src/kernel/BuildTelemetry.hpp
    
    # Repository Memory Graph
    ${CMAKE_SOURCE_DIR}/src/memory/RepositoryMemoryGraph.hpp
    
    # Control Plane UI
    ${CMAKE_SOURCE_DIR}/src/controlplane/ControlPlaneUI.hpp
)

# ============================================================================
# Include Directories
# ============================================================================

set(SOVEREIGN_SUBSTRATE_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/src/intent
    ${CMAKE_SOURCE_DIR}/src/guardrails
    ${CMAKE_SOURCE_DIR}/src/hotpatch
    ${CMAKE_SOURCE_DIR}/src/sovereign/puppeteer
    ${CMAKE_SOURCE_DIR}/src/kernel
    ${CMAKE_SOURCE_DIR}/src/memory
    ${CMAKE_SOURCE_DIR}/src/controlplane
)

# ============================================================================
# Function to add Sovereign Substrate to a target
# ============================================================================

function(target_add_sovereign_substrate target)
    target_sources(${target} PRIVATE ${SOVEREIGN_SUBSTRATE_SOURCES})
    target_include_directories(${target} PRIVATE ${SOVEREIGN_SUBSTRATE_INCLUDE_DIRS})
    
    # Link dependencies
    # Note: Add actual dependencies as needed (OpenSSL for SHA256, etc.)
    # target_link_libraries(${target} PRIVATE ...)
    
    message(STATUS "Added Sovereign Substrate to target: ${target}")
endfunction()

# ============================================================================
# Print Configuration Summary
# ============================================================================

message(STATUS "")
message(STATUS "Sovereign Substrate Configuration:")
message(STATUS "  Intent System:        ${RAWR_INTENT_SYSTEM_ENABLED}")
message(STATUS "  Intent Guard:         ${RAWR_INTENT_GUARD_ENABLED}")
message(STATUS "  Validation:           ${RAWR_INTENT_VALIDATION_ENABLED}")
message(STATUS "  Transactions:         ${RAWR_PATCH_TRANSACTION_ENABLED}")
message(STATUS "  Capability Tokens:    ${RAWR_CAPABILITY_TOKENS_ENABLED}")
message(STATUS "  Hotpatch Journal:     ${RAWR_HOTPATCH_JOURNAL_ENABLED}")
message(STATUS "  Patch Firewall:       ${RAWR_PATCH_FIREWALL_ENABLED}")
message(STATUS "  Reflector Agent:      ${RAWR_REFLECTOR_AGENT_ENABLED}")
message(STATUS "  Atomic Activation:    ${RAWR_ATOMIC_ACTIVATION_ENABLED}")
message(STATUS "  First-Class Rollback: ${RAWR_FIRST_CLASS_ROLLBACK_ENABLED}")
message(STATUS "  Model Adapter:        ${RAWR_MODEL_ADAPTER_ENABLED}")
message(STATUS "  Emergency Bypass:     ${RAWR_INTENT_EMERGENCY_BYPASS}")
message(STATUS "")
message(STATUS "  Agent Kernel:         ${RAWR_AGENT_KERNEL_ENABLED}")
message(STATUS "  Telemetry Injector:   ${RAWR_TELEMETRY_INJECTOR_ENABLED}")
message(STATUS "  Intent Replay:        ${RAWR_INTENT_REPLAY_ENABLED}")
message(STATUS "  Build Telemetry:      ${RAWR_BUILD_TELEMETRY_ENABLED}")
message(STATUS "")
message(STATUS "  Memory Graph:         ${RAWR_MEMORY_GRAPH_ENABLED}")
message(STATUS "  Control Plane:        ${RAWR_CONTROL_PLANE_ENABLED}")
message(STATUS "")

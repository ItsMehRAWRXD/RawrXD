# =============================================================================
# Intent Guardrails CMake Configuration
# Toggleable features for the Intent-to-Execution system
# =============================================================================

# Master toggle for entire Intent system
option(RAWR_INTENT_SYSTEM_ENABLED "Enable Intent Guardrails system" ON)

if(NOT RAWR_INTENT_SYSTEM_ENABLED)
    message(STATUS "[Intent Guardrails] System disabled")
    return()
endif()

message(STATUS "[Intent Guardrails] Configuring...")

# Individual feature toggles
option(RAWR_INTENT_GUARD_ENABLED "Enable Intent Guardrails" ON)
option(RAWR_INTENT_VALIDATION_ENABLED "Enable Intent Validation" ON)
option(RAWR_PATCH_TRANSACTION_ENABLED "Enable Patch Transactions" ON)
option(RAWR_CAPABILITY_TOKENS_ENABLED "Enable Capability Tokens" ON)
option(RAWR_HOTPATCH_JOURNAL_ENABLED "Enable Hotpatch Journal" ON)
option(RAWR_PATCH_FIREWALL_ENABLED "Enable Patch Firewall" ON)
option(RAWR_REFLECTOR_AGENT_ENABLED "Enable Reflector Agent" ON)
option(RAWR_ATOMIC_ACTIVATION_ENABLED "Enable Atomic Activation" ON)
option(RAWR_ROLLBACK_FIRST_CLASS_ENABLED "Enable First-Class Rollback" ON)
option(RAWR_MODEL_ADAPTER_ENABLED "Enable Model Adapter" ON)

# Emergency bypass (compile-time kill switch)
option(RAWR_INTENT_EMERGENCY_BYPASS "Emergency bypass for all guardrails" OFF)

if(RAWR_INTENT_EMERGENCY_BYPASS)
    message(WARNING "[Intent Guardrails] EMERGENCY BYPASS ENABLED - All guardrails disabled!")
endif()

# Feature summary
message(STATUS "[Intent Guardrails] Features:")
message(STATUS "  - Intent Guard: ${RAWR_INTENT_GUARD_ENABLED}")
message(STATUS "  - Validation: ${RAWR_INTENT_VALIDATION_ENABLED}")
message(STATUS "  - Transactions: ${RAWR_PATCH_TRANSACTION_ENABLED}")
message(STATUS "  - Capability Tokens: ${RAWR_CAPABILITY_TOKENS_ENABLED}")
message(STATUS "  - Hotpatch Journal: ${RAWR_HOTPATCH_JOURNAL_ENABLED}")
message(STATUS "  - Patch Firewall: ${RAWR_PATCH_FIREWALL_ENABLED}")
message(STATUS "  - Reflector Agent: ${RAWR_REFLECTOR_AGENT_ENABLED}")
message(STATUS "  - Atomic Activation: ${RAWR_ATOMIC_ACTIVATION_ENABLED}")
message(STATUS "  - First-Class Rollback: ${RAWR_ROLLBACK_FIRST_CLASS_ENABLED}")
message(STATUS "  - Model Adapter: ${RAWR_MODEL_ADAPTER_ENABLED}")

# Compile definitions
add_compile_definitions(
    RAWR_INTENT_GUARD_ENABLED=$<BOOL:${RAWR_INTENT_GUARD_ENABLED}>
    RAWR_INTENT_VALIDATION_ENABLED=$<BOOL:${RAWR_INTENT_VALIDATION_ENABLED}>
    RAWR_PATCH_TRANSACTION_ENABLED=$<BOOL:${RAWR_PATCH_TRANSACTION_ENABLED}>
    RAWR_CAPABILITY_TOKENS_ENABLED=$<BOOL:${RAWR_CAPABILITY_TOKENS_ENABLED}>
    RAWR_HOTPATCH_JOURNAL_ENABLED=$<BOOL:${RAWR_HOTPATCH_JOURNAL_ENABLED}>
    RAWR_PATCH_FIREWALL_ENABLED=$<BOOL:${RAWR_PATCH_FIREWALL_ENABLED}>
    RAWR_REFLECTOR_AGENT_ENABLED=$<BOOL:${RAWR_REFLECTOR_AGENT_ENABLED}>
    RAWR_ATOMIC_ACTIVATION_ENABLED=$<BOOL:${RAWR_ATOMIC_ACTIVATION_ENABLED}>
    RAWR_ROLLBACK_FIRST_CLASS_ENABLED=$<BOOL:${RAWR_ROLLBACK_FIRST_CLASS_ENABLED}>
    RAWR_MODEL_ADAPTER_ENABLED=$<BOOL:${RAWR_MODEL_ADAPTER_ENABLED}>
    RAWR_INTENT_EMERGENCY_BYPASS=$<BOOL:${RAWR_INTENT_EMERGENCY_BYPASS}>
)

# Intent system sources
set(INTENT_SOURCES
    src/intent/intent_config.cpp
)

# Guardrails sources
set(GUARDRAILS_SOURCES
)

# Hotpatch sources
set(HOTPATCH_SOURCES
)

# Add to main sources if enabled
if(RAWR_INTENT_SYSTEM_ENABLED)
    list(APPEND SOURCES ${INTENT_SOURCES})
    message(STATUS "[Intent Guardrails] Added ${INTENT_SOURCES} to build")
endif()

# Include directories (only if targets exist)
if(TARGET RawrEngine)
    target_include_directories(RawrEngine PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/intent
        ${CMAKE_CURRENT_SOURCE_DIR}/src/guardrails
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hotpatch
    )
endif()

if(TARGET RawrXD_Gold)
    target_include_directories(RawrXD_Gold PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/intent
        ${CMAKE_CURRENT_SOURCE_DIR}/src/guardrails
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hotpatch
    )
endif()

message(STATUS "[Intent Guardrails] Configuration complete")

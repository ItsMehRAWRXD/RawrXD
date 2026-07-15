/**
 * FMF Fallback Detection Macros
 * 
 * Additional macros for detecting fallback patterns in code paths.
 * These catch silent degradation that stub instrumentation misses.
 */

#pragma once

#include "FailureModeFirewall.h"

// ============================================================================
// NULL POINTER CHECKS WITH FMF REPORTING
// ============================================================================

// Check for null pointer and report as fallback
#define FMF_NULL_CHECK(ptr, feature) \
    if ((ptr) == nullptr) { \
        FMF_FALLBACK("NULL_POINTER_" #ptr); \
        return; \
    }

// Check for null pointer with return value
#define FMF_NULL_CHECK_RET(ptr, feature, retval) \
    if ((ptr) == nullptr) { \
        FMF_FALLBACK("NULL_POINTER_" #ptr); \
        return retval; \
    }

// ============================================================================
// FALLBACK PATH DETECTION
// ============================================================================

// Report when entering a fallback/default code path
#define FMF_FALLBACK_PATH(reason) \
    FMF_FALLBACK(reason)

// Report when a feature is disabled or unavailable
#define FMF_FEATURE_DISABLED(feature) \
    FMF_FALLBACK("DISABLED_" feature)

// Report when a feature falls back to degraded mode
#define FMF_DEGRADED_MODE(feature, reason) \
    FMF_FALLBACK("DEGRADED_" feature "_" reason)

// ============================================================================
// LSP-SPECIFIC FALLBACK DETECTION
// ============================================================================

// LSP client not available
#define FMF_LSP_CLIENT_NULL() \
    FMF_FALLBACK("LSP_CLIENT_NULL")

// LSP request timeout
#define FMF_LSP_TIMEOUT(requestType) \
    FMF_FALLBACK("LSP_TIMEOUT_" requestType)

// LSP response parsing failure
#define FMF_LSP_PARSE_ERROR(requestType) \
    FMF_FALLBACK("LSP_PARSE_ERROR_" requestType)

// LSP version mismatch
#define FMF_LSP_VERSION_MISMATCH(expected, actual) \
    FMF_FALLBACK("LSP_VERSION_MISMATCH")

// ============================================================================
// INFERENCE-SPECIFIC FALLBACK DETECTION
// ============================================================================

// Inference engine not initialized
#define FMF_INFERENCE_NOT_INIT() \
    FMF_FALLBACK("INFERENCE_NOT_INITIALIZED")

// Model not loaded
#define FMF_MODEL_NOT_LOADED() \
    FMF_FALLBACK("MODEL_NOT_LOADED")

// Tokenizer fallback
#define FMF_TOKENIZER_FALLBACK() \
    FMF_FALLBACK("TOKENIZER_FALLBACK")

// GPU fallback to CPU
#define FMF_GPU_FALLBACK(reason) \
    FMF_FALLBACK("GPU_FALLBACK_" reason)

// ============================================================================
// BRIDGE/ASM-SPECIFIC FALLBACK DETECTION
// ============================================================================

// ASM kernel not available
#define FMF_ASM_KERNEL_NOT_AVAILABLE(kernelName) \
    FMF_FALLBACK("ASM_KERNEL_NOT_AVAILABLE_" kernelName)

// Bridge layer fallback
#define FMF_BRIDGE_FALLBACK(bridgeName) \
    FMF_FALLBACK("BRIDGE_FALLBACK_" bridgeName)

// MASM symbol resolution failure
#define FMF_MASM_SYMBOL_NOT_FOUND(symbolName) \
    FMF_FALLBACK("MASM_SYMBOL_NOT_FOUND_" symbolName)

// ============================================================================
// CONDITIONAL EXECUTION TRACKING
// ============================================================================

// Track when a feature path is taken
#define FMF_PATH_TAKEN(pathName) \
    FailureModeFirewall::Instance().ReportRealExecution("PATH_" pathName, __FILE__, __FUNCTION__)

// Track when a fallback path is taken
#define FMF_FALLBACK_TAKEN(pathName, reason) \
    FailureModeFirewall::Instance().ReportFallback("PATH_" pathName "_" reason, __FILE__, __LINE__)

// ============================================================================
// ERROR HANDLING FALLBACK DETECTION
// ============================================================================

// Catch block fallback
#define FMF_CATCH_FALLBACK(exceptionType) \
    FMF_FALLBACK("EXCEPTION_" exceptionType)

// Error code fallback
#define FMF_ERROR_FALLBACK(errorCode) \
    FMF_FALLBACK("ERROR_" errorCode)

// Default case in switch (often indicates unhandled case)
#define FMF_DEFAULT_CASE_FALLBACK(switchName) \
    FMF_FALLBACK("DEFAULT_CASE_" switchName)

// ============================================================================
// INITIALIZATION FALLBACK DETECTION
// ============================================================================

// Initialization failed
#define FMF_INIT_FAILED(component) \
    FMF_FALLBACK("INIT_FAILED_" component)

// Shutdown fallback
#define FMF_SHUTDOWN_FALLBACK(component) \
    FMF_FALLBACK("SHUTDOWN_FALLBACK_" component)

// Configuration fallback
#define FMF_CONFIG_FALLBACK(configKey) \
    FMF_FALLBACK("CONFIG_FALLBACK_" configKey)

// ============================================================================
// RESOURCE FALLBACK DETECTION
// ============================================================================

// Memory allocation fallback
#define FMF_MEMORY_FALLBACK() \
    FMF_FALLBACK("MEMORY_ALLOCATION_FALLBACK")

// File I/O fallback
#define FMF_FILEIO_FALLBACK(operation) \
    FMF_FALLBACK("FILEIO_FALLBACK_" operation)

// Network fallback
#define FMF_NETWORK_FALLBACK(operation) \
    FMF_FALLBACK("NETWORK_FALLBACK_" operation)

// ============================================================================
// GUARD MACROS FOR POLICY ENFORCEMENT
// ============================================================================

// Guard that enforces BLOCK policy for a scope
#define FMF_ENFORCE_BLOCK_SCOPE() \
    FMFPolicyGuard guard(FMFPolicy::BLOCK)

// Guard that enforces WARN policy for a scope
#define FMF_ENFORCE_WARN_SCOPE() \
    FMFPolicyGuard guard(FMFPolicy::WARN)

// Guard that enforces SILENT policy for a scope
#define FMF_ENFORCE_SILENT_SCOPE() \
    FMFPolicyGuard guard(FMFPolicy::SILENT)

// ============================================================================
// COMBINED CHECKS
// ============================================================================

// Check pointer and enforce policy
#define FMF_CHECK_PTR_ENFORCE(ptr, feature) \
    if ((ptr) == nullptr) { \
        FMF_FALLBACK("NULL_POINTER_" #ptr); \
        FMF_STUB_ENTRY(feature); \
        return; \
    }

// Check condition and report fallback
#define FMF_CHECK_CONDITION(condition, reason) \
    if (!(condition)) { \
        FMF_FALLBACK(reason); \
        return; \
    }

// Check condition with return value
#define FMF_CHECK_CONDITION_RET(condition, reason, retval) \
    if (!(condition)) { \
        FMF_FALLBACK(reason); \
        return retval; \
    }
// =============================================================================
// RawrXD-CoreRuntime: Symbol Ownership Enforcement
// =============================================================================
// PURPOSE: Compile-time guards against symbol contamination
// USAGE: Include this header FIRST in all CoreRuntime source files
// =============================================================================

#ifndef RAWRXD_CORE_SYMBOL_OWNERSHIP_H
#define RAWRXD_CORE_SYMBOL_OWNERSHIP_H

// =============================================================================
// DOMAIN IDENTIFICATION MACROS
// =============================================================================
// These identify which symbol domain a compilation unit belongs to

// CoreRuntime domain - the "truth baseline"
#define RAWRXD_DOMAIN_CORE_RUNTIME 1

// UI domain - depends on Core, never the reverse
#define RAWRXD_DOMAIN_UI 2

// ASM domain - low-level kernels, no C++ dependencies
#define RAWRXD_DOMAIN_ASM 3

// Plugin domain - optional, dynamically loaded
#define RAWRXD_DOMAIN_PLUGIN 4

// =============================================================================
// CURRENT DOMAIN ASSERTION (Set by build system per-target)
// =============================================================================

#ifndef RAWRXD_CURRENT_DOMAIN
    #error "RAWRXD_CURRENT_DOMAIN must be defined before including symbol_ownership.h"
#endif

// =============================================================================
// CROSS-DOMAIN DEPENDENCY GUARDS
// =============================================================================
// These prevent accidental inclusion of headers from wrong domains

// CoreRuntime CANNOT depend on UI
#if RAWRXD_CURRENT_DOMAIN == RAWRXD_DOMAIN_CORE_RUNTIME
    #ifdef _WIN32
        // Block accidental Windows UI headers
        #ifdef _WINDOWS_
            #error "[SYMBOL VIOLATION] CoreRuntime cannot include Windows UI headers"
        #endif
    #endif
    
    // Block Qt (if present)
    #ifdef Q_OBJECT
        #error "[SYMBOL VIOLATION] CoreRuntime cannot include Qt headers"
    #endif
    
    // Block QuickJS
    #ifdef JS_VERSION
        #error "[SYMBOL VIOLATION] CoreRuntime cannot include QuickJS headers"
    #endif
#endif

// =============================================================================
// SYMBOL EXPORT/IMPORT MACROS
// =============================================================================
// Explicit visibility control per domain

#if defined(_WIN32)
    #define RAWRXD_CORE_API __declspec(dllexport)
    #define RAWRXD_UI_API __declspec(dllimport)
    #define RAWRXD_ASM_API extern "C"
#elif defined(__GNUC__)
    #define RAWRXD_CORE_API __attribute__((visibility("default")))
    #define RAWRXD_UI_API __attribute__((visibility("hidden")))
    #define RAWRXD_ASM_API extern "C" __attribute__((visibility("default")))
#else
    #define RAWRXD_CORE_API
    #define RAWRXD_UI_API
    #define RAWRXD_ASM_API extern "C"
#endif

// =============================================================================
// SINGLE-DEFINITION RULE ENFORCEMENT
// =============================================================================
// Ensures each symbol is defined in exactly one domain

// Use this macro to mark the "canonical" definition of a symbol
#define RAWRXD_SYMBOL_OWNER(domain, symbol) \
    static_assert(domain == RAWRXD_CURRENT_DOMAIN, \
        "Symbol '" #symbol "' defined in wrong domain")

// Use this macro to mark external references
#define RAWRXD_SYMBOL_REFERENCE(domain, symbol) \
    static_assert(domain != RAWRXD_CURRENT_DOMAIN, \
        "Symbol '" #symbol "' should be defined in its home domain")

// =============================================================================
// STUB POLICY
// =============================================================================
// Stubs are ONLY allowed in debug/test builds, never in CoreRuntime release

#ifdef RAWRXD_CORE_BUILD
    #ifdef RAWRXD_ALLOW_STUBS
        #error "[POLICY VIOLATION] Stubs not allowed in CoreRuntime builds"
    #endif
#endif

// =============================================================================
// FORWARD DECLARATION HELPERS
// =============================================================================
// Use these instead of including full headers

namespace RawrXD {
namespace Core {
    class InferenceEngine;
    class GraphExecutor;
    class MemoryPool;
    class Tensor;
}

// UI namespace - explicitly NOT available to Core
namespace UI {
    #if RAWRXD_CURRENT_DOMAIN == RAWRXD_DOMAIN_CORE_RUNTIME
        class Window;  // Opaque, cannot be used
        class Dialog;  // Opaque, cannot be used
    #endif
}
} // namespace RawrXD

#endif // RAWRXD_CORE_SYMBOL_OWNERSHIP_H

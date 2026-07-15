// =============================================================================
// RawrXD-CoreRuntime: Export Definitions
// =============================================================================

#ifndef RAWRXD_CORE_EXPORT_H
#define RAWRXD_CORE_EXPORT_H

// Simple export macro for building/usage
#ifdef RAWRXD_CORE_BUILDING_DLL
    #ifdef _WIN32
        #define RAWRXD_CORE_EXPORT __declspec(dllexport)
    #else
        #define RAWRXD_CORE_EXPORT __attribute__((visibility("default")))
    #endif
#else
    #ifdef _WIN32
        #define RAWRXD_CORE_EXPORT __declspec(dllimport)
    #else
        #define RAWRXD_CORE_EXPORT
    #endif
#endif

// For static builds, just define as empty
#ifndef RAWRXD_CORE_EXPORT
    #define RAWRXD_CORE_EXPORT
#endif

#endif // RAWRXD_CORE_EXPORT_H

// RawrXDExportTemplate.h.in
// Template for generating DLL export/import headers
// This file is configured by rawrxd_generate_export_header()

#ifndef RawrXDCore_EXPORT_H
#define RawrXDCore_EXPORT_H

// Detect platform and compiler for proper export decorations
#if defined(_WIN32) || defined(__CYGWIN__)
  // Windows (MSVC, MinGW, Clang-CL)
  #ifdef RawrXDCore_EXPORT_EXPORTS
    // Building the DLL - export symbols
    #define RawrXDCore_EXPORT __declspec(dllexport)
  #else
    // Using the DLL - import symbols
    #define RawrXDCore_EXPORT __declspec(dllimport)
  #endif
#elif defined(__GNUC__) && (__GNUC__ >= 4)
  // GCC/Clang on Linux/macOS with visibility support
  #define RawrXDCore_EXPORT __attribute__((visibility("default")))
#else
  // Fallback for other compilers
  #define RawrXDCore_EXPORT
#endif

// Helper for deprecated API
#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef RawrXDCore_EXPORT_EXPORTS
    #define RawrXDCore_EXPORT_DEPRECATED __declspec(deprecated) __declspec(dllexport)
  #else
    #define RawrXDCore_EXPORT_DEPRECATED __declspec(deprecated) __declspec(dllimport)
  #endif
#elif defined(__GNUC__) && (__GNUC__ >= 4)
  #define RawrXDCore_EXPORT_DEPRECATED __attribute__((deprecated)) __attribute__((visibility("default")))
#else
  #define RawrXDCore_EXPORT_DEPRECATED __attribute__((deprecated))
#endif

// Helper for internal (non-exported) symbols
#if defined(_WIN32) || defined(__CYGWIN__)
  #define RawrXDCore_EXPORT_INTERNAL
#elif defined(__GNUC__) && (__GNUC__ >= 4)
  #define RawrXDCore_EXPORT_INTERNAL __attribute__((visibility("hidden")))
#else
  #define RawrXDCore_EXPORT_INTERNAL
#endif

#endif // RawrXDCore_EXPORT_H

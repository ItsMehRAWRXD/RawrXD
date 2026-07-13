//============================================================================
// Sovereign_KernelRegistration.hpp
// Register Phase 7A/7B Kernels with Phase 7C Dispatch Registry
//
// Single function to register all available kernels
//============================================================================

#pragma once

namespace Sovereign {

// Register all Phase 7A/7B kernels with the dispatch registry
// Returns true on success, false on failure
bool RegisterAllKernels();

// Print registration summary
void PrintKernelRegistrationSummary();

} // namespace Sovereign

// C API
extern "C" {
    // Register all kernels (returns 0 on success)
    int Sovereign_RegisterAllKernels(void);
}

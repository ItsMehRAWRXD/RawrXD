//=============================================================================
// GGUFDiagnostics.hpp - Runtime diagnostics for GGUF loading issues
// Helps identify the root cause of page faults and alignment errors
//=============================================================================

#pragma once

#include "GGUFLoader.hpp"
#include <cstdint>
#include <string>

namespace Deep2 {

//=============================================================================
// Diagnostic Result Structure
//=============================================================================
struct GGUFDiagnosticResult {
    bool fileExists = false;
    bool fileReadable = false;
    bool headerValid = false;
    bool metadataValid = false;
    bool tensorsValid = false;
    bool dataLoadable = false;
    
    uint64_t fileSize = 0;
    uint64_t expectedDataSize = 0;
    uint64_t actualDataSize = 0;
    
    int errorCode = 0;
    char errorMessage[512] = {0};
    
    void Print() const;
};

//=============================================================================
// Diagnostic Functions
//=============================================================================
class GGUFDiagnostics {
public:
    // Run full diagnostic suite
    static GGUFDiagnosticResult RunFullDiagnostic(const char* filepath);
    
    // Individual checks
    static bool CheckFileExists(const char* filepath);
    static bool CheckFileReadable(const char* filepath);
    static bool CheckHeaderValid(const char* filepath, char* error = nullptr);
    static bool CheckMetadataValid(const char* filepath, char* error = nullptr);
    static bool CheckTensorsValid(const char* filepath, char* error = nullptr);
    
    // Memory alignment check
    static bool CheckAlignment(void* ptr, size_t alignment = 64);
    
    // Page fault prevention
    static bool ValidateMemoryRange(const void* ptr, size_t size);
    
    // Fix common issues
    static bool FixAlignmentIssues(GGUFLoadResult& result);
};

} // namespace Deep2

#pragma once

//==============================================================================
// CompilerServiceAdapter.h - Bridge to CompilerAgent
// Phase 15: Complete System Unification
//
// This adapter connects the CompilerAgent (src/agent/CompilerAgent.h)
// to the existing ICompilerService interface in RawrXDHost.h
//==============================================================================

#include "RawrXDHost.h"
#include "../agent/CompilerAgent.h"
#include "../context/ContextEngine.h"
#include <memory>

namespace RawrXD {
namespace Unified {

//==============================================================================
// Compiler Service Adapter
// Implements ICompilerService using CompilerAgent backend
//==============================================================================
class CompilerServiceAdapter : public ICompilerService {
public:
    CompilerServiceAdapter();
    ~CompilerServiceAdapter() override;

    // Initialize with AI provider for autonomous fixing
    bool Initialize() override;
    bool InitializeWithAI(AIProvider* ai);

    // Compile with optional AI-assisted fixing
    CompileResult Compile(const CompileRequest& req) override;
    
    // Compile with autonomous fix loop
    CompileResult CompileWithAIFix(const CompileRequest& req, int maxIterations = 3);

    // Get supported languages
    std::vector<std::string> GetSupportedLanguages() override;

    // Access to context engine for project awareness
    ContextEngine* GetContextEngine() { return &contextEngine_; }

private:
    std::unique_ptr<CompilerAgent> compilerAgent_;
    ContextEngine contextEngine_;
    AIProvider* aiProvider_ = nullptr;
    bool initialized_ = false;
    
    // Language to compiler mapping
    std::string GetCompilerForLanguage(const std::string& language);
};

} // namespace Unified
} // namespace RawrXD

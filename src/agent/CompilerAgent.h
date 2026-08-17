#pragma once
#include "../core/AIProvider.h"
#include "../core/EventBus.h"
#include "../context/ContextEngine.h"
#include <string>

namespace RawrXD {

class CompilerAgent {
public:
    CompilerAgent(AIProvider* ai, ContextEngine* context);

    bool CompileAndFix(const std::string& sourceFile, 
                       const std::string& compilerArgs,
                       int maxIterations = 3);

private:
    std::string RunCompiler(const std::string& sourceFile, const std::string& args);
    std::string ExtractErrors(const std::string& compilerOutput);
    bool ApplyPatch(const std::string& sourceFile, const std::string& patch);

    AIProvider* ai_;
    ContextEngine* context_;
    int iteration_;
};

} // namespace RawrXD

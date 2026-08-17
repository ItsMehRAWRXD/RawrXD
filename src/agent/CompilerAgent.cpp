#include "CompilerAgent.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdio>

namespace RawrXD {

CompilerAgent::CompilerAgent(AIProvider* ai, ContextEngine* context)
    : ai_(ai), context_(context), iteration_(0) {}

bool CompilerAgent::CompileAndFix(const std::string& sourceFile,
                                  const std::string& compilerArgs,
                                  int maxIterations) {
    for (int i = 0; i < maxIterations; i++) {
        iteration_ = i + 1;
        
        std::string output = RunCompiler(sourceFile, compilerArgs);
        std::string errors = ExtractErrors(output);
        
        if (errors.empty()) {
            return true; // Compilation successful
        }
        
        // Feed errors to AI for fix
        std::ifstream file(sourceFile);
        std::string source((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();
        
        AIRequest request;
        request.type = AIRequestType::Debug;
        request.prompt = source;
        request.context = errors;
        request.maxTokens = 512;
        
        AIResponse response = ai_->Execute(request);
        
        if (response.success && !response.text.empty()) {
            if (ApplyPatch(sourceFile, response.text)) {
                continue; // Try compiling again
            }
        }
        break;
    }
    return false;
}

std::string CompilerAgent::RunCompiler(const std::string& sourceFile, 
                                       const std::string& args) {
    std::string cmd = "cl.exe " + args + " \"" + sourceFile + "\" 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "";
    
    std::ostringstream result;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result << buffer;
    }
    _pclose(pipe);
    return result.str();
}

std::string CompilerAgent::ExtractErrors(const std::string& compilerOutput) {
    std::istringstream stream(compilerOutput);
    std::string line;
    std::ostringstream errors;
    
    while (std::getline(stream, line)) {
        if (line.find("error") != std::string::npos ||
            line.find("warning") != std::string::npos) {
            errors << line << "\n";
        }
    }
    return errors.str();
}

bool CompilerAgent::ApplyPatch(const std::string& sourceFile, 
                               const std::string& patch) {
    // Extract code block from AI response
    std::string code = patch;
    size_t start = code.find("```");
    if (start != std::string::npos) {
        start = code.find('\n', start);
        size_t end = code.find("```", start);
        if (end != std::string::npos) {
            code = code.substr(start, end - start);
        }
    }
    
    if (!code.empty()) {
        std::ofstream file(sourceFile);
        file << code;
        file.close();
        return true;
    }
    return false;
}

} // namespace RawrXD

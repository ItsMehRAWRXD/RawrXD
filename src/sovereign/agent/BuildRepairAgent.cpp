// ============================================================================
// BuildRepairAgent.cpp - Autonomous Build Repair Implementation
// ============================================================================

#include "BuildRepairAgent.hpp"
#include <fstream>
#include <sstream>
#include <regex>
#include <cstdio>
#include <array>
#include <iostream>

namespace Sovereign {

BuildRepairAgent::BuildRepairAgent() = default;
BuildRepairAgent::~BuildRepairAgent() = default;

BuildResult BuildRepairAgent::RunBuild(const std::string& buildCommand, const std::string& workspace) {
    BuildResult result;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::string output = ExecuteCommand("cd \"" + workspace + "\" && " + buildCommand + " 2>&1");
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    result.output = output;
    
    // Parse errors
    auto errors = ParseBuildOutput(output);
    for (const auto& e : errors) {
        if (e.type == "error") result.errors.push_back(e);
        else result.warnings.push_back(e);
    }
    
    result.success = result.errors.empty();
    result.exitCode = result.success ? 0 : 1;
    
    return result;
}

BuildResult BuildRepairAgent::RunCMake(const std::string& workspace) {
    return RunBuild("cmake -B build -S .", workspace);
}

BuildResult BuildRepairAgent::RunNinja(const std::string& workspace) {
    return RunBuild("ninja -C build", workspace);
}

std::vector<BuildError> BuildRepairAgent::ParseBuildOutput(const std::string& output) {
    auto msvcErrors = ParseMSVCErrors(output);
    if (!msvcErrors.empty()) return msvcErrors;
    
    auto gccErrors = ParseGCCErrors(output);
    if (!gccErrors.empty()) return gccErrors;
    
    auto clangErrors = ParseClangErrors(output);
    if (!clangErrors.empty()) return clangErrors;
    
    return {};
}

std::vector<BuildError> BuildRepairAgent::ParseMSVCErrors(const std::string& output) {
    std::vector<BuildError> errors;
    std::istringstream stream(output);
    std::string line;
    
    // MSVC format: file(line,column): error/warning CXXXX: message
    std::regex msvcPattern(R"((.+?)\((\d+)(?:,(\d+))?\)\s*:\s*(error|warning)\s+(C\d+)\s*:\s*(.+))");
    
    while (std::getline(stream, line)) {
        std::smatch match;
        if (std::regex_match(line, match, msvcPattern)) {
            BuildError error;
            error.file = match[1];
            error.line = std::stoi(match[2]);
            error.column = match[3].matched ? std::stoi(match[3]) : 0;
            error.type = match[4];
            error.message = match[6];
            error.code = line;
            errors.push_back(error);
        }
    }
    
    return errors;
}

std::vector<BuildError> BuildRepairAgent::ParseGCCErrors(const std::string& output) {
    std::vector<BuildError> errors;
    std::istringstream stream(output);
    std::string line;
    
    // GCC format: file:line:column: error/warning: message
    std::regex gccPattern(R"((.+?):(\d+):(\d+):\s*(error|warning):\s*(.+))");
    
    while (std::getline(stream, line)) {
        std::smatch match;
        if (std::regex_match(line, match, gccPattern)) {
            BuildError error;
            error.file = match[1];
            error.line = std::stoi(match[2]);
            error.column = std::stoi(match[3]);
            error.type = match[4];
            error.message = match[5];
            error.code = line;
            errors.push_back(error);
        }
    }
    
    return errors;
}

std::vector<BuildError> BuildRepairAgent::ParseClangErrors(const std::string& output) {
    return ParseGCCErrors(output); // Same format
}

std::vector<FixStrategy> BuildRepairAgent::GenerateFixes(const std::vector<BuildError>& errors) {
    std::vector<FixStrategy> fixes;
    
    for (const auto& error : errors) {
        FixStrategy fix;
        
        if (error.message.find("no such file") != std::string::npos ||
            error.message.find("cannot open source file") != std::string::npos ||
            error.message.find("include") != std::string::npos) {
            fix = FixIncludeError(error);
        } else if (error.message.find("syntax") != std::string::npos ||
                   error.message.find("expected") != std::string::npos ||
                   error.message.find("unexpected") != std::string::npos) {
            fix = FixSyntaxError(error);
        } else if (error.message.find("unresolved external symbol") != std::string::npos ||
                   error.message.find("undefined reference") != std::string::npos) {
            fix = FixLinkerError(error);
        } else if (error.message.find("type") != std::string::npos ||
                   error.message.find("cannot convert") != std::string::npos) {
            fix = FixTypeError(error);
        } else if (error.message.find("undeclared") != std::string::npos ||
                   error.message.find("not declared") != std::string::npos) {
            fix = FixUndefinedSymbol(error);
        }
        
        if (!fix.type.empty()) {
            fixes.push_back(fix);
        }
    }
    
    return fixes;
}

FixStrategy BuildRepairAgent::FixIncludeError(const BuildError& error) {
    FixStrategy fix;
    fix.type = "include";
    fix.description = "Fix missing include";
    fix.file = error.file;
    fix.line = error.line;
    fix.confidence = 70;
    
    // Extract missing header name
    std::regex headerPattern(R"(['"<]([^'">]+)[>'">])");
    std::smatch match;
    if (std::regex_search(error.message, match, headerPattern)) {
        fix.oldText = match[0].str();
        fix.newText = "#include <" + match[1].str() + ">";
    }
    
    return fix;
}

FixStrategy BuildRepairAgent::FixSyntaxError(const BuildError& error) {
    FixStrategy fix;
    fix.type = "syntax";
    fix.description = "Fix syntax error";
    fix.file = error.file;
    fix.line = error.line;
    fix.confidence = 50;
    return fix;
}

FixStrategy BuildRepairAgent::FixLinkerError(const BuildError& error) {
    FixStrategy fix;
    fix.type = "linker";
    fix.description = "Fix linker error - add missing source or library";
    fix.file = error.file;
    fix.confidence = 60;
    return fix;
}

FixStrategy BuildRepairAgent::FixTypeError(const BuildError& error) {
    FixStrategy fix;
    fix.type = "type";
    fix.description = "Fix type mismatch";
    fix.file = error.file;
    fix.line = error.line;
    fix.confidence = 40;
    return fix;
}

FixStrategy BuildRepairAgent::FixUndefinedSymbol(const BuildError& error) {
    FixStrategy fix;
    fix.type = "undefined";
    fix.description = "Fix undefined symbol - add forward declaration or include";
    fix.file = error.file;
    fix.line = error.line;
    fix.confidence = 55;
    return fix;
}

bool BuildRepairAgent::ApplyFix(const FixStrategy& fix) {
    totalRepairs_++;
    
    if (fix.type == "include" && !fix.file.empty()) {
        std::string content = ReadFile(fix.file);
        if (content.empty()) return false;
        
        // Add include at top of file
        std::string newContent = fix.newText + "\n" + content;
        if (WriteFile(fix.file, newContent)) {
            successfulRepairs_++;
            return true;
        }
    }
    
    return false;
}

BuildResult BuildRepairAgent::BuildAndRepair(const std::string& workspace, int maxAttempts) {
    BuildResult result;
    
    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        result = RunNinja(workspace);
        
        if (result.success) {
            std::cout << "[BuildRepairAgent] Build succeeded on attempt " << (attempt + 1) << "\n";
            return result;
        }
        
        std::cout << "[BuildRepairAgent] Build failed on attempt " << (attempt + 1) 
                  << " (" << result.errors.size() << " errors)\n";
        
        // Generate and apply fixes
        auto fixes = GenerateFixes(result.errors);
        if (fixes.empty()) break;
        
        bool anyFixApplied = false;
        for (const auto& fix : fixes) {
            if (ApplyFix(fix)) {
                std::cout << "[BuildRepairAgent] Applied fix: " << fix.description << "\n";
                anyFixApplied = true;
            }
        }
        
        if (!anyFixApplied) break;
    }
    
    return result;
}

double BuildRepairAgent::GetSuccessRate() const {
    return totalRepairs_ > 0 ? (100.0 * successfulRepairs_ / totalRepairs_) : 0.0;
}

std::string BuildRepairAgent::ExecuteCommand(const std::string& command) {
    std::array<char, 4096> buffer;
    std::string result;
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) return "";
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    _pclose(pipe);
    
    return result;
}

std::string BuildRepairAgent::ReadFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) return "";
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

bool BuildRepairAgent::WriteFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) return false;
    file << content;
    return true;
}

} // namespace Sovereign

#pragma once
#include <string>
#include <vector>
#include <windows.h>

struct CompilerInfo {
    std::string name;
    std::string displayName;
    std::string version;
    std::string category;
    std::string path;
};

class CompilerIntegration {
public:
    CompilerIntegration();
    ~CompilerIntegration();
    
    // Initialize with compiler registry
    bool Initialize();
    
    // Execute a compiler and capture output
    bool ExecuteCompiler(const std::string& compilerName, 
                       const std::string& sourceFile,
                       std::string& output,
                       std::string& error);
    
    // Get list of available compilers
    std::vector<CompilerInfo> GetCompilers() const;
    std::vector<CompilerInfo> GetCompilersByCategory(const std::string& category) const;
    
    // Get compiler by name
    bool GetCompiler(const std::string& name, CompilerInfo& info) const;
    
    // Menu integration
    void PopulateBuildMenu(void* menuHandle);
    void PopulateCompilerMenu(void* menuHandle);
    
private:
    std::vector<CompilerInfo> m_compilers;
    bool m_initialized;
    
    bool RunProcess(const std::string& exePath, 
                    const std::string& args,
                    std::string& output,
                    std::string& error,
                    DWORD& exitCode);
};

// Global integration functions
bool IntegrateCompilersIntoCLI();
bool IntegrateCompilersIntoGUI();
void ShowCompilerStatus();

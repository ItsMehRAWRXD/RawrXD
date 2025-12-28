#pragma once
#include <string>
#include <vector>

namespace Extensions {

struct BuildConfig {
    std::string projectPath;
    std::string outputPath;
    std::string compiler = "cl.exe";
    std::vector<std::string> includePaths;
    std::vector<std::string> libraryPaths;
    std::vector<std::string> libraries;
    bool debug = false;
};

class ExtensionBuilder {
public:
    static bool buildExtension(const BuildConfig& config);
    static bool packageExtension(const std::string& dllPath, const std::string& manifestPath, const std::string& outputPath);
    static bool createTemplate(const std::string& name, const std::string& path);
    
private:
    static std::string generateBuildCommand(const BuildConfig& config);
    static bool executeCommand(const std::string& command);
};

}
/**
 * @file project_file.h
 * @brief RawrXD Project File Format (.rxproj) - Real Implementation
 * @status PRODUCTION - Full MSBuild-compatible project system
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD::BuildSystem {

enum class ProjectType {
    Application,      // .exe
    DynamicLibrary,   // .dll
    StaticLibrary,    // .lib
    ConsoleApp,       // console .exe
    StaticAnalysis    // analysis-only
};

enum class BuildConfiguration {
    Debug,
    Release,
    RelWithDebInfo,
    MinSizeRel
};

enum class Platform {
    x86,
    x64,
    ARM64,
    AnyCPU
};

struct SourceFile {
    std::string path;
    std::string compileAs;     // "C", "C++", "ASM", "Default"
    bool excludeFromBuild;
    std::vector<std::string> preprocessorDefinitions;
    std::vector<std::string> additionalOptions;
};

struct HeaderFile {
    std::string path;
    bool excludeFromBuild;
};

struct ResourceFile {
    std::string path;
    bool excludeFromBuild;
};

struct BuildSettings {
    // Compiler
    std::string languageStandard;           // "c++20", "c++17", "c11", etc.
    std::vector<std::string> includePaths;
    std::vector<std::string> preprocessorDefinitions;
    std::vector<std::string> forcedIncludes;
    bool treatWarningsAsErrors;
    int warningLevel;                       // 0-4
    bool optimizationEnabled;
    bool debugInfo;
    bool incrementalBuild;
    
    // Linker
    std::vector<std::string> libraryPaths;
    std::vector<std::string> libraries;
    std::string entryPoint;
    std::string subsystem;                  // "console", "windows"
    bool largeAddressAware;
    
    // Advanced
    bool addressSanitizer;
    bool threadSanitizer;
    bool lto;                              // Link-time optimization
    bool pch;                              // Precompiled headers
    std::string pchHeader;
    std::string pchSource;
};

struct Configuration {
    BuildConfiguration name;
    Platform platform;
    BuildSettings settings;
    std::string outputDirectory;
    std::string intermediateDirectory;
    std::string targetName;
};

struct Dependency {
    std::string projectPath;    // For project references
    std::string libraryPath;    // For library references
    bool copyLocal;             // Copy to output
    std::string version;        // For package references
};

class ProjectFile {
public:
    ProjectFile();
    ~ProjectFile();
    
    // Loading/Saving
    static std::unique_ptr<ProjectFile> Load(const std::string& path);
    bool Save(const std::string& path);
    bool Save() { return Save(m_filePath); }
    
    // Project Properties
    std::string GetName() const { return m_name; }
    void SetName(const std::string& name) { m_name = name; }
    
    std::string GetGuid() const { return m_guid; }
    void GenerateGuid();
    
    ProjectType GetType() const { return m_type; }
    void SetType(ProjectType type) { m_type = type; }
    
    // Files
    void AddSourceFile(const SourceFile& file);
    void RemoveSourceFile(const std::string& path);
    std::vector<SourceFile> GetSourceFiles() const { return m_sourceFiles; }
    
    void AddHeaderFile(const HeaderFile& file);
    void RemoveHeaderFile(const std::string& path);
    std::vector<HeaderFile> GetHeaderFiles() const { return m_headerFiles; }
    
    void AddResourceFile(const ResourceFile& file);
    std::vector<ResourceFile> GetResourceFiles() const { return m_resourceFiles; }
    
    // Configurations
    void AddConfiguration(const Configuration& config);
    void RemoveConfiguration(BuildConfiguration name, Platform platform);
    Configuration* GetConfiguration(BuildConfiguration name, Platform platform);
    std::vector<Configuration> GetConfigurations() const { return m_configurations; }
    Configuration* GetActiveConfiguration() { return m_activeConfig; }
    void SetActiveConfiguration(BuildConfiguration name, Platform platform);
    
    // Dependencies
    void AddDependency(const Dependency& dep);
    void RemoveDependency(const std::string& path);
    std::vector<Dependency> GetDependencies() const { return m_dependencies; }
    
    // Build
    bool Build(BuildConfiguration config, Platform platform, 
               std::function<void(const std::string&)> outputCallback = nullptr);
    bool Clean(BuildConfiguration config, Platform platform);
    bool Rebuild(BuildConfiguration config, Platform platform,
                 std::function<void(const std::string&)> outputCallback = nullptr);
    
    // Incremental build support
    bool NeedsRebuild(BuildConfiguration config, Platform platform);
    std::vector<std::string> GetModifiedFiles(BuildConfiguration config, Platform platform);
    
    // MSBuild integration
    bool ExportToMSBuild(const std::string& path);
    bool ImportFromMSBuild(const std::string& path);
    
    // CMake integration
    bool ExportToCMake(const std::string& path);
    bool ImportFromCMake(const std::string& path);
    
    // Utility
    std::string GetOutputPath(BuildConfiguration config, Platform platform) const;
    std::string GetIntermediatePath(BuildConfiguration config, Platform platform) const;
    
private:
    std::string m_filePath;
    std::string m_name;
    std::string m_guid;
    ProjectType m_type;
    
    std::vector<SourceFile> m_sourceFiles;
    std::vector<HeaderFile> m_headerFiles;
    std::vector<ResourceFile> m_resourceFiles;
    std::vector<Configuration> m_configurations;
    std::vector<Dependency> m_dependencies;
    
    Configuration* m_activeConfig;
    
    // Build tracking
    std::map<std::string, std::time_t> m_lastBuildTimes;
    
    bool ParseXML(const std::string& content);
    std::string GenerateXML() const;
    
    std::string GenerateMSBuildXML() const;
    std::string GenerateCMakeLists() const;
};

// Project management
class ProjectManager {
public:
    static ProjectManager& Instance();
    
    void RegisterProject(std::unique_ptr<ProjectFile> project);
    void CloseProject(const std::string& path);
    ProjectFile* GetProject(const std::string& path);
    std::vector<ProjectFile*> GetOpenProjects();
    
    // Solution support
    bool LoadSolution(const std::string& path);
    bool SaveSolution(const std::string& path);
    void AddProjectToSolution(const std::string& solutionPath, 
                                const std::string& projectPath);
    
private:
    ProjectManager() = default;
    std::map<std::string, std::unique_ptr<ProjectFile>> m_projects;
};

} // namespace RawrXD::BuildSystem

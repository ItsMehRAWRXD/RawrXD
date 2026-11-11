// Win32IDE_Project.h
// Project system header - NO MORE SCAFFOLDING

#pragma once
#include <windows.h>
#include <string>
#include <vector>

// Project types
enum ProjectType {
    PROJECT_EXECUTABLE,
    PROJECT_LIBRARY,
    PROJECT_DLL
};

// Build callback interface
class IBuildCallback {
public:
    virtual void OnBuildStart() = 0;
    virtual void OnBuildProgress(const wchar_t* message, int percent) = 0;
    virtual void OnBuildError(const wchar_t* error) = 0;
    virtual void OnBuildComplete(bool success) = 0;
};

// Project class
class RxProject {
public:
    RxProject() : m_type(PROJECT_EXECUTABLE), m_isLoaded(false), m_isModified(false) {}
    ~RxProject() {}

    // Load/Save
    bool LoadFromFile(const wchar_t* filePath);
    bool SaveToFile(const wchar_t* filePath = nullptr) const;
    bool Save() const { return SaveToFile(nullptr); }

    // Build
    bool Build(IBuildCallback* callback = nullptr);

    // Getters
    const wchar_t* GetName() const { return m_name.c_str(); }
    const wchar_t* GetVersion() const { return m_version.c_str(); }
    const wchar_t* GetFilePath() const { return m_filePath.c_str(); }
    ProjectType GetType() const { return m_type; }
    const wchar_t* GetOutput() const { return m_output.c_str(); }
    size_t GetSourceCount() const { return m_sources.size(); }
    const wchar_t* GetSource(size_t index) const { return m_sources[index].c_str(); }
    size_t GetHeaderCount() const { return m_headers.size(); }
    const wchar_t* GetHeader(size_t index) const { return m_headers[index].c_str(); }
    bool IsLoaded() const { return m_isLoaded; }
    bool IsModified() const { return m_isModified; }

    // Setters
    void SetName(const wchar_t* name) { m_name = name; m_isModified = true; }
    void SetVersion(const wchar_t* version) { m_version = version; m_isModified = true; }
    void SetType(ProjectType type) { m_type = type; m_isModified = true; }
    void SetOutput(const wchar_t* output) { m_output = output; m_isModified = true; }
    void SetFilePath(const wchar_t* path) { m_filePath = path; }
    void AddSource(const wchar_t* source) { m_sources.push_back(source); m_isModified = true; }
    void AddHeader(const wchar_t* header) { m_headers.push_back(header); m_isModified = true; }
    void ClearModified() { m_isModified = false; }

private:
    std::wstring m_name;
    std::wstring m_version;
    std::wstring m_filePath;
    std::wstring m_output;
    std::wstring m_compilerFlags;
    ProjectType m_type;
    std::vector<std::wstring> m_sources;
    std::vector<std::wstring> m_headers;
    bool m_isLoaded;
    bool m_isModified;

    bool ParseJSON(const std::string& json);
    std::string GenerateJSON() const;
};

// Project manager (singleton)
class ProjectManager {
public:
    ProjectManager();
    ~ProjectManager();

    // Project operations
    bool NewProject(const wchar_t* name, const wchar_t* location, ProjectType type);
    bool OpenProject(const wchar_t* filePath);
    bool SaveProject();
    bool SaveProjectAs(const wchar_t* filePath);
    void CloseProject();

    // Build
    bool BuildProject(IBuildCallback* callback = nullptr);

    // Query
    bool IsProjectOpen() const;
    RxProject* GetCurrentProject() { return m_currentProject; }
    const wchar_t* GetProjectName() const;
    const wchar_t* GetProjectFilePath() const;

    // Singleton access
    static ProjectManager& GetInstance() {
        static ProjectManager instance;
        return instance;
    }

private:
    RxProject* m_currentProject;
};

// Convenience macro
#define g_ProjectManager ProjectManager::GetInstance()

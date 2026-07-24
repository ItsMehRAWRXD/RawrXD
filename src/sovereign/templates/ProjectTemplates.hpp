// ============================================================================
// ProjectTemplates.hpp - Project Templates & Scaffolding System
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct ProjectTemplate {
    std::string name;
    std::string description;
    std::string language;
    std::string buildSystem;
    std::vector<std::string> files;
    std::vector<std::string> dependencies;
    std::unordered_map<std::string, std::string> placeholders;
};

struct ScaffoldedProject {
    std::string path;
    std::string name;
    std::vector<std::string> createdFiles;
    bool success;
    std::string error;
};

class ProjectTemplates {
public:
    ProjectTemplates();
    ~ProjectTemplates();

    void Initialize();
    void Shutdown();

    void AddTemplate(const ProjectTemplate& tmpl);
    void RemoveTemplate(const std::string& name);
    std::vector<ProjectTemplate> GetTemplates() const;
    ProjectTemplate GetTemplate(const std::string& name) const;
    bool HasTemplate(const std::string& name) const;

    ScaffoldedProject Scaffold(const std::string& templateName, const std::string& outputPath, 
                                const std::unordered_map<std::string, std::string>& values);
    ScaffoldedProject ScaffoldFromUrl(const std::string& url, const std::string& outputPath);

    void AddDefaultTemplates();

    struct TemplateStats {
        uint64_t totalTemplates;
        uint64_t totalScaffolds;
        uint64_t successfulScaffolds;
        uint64_t failedScaffolds;
    };
    TemplateStats GetStats() const { return stats_; }

private:
    std::unordered_map<std::string, ProjectTemplate> templates_;
    TemplateStats stats_;
    mutable std::mutex mutex_;
    
    std::string ReplacePlaceholders(const std::string& content, const std::unordered_map<std::string, std::string>& values) const;
    bool CreateFile(const std::string& path, const std::string& content);
};

} // namespace Sovereign

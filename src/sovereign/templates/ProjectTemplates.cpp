// ============================================================================
// ProjectTemplates.cpp - Project Templates & Scaffolding Implementation
// ============================================================================

#include "ProjectTemplates.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

namespace Sovereign {

ProjectTemplates::ProjectTemplates() = default;
ProjectTemplates::~ProjectTemplates() = default;

void ProjectTemplates::Initialize() {
    AddDefaultTemplates();
}

void ProjectTemplates::Shutdown() {
    templates_.clear();
}

void ProjectTemplates::AddTemplate(const ProjectTemplate& tmpl) {
    std::lock_guard<std::mutex> lock(mutex_);
    templates_[tmpl.name] = tmpl;
    stats_.totalTemplates++;
}

void ProjectTemplates::RemoveTemplate(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    templates_.erase(name);
}

std::vector<ProjectTemplate> ProjectTemplates::GetTemplates() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ProjectTemplate> result;
    for (const auto& [name, tmpl] : templates_) {
        result.push_back(tmpl);
    }
    return result;
}

ProjectTemplate ProjectTemplates::GetTemplate(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = templates_.find(name);
    if (it != templates_.end()) return it->second;
    return {};
}

bool ProjectTemplates::HasTemplate(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return templates_.find(name) != templates_.end();
}

ScaffoldedProject ProjectTemplates::Scaffold(const std::string& templateName, const std::string& outputPath,
                                               const std::unordered_map<std::string, std::string>& values) {
    std::lock_guard<std::mutex> lock(mutex_);
    ScaffoldedProject result;
    result.path = outputPath;
    result.success = false;
    
    auto it = templates_.find(templateName);
    if (it == templates_.end()) {
        result.error = "Template not found: " + templateName;
        stats_.failedScaffolds++;
        return result;
    }
    
    const auto& tmpl = it->second;
    fs::create_directories(outputPath);
    
    for (const auto& file : tmpl.files) {
        std::string content = ReplacePlaceholders(file, values);
        std::string filePath = outputPath + "/" + file;
        
        if (CreateFile(filePath, content)) {
            result.createdFiles.push_back(filePath);
        }
    }
    
    result.success = true;
    result.name = templateName;
    stats_.totalScaffolds++;
    stats_.successfulScaffolds++;
    
    return result;
}

void ProjectTemplates::AddDefaultTemplates() {
    // C++ Console App
    ProjectTemplate cppConsole;
    cppConsole.name = "cpp-console";
    cppConsole.description = "C++ Console Application with CMake";
    cppConsole.language = "cpp";
    cppConsole.buildSystem = "cmake";
    cppConsole.placeholders = {{"project_name", "MyProject"}, {"author", "Author"}};
    AddTemplate(cppConsole);
    
    // C++ Library
    ProjectTemplate cppLib;
    cppLib.name = "cpp-library";
    cppLib.description = "C++ Static/Shared Library with CMake";
    cppLib.language = "cpp";
    cppLib.buildSystem = "cmake";
    AddTemplate(cppLib);
    
    // Python Package
    ProjectTemplate pyPkg;
    pyPkg.name = "python-package";
    pyPkg.description = "Python Package with setup.py";
    pyPkg.language = "python";
    pyPkg.buildSystem = "setuptools";
    AddTemplate(pyPkg);
    
    // Empty project
    ProjectTemplate empty;
    empty.name = "empty";
    empty.description = "Empty project directory";
    empty.language = "any";
    empty.buildSystem = "none";
    AddTemplate(empty);
}

std::string ProjectTemplates::ReplacePlaceholders(const std::string& content, 
                                                    const std::unordered_map<std::string, std::string>& values) const {
    std::string result = content;
    for (const auto& [key, value] : values) {
        size_t pos = 0;
        while ((pos = result.find("{{" + key + "}}", pos)) != std::string::npos) {
            result.replace(pos, key.size() + 4, value);
            pos += value.size();
        }
    }
    return result;
}

bool ProjectTemplates::CreateFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) return false;
    file << content;
    return true;
}

} // namespace Sovereign

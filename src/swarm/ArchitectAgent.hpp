#pragma once

#include "SwarmOrchestrator.hpp"
#include <vector>
#include <string>
#include <map>

namespace rawrxd {
namespace swarm {

// Database schema design
struct DatabaseSchema {
    struct Table {
        std::string name;
        std::vector<std::pair<std::string, std::string>> columns; // name, type
        std::vector<std::string> primaryKeys;
        std::vector<std::pair<std::string, std::string>> foreignKeys;
        std::vector<std::string> indexes;
    };
    
    std::vector<Table> tables;
    std::string databaseType; // "postgresql", "mysql", "sqlite", "mongodb"
};

// Technology stack selection
struct TechStack {
    std::string frontendFramework;    // "react", "vue", "angular", "svelte"
    std::string backendFramework;     // "express", "fastapi", "spring", "dotnet"
    std::string database;             // "postgresql", "mysql", "mongodb"
    std::string styling;              // "tailwind", "styled-components", "scss"
    std::string stateManagement;      // "redux", "zustand", "react-query"
    std::string buildTool;            // "vite", "webpack", "parcel"
    std::vector<std::string> additionalLibs;
};

// Project structure
struct ProjectStructure {
    struct Directory {
        std::string name;
        std::vector<Directory> subdirectories;
        std::vector<std::string> files;
    };
    
    Directory root;
    std::map<std::string, std::string> fileTemplates; // path -> content template
};

// The Architect - Designs the entire system
class ArchitectAgent {
public:
    struct DesignRequest {
        std::string projectName;
        std::string description;
        std::vector<std::string> features;
        std::string targetPlatform; // "web", "desktop", "mobile", "fullstack"
        std::string scale;          // "startup", "enterprise", "personal"
        std::vector<std::string> constraints;
    };
    
    struct SystemDesign {
        TechStack stack;
        DatabaseSchema schema;
        ProjectStructure structure;
        std::vector<std::string> apiEndpoints;
        std::map<std::string, std::string> serviceArchitecture;
        std::string deploymentStrategy;
    };
    
    // Main design function
    SystemDesign designSystem(const DesignRequest& request);
    
    // Component designers
    TechStack selectTechStack(const DesignRequest& request);
    DatabaseSchema designDatabase(const DesignRequest& request, const TechStack& stack);
    ProjectStructure createProjectTree(const DesignRequest& request, const TechStack& stack);
    std::vector<std::string> designAPI(const DesignRequest& request, const DatabaseSchema& schema);
    
    // Stack recommendations based on requirements
    std::string recommendFrontend(const std::vector<std::string>& features);
    std::string recommendBackend(const std::vector<std::string>& features, const std::string& frontend);
    std::string recommendDatabase(const std::vector<std::string>& features, const std::string& scale);
    
    // Generate configuration files
    std::string generatePackageJson(const TechStack& stack, const std::string& projectName);
    std::string generateTsConfig(const TechStack& stack);
    std::string generateDockerfile(const TechStack& stack);
    std::string generateDockerCompose(const TechStack& stack, const DatabaseSchema& schema);
    std::string generateEnvFile(const TechStack& stack, const DatabaseSchema& schema);
    
    // Architecture documentation
    std::string generateArchitectureDoc(const SystemDesign& design);
    std::string generateERDiagram(const DatabaseSchema& schema);
    std::string generateAPIDocumentation(const std::vector<std::string>& endpoints);
};

} // namespace swarm
} // namespace rawrxd

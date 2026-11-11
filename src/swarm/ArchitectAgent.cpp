// ============================================================================
// ArchitectAgent.cpp - Kimi K2.6 300-Agent Swarm
// The Architect - 1 agent that designs the entire system
// ============================================================================

#include "ArchitectAgent.hpp"
#include <sstream>
#include <algorithm>
#include <random>

namespace rawrxd {
namespace swarm {

// Main design function
ArchitectAgent::SystemDesign ArchitectAgent::designSystem(const DesignRequest& request) {
    SystemDesign design;
    
    // Step 1: Select technology stack
    design.stack = selectTechStack(request);
    
    // Step 2: Design database schema
    design.schema = designDatabase(request, design.stack);
    
    // Step 3: Create project structure
    design.structure = createProjectTree(request, design.stack);
    
    // Step 4: Design API endpoints
    design.apiEndpoints = designAPI(request, design.schema);
    
    // Step 5: Define service architecture
    design.serviceArchitecture = {
        {"api-gateway", "Entry point for all client requests"},
        {"auth-service", "Authentication and authorization"},
        {"user-service", "User management and profiles"},
        {"core-service", "Main business logic"},
        {"notification-service", "Email, SMS, push notifications"},
        {"file-service", "File upload and storage"}
    };
    
    // Step 6: Define deployment strategy
    design.deploymentStrategy = "docker-compose";
    if (request.scale == "enterprise") {
        design.deploymentStrategy = "kubernetes";
    }
    
    return design;
}

// Technology stack selection
TechStack ArchitectAgent::selectTechStack(const DesignRequest& request) {
    TechStack stack;
    
    // Frontend framework
    stack.frontendFramework = recommendFrontend(request.features);
    
    // Backend framework
    stack.backendFramework = recommendBackend(request.features, stack.frontendFramework);
    
    // Database
    stack.database = recommendDatabase(request.features, request.scale);
    
    // Styling
    if (std::find(request.features.begin(), request.features.end(), "dark-mode") != request.features.end()) {
        stack.styling = "tailwind";
    } else {
        stack.styling = "styled-components";
    }
    
    // State management
    if (stack.frontendFramework == "react") {
        stack.stateManagement = "zustand";
    } else if (stack.frontendFramework == "vue") {
        stack.stateManagement = "pinia";
    } else {
        stack.stateManagement = "redux";
    }
    
    // Build tool
    stack.buildTool = "vite";
    
    // Additional libraries
    stack.additionalLibs = {
        "axios", "react-query", "date-fns", "lodash",
        "zod", "react-hook-form", "react-router-dom"
    };
    
    return stack;
}

// Database schema design
DatabaseSchema ArchitectAgent::designDatabase(const DesignRequest& request, const TechStack& stack) {
    DatabaseSchema schema;
    schema.databaseType = stack.database;
    
    // Users table
    DatabaseSchema::Table users;
    users.name = "users";
    users.columns = {
        {"id", "uuid"}, {"email", "varchar(255)"}, {"password_hash", "varchar(255)"},
        {"first_name", "varchar(100)"}, {"last_name", "varchar(100)"},
        {"role", "varchar(50)"}, {"created_at", "timestamp"}, {"updated_at", "timestamp"}
    };
    users.primaryKeys = {"id"};
    users.indexes = {"email"};
    schema.tables.push_back(users);
    
    // Sessions table
    DatabaseSchema::Table sessions;
    sessions.name = "sessions";
    sessions.columns = {
        {"id", "uuid"}, {"user_id", "uuid"}, {"token", "varchar(512)"},
        {"expires_at", "timestamp"}, {"created_at", "timestamp"}
    };
    sessions.primaryKeys = {"id"};
    sessions.foreignKeys = {{"user_id", "users.id"}};
    schema.tables.push_back(sessions);
    
    // Add feature-specific tables
    for (const auto& feature : request.features) {
        if (feature == "blog" || feature == "content") {
            DatabaseSchema::Table posts;
            posts.name = "posts";
            posts.columns = {
                {"id", "uuid"}, {"author_id", "uuid"}, {"title", "varchar(255)"},
                {"content", "text"}, {"status", "varchar(50)"},
                {"published_at", "timestamp"}, {"created_at", "timestamp"}
            };
            posts.primaryKeys = {"id"};
            posts.foreignKeys = {{"author_id", "users.id"}};
            schema.tables.push_back(posts);
        }
        
        if (feature == "e-commerce" || feature == "shop") {
            DatabaseSchema::Table products;
            products.name = "products";
            products.columns = {
                {"id", "uuid"}, {"name", "varchar(255)"}, {"description", "text"},
                {"price", "decimal(10,2)"}, {"stock", "integer"},
                {"category_id", "uuid"}, {"created_at", "timestamp"}
            };
            products.primaryKeys = {"id"};
            schema.tables.push_back(products);
        }
    }
    
    return schema;
}

// Project structure creation
ProjectStructure ArchitectAgent::createProjectTree(const DesignRequest& request, const TechStack& stack) {
    ProjectStructure structure;
    
    // Root directory
    structure.root.name = request.projectName;
    
    // Source directories
    ProjectStructure::Directory src;
    src.name = "src";
    
    ProjectStructure::Directory components;
    components.name = "components";
    components.subdirectories = {
        { "common", {}, {} },
        { "forms", {}, {} },
        { "layout", {}, {} },
        { "pages", {}, {} }
    };
    
    ProjectStructure::Directory services;
    services.name = "services";
    services.files = {"api.ts", "auth.ts", "storage.ts"};
    
    ProjectStructure::Directory hooks;
    hooks.name = "hooks";
    hooks.files = {"useAuth.ts", "useApi.ts", "useLocalStorage.ts"};
    
    ProjectStructure::Directory utils;
    utils.name = "utils";
    utils.files = {"validation.ts", "formatting.ts", "constants.ts"};
    
    ProjectStructure::Directory types;
    types.name = "types";
    types.files = {"index.ts", "api.ts", "models.ts"};
    
    src.subdirectories = {components, services, hooks, utils, types};
    src.files = {"App.tsx", "main.tsx", "router.tsx"};
    
    // Root subdirectories
    structure.root.subdirectories = {
        src,
        {"public", {}, {"index.html", "favicon.ico"}},
        {"tests", {{"unit", {}, {}}, {"e2e", {}, {}}}, {}},
        {"docs", {}, {"README.md", "API.md"}}
    };
    
    // Root files
    structure.root.files = {
        "package.json", "tsconfig.json", "vite.config.ts",
        ".eslintrc.js", ".prettierrc", "Dockerfile", "docker-compose.yml"
    };
    
    return structure;
}

// API endpoint design
std::vector<std::string> ArchitectAgent::designAPI(const DesignRequest& request, const DatabaseSchema& schema) {
    std::vector<std::string> endpoints;
    
    // Auth endpoints
    endpoints.push_back("POST /api/v1/auth/register");
    endpoints.push_back("POST /api/v1/auth/login");
    endpoints.push_back("POST /api/v1/auth/logout");
    endpoints.push_back("POST /api/v1/auth/refresh");
    endpoints.push_back("GET /api/v1/auth/me");
    
    // User endpoints
    endpoints.push_back("GET /api/v1/users");
    endpoints.push_back("GET /api/v1/users/:id");
    endpoints.push_back("PUT /api/v1/users/:id");
    endpoints.push_back("DELETE /api/v1/users/:id");
    
    // Feature-specific endpoints
    for (const auto& feature : request.features) {
        if (feature == "blog" || feature == "content") {
            endpoints.push_back("GET /api/v1/posts");
            endpoints.push_back("POST /api/v1/posts");
            endpoints.push_back("GET /api/v1/posts/:id");
            endpoints.push_back("PUT /api/v1/posts/:id");
            endpoints.push_back("DELETE /api/v1/posts/:id");
        }
    }
    
    return endpoints;
}

// Recommendation functions
std::string ArchitectAgent::recommendFrontend(const std::vector<std::string>& features) {
    if (std::find(features.begin(), features.end(), "vue") != features.end()) {
        return "vue";
    }
    if (std::find(features.begin(), features.end(), "svelte") != features.end()) {
        return "svelte";
    }
    if (std::find(features.begin(), features.end(), "angular") != features.end()) {
        return "angular";
    }
    return "react"; // Default
}

std::string ArchitectAgent::recommendBackend(const std::vector<std::string>& features, const std::string& frontend) {
    if (std::find(features.begin(), features.end(), "python") != features.end()) {
        return "fastapi";
    }
    if (std::find(features.begin(), features.end(), "java") != features.end()) {
        return "spring";
    }
    if (std::find(features.begin(), features.end(), "dotnet") != features.end()) {
        return "dotnet";
    }
    return "express"; // Default
}

std::string ArchitectAgent::recommendDatabase(const std::vector<std::string>& features, const std::string& scale) {
    if (std::find(features.begin(), features.end(), "nosql") != features.end()) {
        return "mongodb";
    }
    if (scale == "enterprise") {
        return "postgresql";
    }
    return "sqlite";
}

// Configuration file generators
std::string ArchitectAgent::generatePackageJson(const TechStack& stack, const std::string& projectName) {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"name\": \"" << projectName << "\",\n";
    ss << "  \"version\": \"1.0.0\",\n";
    ss << "  \"type\": \"module\",\n";
    ss << "  \"scripts\": {\n";
    ss << "    \"dev\": \"vite\",\n";
    ss << "    \"build\": \"tsc && vite build\",\n";
    ss << "    \"preview\": \"vite preview\",\n";
    ss << "    \"test\": \"vitest\",\n";
    ss << "    \"lint\": \"eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0\"\n";
    ss << "  },\n";
    ss << "  \"dependencies\": {\n";
    ss << "    \"react\": \"^18.2.0\",\n";
    ss << "    \"react-dom\": \"^18.2.0\",\n";
    ss << "    \"react-router-dom\": \"^6.20.0\",\n";
    ss << "    \"axios\": \"^1.6.0\",\n";
    ss << "    \"zustand\": \"^4.4.0\"\n";
    ss << "  },\n";
    ss << "  \"devDependencies\": {\n";
    ss << "    \"typescript\": \"^5.3.0\",\n";
    ss << "    \"vite\": \"^5.0.0\",\n";
    ss << "    \"@types/react\": \"^18.2.0\"\n";
    ss << "  }\n";
    ss << "}\n";
    return ss.str();
}

std::string ArchitectAgent::generateTsConfig(const TechStack& stack) {
    return R"({
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
})";
}

std::string ArchitectAgent::generateDockerfile(const TechStack& stack) {
    return R"(FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"])";
}

std::string ArchitectAgent::generateDockerCompose(const TechStack& stack, const DatabaseSchema& schema) {
    std::stringstream ss;
    ss << "version: '3.8'\n\n";
    ss << "services:\n";
    ss << "  app:\n";
    ss << "    build: .\n";
    ss << "    ports:\n";
    ss << "      - \"3000:80\"\n";
    ss << "    depends_on:\n";
    ss << "      - db\n";
    ss << "  db:\n";
    ss << "    image: postgres:15-alpine\n";
    ss << "    environment:\n";
    ss << "      POSTGRES_USER: user\n";
    ss << "      POSTGRES_PASSWORD: password\n";
    ss << "      POSTGRES_DB: app\n";
    ss << "    volumes:\n";
    ss << "      - postgres_data:/var/lib/postgresql/data\n";
    ss << "volumes:\n";
    ss << "  postgres_data:\n";
    return ss.str();
}

std::string ArchitectAgent::generateEnvFile(const TechStack& stack, const DatabaseSchema& schema) {
    return R"(NODE_ENV=development
VITE_API_URL=http://localhost:3001/api/v1
VITE_APP_NAME=MyApp
DATABASE_URL=postgresql://user:password@localhost:5432/app
JWT_SECRET=your-secret-key-here
JWT_EXPIRES_IN=7d)";
}

// Documentation generators
std::string ArchitectAgent::generateArchitectureDoc(const SystemDesign& design) {
    std::stringstream ss;
    ss << "# System Architecture\n\n";
    ss << "## Technology Stack\n\n";
    ss << "- Frontend: " << design.stack.frontendFramework << "\n";
    ss << "- Backend: " << design.stack.backendFramework << "\n";
    ss << "- Database: " << design.stack.database << "\n";
    ss << "- Styling: " << design.stack.styling << "\n\n";
    ss << "## API Endpoints\n\n";
    for (const auto& endpoint : design.apiEndpoints) {
        ss << "- " << endpoint << "\n";
    }
    return ss.str();
}

std::string ArchitectAgent::generateERDiagram(const DatabaseSchema& schema) {
    std::stringstream ss;
    ss << "```mermaid\nerDiagram\n";
    for (const auto& table : schema.tables) {
        ss << "    " << table.name << " {\n";
        for (const auto& col : table.columns) {
            ss << "        " << col.second << " " << col.first << "\n";
        }
        ss << "    }\n";
    }
    ss << "```\n";
    return ss.str();
}

std::string ArchitectAgent::generateAPIDocumentation(const std::vector<std::string>& endpoints) {
    std::stringstream ss;
    ss << "# API Documentation\n\n";
    for (const auto& endpoint : endpoints) {
        ss << "## " << endpoint << "\n\n";
        ss << "### Request\n\n";
        ss << "### Response\n\n";
        ss << "### Errors\n\n";
    }
    return ss.str();
}

} // namespace swarm
} // namespace rawrxd

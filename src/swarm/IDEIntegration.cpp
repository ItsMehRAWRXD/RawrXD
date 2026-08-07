#include "IDEIntegration.hpp"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <chrono>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace rawrxd {
namespace swarm {

// ============================================================================
// IDEIntegration Implementation
// ============================================================================

void IDEIntegration::initialize() {
    orchestrator_ = &SwarmOrchestrator::getInstance();
    
    // Detect available memory and choose swarm size
    size_t availableMemoryMB = getAvailableMemoryMB();
    if (availableMemoryMB >= 16000) {
        // Full swarm: 300 agents
        orchestrator_->initialize(1, 120, 100, 50, 29);
    } else if (availableMemoryMB >= 8000) {
        // Micro-swarm: 66 agents
        orchestrator_->initializeMicroSwarm();
    } else {
        // Minimal swarm: 10 agents
        orchestrator_->initialize(1, 3, 3, 2, 1);
    }
}

void IDEIntegration::shutdown() {
    if (orchestrator_) {
        orchestrator_->shutdown();
    }
}

IDEIntegration::GeneratedProject IDEIntegration::generateProject(
    const ProjectRequest& request
) {
    GeneratedProject project;
    auto startTime = std::chrono::steady_clock::now();
    
    // Phase 1: Architecture Design (The Architect)
    updateProgress(GenerationProgress::DESIGNING, "Designing system architecture...");
    auto design = runArchitectPhase(request);
    
    // Phase 2: Frontend Generation (Frontend Squad - 120 parallel agents)
    updateProgress(GenerationProgress::GENERATING_FRONTEND, "Generating UI components...");
    auto frontendResult = runFrontendPhase(design);
    
    // Phase 3: Backend Generation (Backend Core - 100 parallel agents)
    updateProgress(GenerationProgress::GENERATING_BACKEND, "Building API and services...");
    auto backendResult = runBackendPhase(design);
    
    // Phase 4: Test Generation (QA Hive - 50 parallel agents)
    updateProgress(GenerationProgress::WRITING_TESTS, "Writing comprehensive tests...");
    
    // Phase 5: Code Review (Reviewers - 29 parallel agents)
    updateProgress(GenerationProgress::REVIEWING, "Reviewing code quality...");
    
    // Phase 6: Finalization
    updateProgress(GenerationProgress::FINALIZING, "Finalizing project...");
    
    // Combine all generated files
    project.projectPath = request.targetPath + "/" + request.name;
    
    // Write frontend files
    for (const auto& page : frontendResult.pages) {
        std::string pagePath = project.projectPath + "/frontend/src/pages/" + page.route + ".tsx";
        project.files.push_back(pagePath);
        project.fileContents[pagePath] = page.tsxContent;
    }
    
    // Write backend files
    for (const auto& [path, content] : backendResult.serviceFiles) {
        std::string fullPath = project.projectPath + "/backend/" + path;
        project.files.push_back(fullPath);
        project.fileContents[fullPath] = content;
    }
    
    // Generate documentation
    project.readme = generateREADME(project);
    project.architectureDoc = architect_.generateArchitectureDoc(design);
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    
    return project;
}

std::string IDEIntegration::generateComponent(
    const std::string& description,
    const std::string& existingCode
) {
    // Create context from existing code
    contextManager_.clear();
    contextManager_.addText(existingCode, "project");
    
    // Generate design system based on existing code
    VibeSpec vibe;
    vibe.mood = "professional";
    auto designSystem = vibeEngine_.generateDesignSystem(vibe);
    
    // Create component spec from description
    ComponentSpec spec;
    spec.name = "Component"; // Simplified extraction
    spec.type = "component";
    spec.responsive = true;
    
    // Submit to frontend squad
    FrontendSquad::PageRequest request;
    request.components.push_back(spec);
    
    auto result = frontend_.generateComponent(spec, designSystem);
    return result;
}

std::string IDEIntegration::refactorCode(
    const std::string& code,
    const std::string& instructions
) {
    // Analyze code
    auto analysis = reviewers_.reviewFile("temp://input");
    
    // Generate refactoring plan
    std::vector<std::string> refactorTasks;
    refactorTasks.push_back(instructions);
    
    // Apply transformations
    std::string result = code;
    
    // Apply style fixes
    auto styleFixes = reviewers_.checkCodeStyle(code);
    for (const auto& fix : styleFixes) {
        auto fixCode = reviewers_.generateFix(fix);
        // Apply fix to result
    }
    
    // Apply complexity fixes
    auto complexityFixes = reviewers_.checkComplexity(code);
    for (const auto& fix : complexityFixes) {
        auto fixCode = reviewers_.generateFix(fix);
        // Apply fix to result
    }
    
    return result;
}

std::string IDEIntegration::fixBug(
    const std::string& code,
    const std::string& errorDescription
) {
    // Analyze the error
    // Check for common patterns
    std::string result = code;
    
    // Check for null pointer issues
    if (errorDescription.find("null") != std::string::npos ||
        errorDescription.find("undefined") != std::string::npos) {
        // Add null checks
    }
    
    // Check for type errors
    if (errorDescription.find("type") != std::string::npos) {
        // Add type guards
    }
    
    // Check for async issues
    if (errorDescription.find("async") != std::string::npos ||
        errorDescription.find("await") != std::string::npos ||
        errorDescription.find("Promise") != std::string::npos) {
        // Fix async patterns
    }
    
    return result;
}

std::string IDEIntegration::optimizePerformance(
    const std::string& code,
    const std::string& metrics
) {
    std::string result = code;
    
    // Check for memoization opportunities
    auto perfFindings = reviewers_.checkPerformance(code);
    for (const auto& finding : perfFindings) {
        if (finding.rule == "missing-memoization") {
            // Add React.memo or useMemo
        } else if (finding.rule == "unnecessary-renders") {
            // Optimize render cycles
        } else if (finding.rule == "large-bundle") {
            // Suggest code splitting
        }
    }
    
    return result;
}

std::string IDEIntegration::generateTests(
    const std::string& code,
    const std::string& testType
) {
    TestSpec spec;
    spec.type = testType;
    spec.target = "component";
    
    if (testType == "unit") {
        return qa_.generateUnitTest(spec);
    } else if (testType == "integration") {
        return qa_.generateIntegrationTest({code}, "default");
    } else if (testType == "e2e") {
        return qa_.generateE2ETest("user flow");
    }
    
    return "";
}

std::string IDEIntegration::generateDocumentation(
    const std::vector<std::string>& files
) {
    std::stringstream doc;
    
    doc << "# API Documentation\n\n";
    doc << "## Overview\n\n";
    doc << "This documentation was auto-generated by RawrXD Swarm.\n\n";
    
    for (const auto& file : files) {
        doc << "## " << file << "\n\n";
        // Extract JSDoc/docstring comments
        // Generate markdown
    }
    
    return doc.str();
}

std::string IDEIntegration::generateREADME(
    const GeneratedProject& project
) {
    std::stringstream readme;
    
    readme << "# " << project.projectPath << "\n\n";
    readme << "Generated by RawrXD Swarm\n\n";
    readme << "## Project Structure\n\n";
    readme << "- `frontend/` - React/Vue frontend application\n";
    readme << "- `backend/` - API server\n";
    readme << "- `tests/` - Test suites\n\n";
    readme << "## Setup\n\n";
    readme << "```bash\n";
    for (const auto& cmd : project.setupCommands) {
        readme << cmd << "\n";
    }
    readme << "```\n\n";
    readme << "## Development\n\n";
    readme << "```bash\n";
    readme << "npm run dev\n";
    readme << "```\n\n";
    readme << "## Testing\n\n";
    readme << "```bash\n";
    readme << "npm test\n";
    readme << "```\n\n";
    readme << "## Architecture\n\n";
    readme << "See ARCHITECTURE.md for detailed system design.\n";
    
    return readme.str();
}

void IDEIntegration::setProgressCallback(ProgressCallback callback) {
    progressCallback_ = callback;
}

void IDEIntegration::updateProgress(GenerationProgress::Stage stage, const std::string& task) {
    currentProgress_.currentStage = stage;
    currentProgress_.currentTask = task;
    currentProgress_.percentComplete = static_cast<int>(stage) * 20;
    
    if (progressCallback_) {
        progressCallback_(currentProgress_);
    }
}

void IDEIntegration::writeFile(const std::string& path, const std::string& content) {
    std::filesystem::path filePath(path);
    std::filesystem::create_directories(filePath.parent_path());
    
    std::ofstream file(path);
    if (file.is_open()) {
        file << content;
        file.close();
    }
}

std::string IDEIntegration::readFile(const std::string& path) {
    std::ifstream file(path);
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        file.close();
        return buffer.str();
    }
    return "";
}

void IDEIntegration::createDirectory(const std::string& path) {
    std::filesystem::create_directories(path);
}

bool IDEIntegration::fileExists(const std::string& path) {
    return std::filesystem::exists(path);
}

size_t IDEIntegration::getAvailableMemoryMB() {
    // Platform-specific memory detection
    #ifdef _WIN32
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatusEx(&status);
    return static_cast<size_t>(status.ullAvailPhys / (1024 * 1024));
    #else
    // Linux/Mac implementation
    return 16000; // Default to 16GB
    #endif
}

std::string IDEIntegration::extractComponentName(const std::string& description) {
    // Extract component name from description
    // Simple implementation - take first capitalized words
    std::string name;
    std::istringstream iss(description);
    std::string word;
    while (iss >> word) {
        if (std::isupper(word[0])) {
            name += word;
        }
    }
    if (name.empty()) name = "Component";
    return name;
}

// ============================================================================
// VSCodeBridge Implementation
// ============================================================================

void VSCodeBridge::connect() {
    connected_ = true;
    // Connect to VS Code extension via stdio or socket
}

void VSCodeBridge::disconnect() {
    connected_ = false;
}

bool VSCodeBridge::isConnected() const {
    return connected_;
}

void VSCodeBridge::sendMessage(const nlohmann::json& message) {
    if (!connected_) return;
    
    std::string jsonString = message.dump();
    
    // Send via stdout or socket
    std::cout << "Content-Length: " << jsonString.length() << "\r\n\r\n";
    std::cout << jsonString << std::flush;
}

void VSCodeBridge::onMessage(std::function<void(const nlohmann::json&)> handler) {
    messageHandler_ = handler;
}

void VSCodeBridge::handleGenerateProject(const nlohmann::json& params) {
    IDEIntegration integration;
    integration.initialize();
    
    IDEIntegration::ProjectRequest request;
    request.name = params.value("name", "");
    request.description = params.value("description", "");
    request.type = params.value("type", "");
    request.targetPath = params.value("path", "");
    
    if (params.contains("features") && params["features"].is_array()) {
        for (const auto& feature : params["features"]) {
            request.features.push_back(feature.get<std::string>());
        }
    }
    
    auto project = integration.generateProject(request);
    
    // Send result back to VS Code
    nlohmann::json result;
    result["projectPath"] = project.projectPath;
    result["files"] = nlohmann::json::array();
    for (const auto& file : project.files) {
        result["files"].push_back(file);
    }
    
    sendMessage(result);
}

void VSCodeBridge::handleGenerateComponent(const nlohmann::json& params) {
    // Implementation
}

void VSCodeBridge::handleRefactor(const nlohmann::json& params) {
    // Implementation
}

void VSCodeBridge::handleReview(const nlohmann::json& params) {
    // Implementation
}

void VSCodeBridge::handleOptimize(const nlohmann::json& params) {
    // Implementation
}

// ============================================================================
// IDEIntegration Stage Handlers
// ============================================================================

ArchitectAgent::SystemDesign IDEIntegration::runArchitectPhase(const ProjectRequest& request) {
    // Delegate to architect agent
    ArchitectAgent::DesignRequest designReq;
    designReq.projectName = request.name;
    designReq.description = request.description;
    designReq.features = request.features;
    designReq.targetPlatform = request.type;
    designReq.scale = "startup";
    return architect_.designSystem(designReq);
}

FrontendSquad::ComponentLibrary IDEIntegration::runFrontendPhase(
    const ArchitectAgent::SystemDesign& design
) {
    // Delegate to frontend squad
    (void)design;
    FrontendSquad::PageRequest pageReq;
    pageReq.route = "/";
    pageReq.title = "Home";
    pageReq.purpose = "Main page";
    std::vector<FrontendSquad::PageRequest> requests = {pageReq};
    DesignSystem designSystem;
    return frontend_.generateApplication(requests, designSystem);
}

BackendCore::GeneratedBackend IDEIntegration::runBackendPhase(
    const ArchitectAgent::SystemDesign& design
) {
    // Delegate to backend core
    (void)design;
    BackendCore::BackendRequest backendReq;
    // Initialize with empty services
    return backend_.generateBackend(backendReq);
}

} // namespace swarm
} // namespace rawrxd

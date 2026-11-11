// agentic_workspace_analyzer.cpp
// Codebase scanning: understand structure, dependencies, and change impact

#include "agentic_workspace_analyzer.hpp"
#include "observability/Logger.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>

namespace Agentic {

// ============================================================================
// Helper Functions
// ============================================================================

static std::string normalizePath(const std::string& path) {
    std::string norm = path;
    std::replace(norm.begin(), norm.end(), '\\', '/');
    return norm;
}

static bool hasExtension(const std::string& path, const std::string& ext) {
    if (path.length() < ext.length()) return false;
    return path.substr(path.length() - ext.length()) == ext;
}

// ============================================================================
// SourceFile Implementation
// ============================================================================

// ============================================================================
// DirectoryNode Implementation
// ============================================================================

size_t DirectoryNode::getTotalFiles() const {
    size_t count = files.size();
    for (const auto& sub : subdirs) {
        count += sub->getTotalFiles();
    }
    return count;
}

size_t DirectoryNode::getTotalLines() const {
    size_t total = 0;
    for (const auto& file : files) {
        total += file.line_count;
    }
    for (const auto& sub : subdirs) {
        total += sub->getTotalLines();
    }
    return total;
}

// ============================================================================
// DependencyGraph Implementation
// ============================================================================

bool DependencyGraph::isCriticalFile(const std::string& path) const {
    return std::find(critical_headers.begin(), critical_headers.end(), path) 
           != critical_headers.end();
}

std::vector<std::string> DependencyGraph::getImpactedFiles(const std::string& changed_file) const {
    std::vector<std::string> impacted;
    
    auto it = dependents.find(changed_file);
    if (it != dependents.end()) {
        impacted = it->second;
    }
    
    return impacted;
}

// ============================================================================
// WorkspaceAnalysis Implementation
// ============================================================================

nlohmann::json WorkspaceAnalysis::toJson() const {
    nlohmann::json j;
    j["workspace_root"] = workspace_root;
    j["total_source_files"] = total_source_files;
    j["total_header_files"] = total_header_files;
    j["total_test_files"] = total_test_files;
    j["total_lines_of_code"] = total_lines_of_code;
    j["build_system"] = static_cast<int>(build_info.system);
    j["build_dir"] = build_info.build_dir;
    j["analyzed_at"] = std::to_string(analyzed_at.time_since_epoch().count());
    return j;
}

// ============================================================================
// WorkspaceAnalyzer Implementation
// ============================================================================

WorkspaceAnalyzer::WorkspaceAnalyzer(const std::string& workspace_root)
    : m_root(normalizePath(workspace_root)) {
    m_analysis.workspace_root = m_root;
    m_ignore_patterns = {
        ".git", ".gitignore", "build", "dist", "obj", ".obj",
        "CMakeFiles", "cmake_install.cmake", "Makefile",
        ".vscode", ".vs", ".idea", "node_modules",
        "*.exe", "*.dll", "*.lib", "*.o", "*.a"
    };
}

WorkspaceAnalyzer::~WorkspaceAnalyzer() {
}

bool WorkspaceAnalyzer::analyze() {
    LOG_INFO("WorkspaceAnalyzer", "Starting analysis of " + m_root);
    m_analysis.analyzed_at = std::chrono::system_clock::now();
    
    try {
        // Step 1: Scan directory structure
        m_analysis.root_dir = std::make_shared<DirectoryNode>();
        m_analysis.root_dir->path = m_root;
        
        if (!scanDirectory(m_root, m_analysis.root_dir, 0)) {
            LOG_ERROR("WorkspaceAnalyzer", "Failed to scan directory");
            return false;
        }
        
        // Step 2: Build dependency graph
        buildDependencyGraph();
        
        // Step 3: Identify critical files
        identifyCriticalFiles();
        
        // Step 4: Detect build system
        m_analysis.build_info.system = detectBuildSystem();
        if (m_analysis.build_info.system == BuildSystem::CMake) {
            analyzeWithCMake();
        }
        
        // Step 5: Count metrics
        m_analysis.total_source_files = m_analysis.dep_graph.files.size();
        m_analysis.total_lines_of_code = m_analysis.root_dir->getTotalLines();
        
        LOG_INFO("WorkspaceAnalyzer", "Analysis complete: " +
                std::to_string(m_analysis.total_source_files) + " files, " +
                std::to_string(m_analysis.total_lines_of_code) + " LOC");
        
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("WorkspaceAnalyzer", "Exception during analysis: " + std::string(e.what()));
        return false;
    }
}

bool WorkspaceAnalyzer::scanDirectory(const std::string& dir, std::shared_ptr<DirectoryNode>& node, int depth) {
    if (depth > m_max_depth) {
        return true; // Stop recursing, but still OK
    }
    
    try {
        namespace fs = std::filesystem;
        
        for (const auto& entry : fs::directory_iterator(dir)) {
            const std::string entry_path = entry.path().string();
            const std::string filename = entry.path().filename().string();
            
            // Skip ignored patterns
            bool ignored = false;
            for (const auto& pattern : m_ignore_patterns) {
                if (entry_path.find(pattern) != std::string::npos) {
                    ignored = true;
                    break;
                }
            }
            if (ignored) continue;
            
            if (entry.is_directory()) {
                auto subdir = std::make_shared<DirectoryNode>();
                subdir->path = normalizePath(entry_path);
                subdir->is_build_dir = (filename.find("build") != std::string::npos);
                subdir->is_test_dir = (filename.find("test") != std::string::npos);
                
                if (scanDirectory(entry_path, subdir, depth + 1)) {
                    node->subdirs.push_back(subdir);
                }
            } else if (entry.is_regular_file()) {
                SourceFile file;
                file.path = normalizePath(entry_path);
                file.type = detectFileType(file.path);
                
                if (file.type != FileType::Build && file.type != FileType::Unknown) {
                    if (analyzeSourceFile(entry_path, file)) {
                        node->files.push_back(file);
                        m_analysis.dep_graph.files[file.path] = file;
                    }
                }
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        LOG_WARN("WorkspaceAnalyzer", "Error scanning " + dir + ": " + e.what());
        return false;
    }
}

bool WorkspaceAnalyzer::analyzeSourceFile(const std::string& path, SourceFile& file) {
    try {
        std::ifstream ifs(path);
        if (!ifs) return false;
        
        std::string line;
        while (std::getline(ifs, line) && file.line_count < 1000000) {
            file.line_count++;
            
            // Extract #include directives
            if (line.find("#include") != std::string::npos) {
                std::regex include_regex(R"(#include\s*[<"]([^>"]+)[>"])");
                std::smatch match;
                if (std::regex_search(line, match, include_regex)) {
                    file.includes.push_back(match[1].str());
                }
            }
        }
        
        ifs.close();
        return true;
    } catch (const std::exception& e) {
        LOG_WARN("WorkspaceAnalyzer", "Error analyzing " + path + ": " + e.what());
        return false;
    }
}

bool WorkspaceAnalyzer::extractIncludes(const std::string& path, std::vector<std::string>& includes) {
    includes.clear();
    // Delegate to analyzeSourceFile
    SourceFile dummy;
    dummy.path = path;
    if (analyzeSourceFile(path, dummy)) {
        includes = dummy.includes;
        return true;
    }
    return false;
}

void WorkspaceAnalyzer::buildDependencyGraph() {
    // For each file, resolve includes and build forward/reverse edges
    for (auto& [path, file] : m_analysis.dep_graph.files) {
        std::set<std::string> resolved_deps;
        
        for (const auto& include : file.includes) {
            // Simple resolution: look for matching file
            for (const auto& [other_path, other_file] : m_analysis.dep_graph.files) {
                if (other_path.find(include) != std::string::npos ||
                    include.find(other_path) != std::string::npos) {
                    resolved_deps.insert(other_path);
                    m_analysis.dep_graph.dependents[other_path].push_back(path);
                    break;
                }
            }
        }
        
        file.dependencies = resolved_deps;
    }
}

void WorkspaceAnalyzer::identifyCriticalFiles() {
    // Files with high fan-in (many dependents) are critical
    for (const auto& [path, dependents] : m_analysis.dep_graph.dependents) {
        if (dependents.size() > 5) {
            m_analysis.dep_graph.critical_headers.push_back(path);
        }
    }
    
    // Mark critical files in the graph
    for (auto& [path, file] : m_analysis.dep_graph.files) {
        if (std::find(m_analysis.dep_graph.critical_headers.begin(),
                     m_analysis.dep_graph.critical_headers.end(), path)
            != m_analysis.dep_graph.critical_headers.end()) {
            file.is_critical = true;
        }
    }
}

BuildSystem WorkspaceAnalyzer::detectBuildSystem() const {
    namespace fs = std::filesystem;
    
    if (fs::exists(std::filesystem::path(m_root) / "CMakeLists.txt")) {
        return BuildSystem::CMake;
    }
    if (fs::exists(std::filesystem::path(m_root) / "Makefile")) {
        return BuildSystem::Makefile;
    }
    if (fs::exists(std::filesystem::path(m_root) / "build.ninja")) {
        return BuildSystem::Ninja;
    }
    if (fs::exists(std::filesystem::path(m_root) / "BUILD")) {
        return BuildSystem::Bazel;
    }
    
    return BuildSystem::Unknown;
}

FileType WorkspaceAnalyzer::detectFileType(const std::string& path) const {
    if (path.find("test") != std::string::npos &&
        (hasExtension(path, ".cpp") || hasExtension(path, ".cc") || hasExtension(path, ".c"))) {
        return FileType::Test;
    }
    if (hasExtension(path, ".cpp") || hasExtension(path, ".cc") || hasExtension(path, ".c")) {
        return FileType::Source;
    }
    if (hasExtension(path, ".h") || hasExtension(path, ".hpp") || hasExtension(path, ".hxx")) {
        return FileType::Header;
    }
    if (hasExtension(path, "CMakeLists.txt")) {
        return FileType::CMakeFile;
    }
    if (hasExtension(path, ".json") || hasExtension(path, ".ini") || hasExtension(path, ".yaml")) {
        return FileType::Configuration;
    }
    if (hasExtension(path, ".asm") || hasExtension(path, ".s")) {
        return FileType::Assembly;
    }
    if (hasExtension(path, ".md") || hasExtension(path, ".txt")) {
        return FileType::Documentation;
    }
    if (hasExtension(path, ".obj") || hasExtension(path, ".lib") || 
        hasExtension(path, ".exe") || hasExtension(path, ".dll")) {
        return FileType::Build;
    }
    
    return FileType::Unknown;
}

bool WorkspaceAnalyzer::isTestFile(const std::string& path) const {
    auto it = m_analysis.dep_graph.files.find(path);
    if (it != m_analysis.dep_graph.files.end()) {
        return it->second.type == FileType::Test;
    }
    return detectFileType(path) == FileType::Test;
}

bool WorkspaceAnalyzer::isCriticalFile(const std::string& path) const {
    return m_analysis.dep_graph.isCriticalFile(path);
}

std::vector<std::string> WorkspaceAnalyzer::getFilesAffectedBy(const std::string& changed_file) const {
    // Check cache first
    auto it = m_analysis.change_impact_cache.find(changed_file);
    if (it != m_analysis.change_impact_cache.end()) {
        return it->second;
    }
    
    // Compute and cache
    auto impacted = m_analysis.dep_graph.getImpactedFiles(changed_file);
    return impacted;
}

std::vector<std::string> WorkspaceAnalyzer::getFilesAffectingFile(const std::string& target_file) const {
    std::vector<std::string> affecting;
    
    auto it = m_analysis.dep_graph.files.find(target_file);
    if (it != m_analysis.dep_graph.files.end()) {
        affecting.insert(affecting.end(),
                        it->second.dependencies.begin(),
                        it->second.dependencies.end());
    }
    
    return affecting;
}

int WorkspaceAnalyzer::estimateRebuildTime(const std::vector<std::string>& changed_files) const {
    // Simple heuristic: each changed file costs ~5s, each critical file costs ~10s
    int estimate = 0;
    for (const auto& file : changed_files) {
        estimate += isCriticalFile(file) ? 10 : 5;
    }
    return estimate; // in seconds
}

void WorkspaceAnalyzer::analyzeWithCMake() {
    // Extract build info from CMakeLists.txt or cmake cache
    std::string cmakeListsPath = m_root + "/CMakeLists.txt";
    std::string cmakeCachePath = m_root + "/build/CMakeCache.txt";
    
    // Try to read from CMake cache first (most accurate)
    if (std::filesystem::exists(cmakeCachePath)) {
        std::ifstream cacheFile(cmakeCachePath);
        if (cacheFile) {
            std::string line;
            while (std::getline(cacheFile, line)) {
                // Parse CMAKE_BUILD_TYPE
                if (line.find("CMAKE_BUILD_TYPE:") != std::string::npos) {
                    size_t pos = line.find("=");
                    if (pos != std::string::npos) {
                        m_analysis.build_info.build_type = line.substr(pos + 1);
                    }
                }
                // Parse CMAKE_CXX_COMPILER
                if (line.find("CMAKE_CXX_COMPILER:") != std::string::npos) {
                    size_t pos = line.find("=");
                    if (pos != std::string::npos) {
                        m_analysis.build_info.compiler = line.substr(pos + 1);
                    }
                }
            }
        }
    }
    
    // Parse CMakeLists.txt for project info
    if (std::filesystem::exists(cmakeListsPath)) {
        std::ifstream cmakeFile(cmakeListsPath);
        if (cmakeFile) {
            std::string content((std::istreambuf_iterator<char>(cmakeFile)),
                               std::istreambuf_iterator<char>());
            
            // Extract project name
            std::regex projectRegex(R"(project\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)");
            std::smatch match;
            if (std::regex_search(content, match, projectRegex)) {
                m_analysis.build_info.project_name = match[1].str();
            }
            
            // Extract C++ standard
            std::regex cxxStandardRegex(R"(set\s*\(\s*CMAKE_CXX_STANDARD\s+(\d+)\s*\))");
            if (std::regex_search(content, match, cxxStandardRegex)) {
                m_analysis.build_info.cpp_standard = std::stoi(match[1].str());
            }
            
            // Count targets (add_executable, add_library)
            std::regex targetRegex(R"((add_executable|add_library)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)");
            std::sregex_iterator iter(content.begin(), content.end(), targetRegex);
            std::sregex_iterator end;
            while (iter != end) {
                m_analysis.build_info.targets.push_back((*iter)[2].str());
                ++iter;
            }
        }
    }
    
    // Set build directory
    m_analysis.build_info.build_dir = m_root + "/build";
    m_analysis.build_info.source_dir = m_root;
    
    // Determine recommended parallel jobs based on CPU count
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD numCores = sysInfo.dwNumberOfProcessors;
    m_analysis.build_info.recommended_jobs = std::max(1u, numCores - 1);  // Leave one core free
    m_analysis.build_info.parallel_build_supported = true;
    
    // Check for Ninja or Make
    if (std::filesystem::exists(m_analysis.build_info.build_dir + "/build.ninja")) {
        m_analysis.build_info.generator = "Ninja";
    } else if (std::filesystem::exists(m_analysis.build_info.build_dir + "/Makefile")) {
        m_analysis.build_info.generator = "Unix Makefiles";
    }
}

void WorkspaceAnalyzer::refresh() {
    // Clear previous analysis
    m_analysis.dep_graph.files.clear();
    m_analysis.dep_graph.dependents.clear();
    m_analysis.dep_graph.critical_headers.clear();
    m_analysis.change_impact_cache.clear();
    
    // Re-analyze
    analyze();
}

} // namespace Agentic

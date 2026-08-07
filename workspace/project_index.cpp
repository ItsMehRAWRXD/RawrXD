// project_index.cpp — Project Indexing Engine
#include "workspace_manager.hpp"
#include <fstream>
#include <regex>
#include <unordered_set>

namespace RawrXD {
namespace Workspace {

// ============================================================================
// Project Indexer — Scans and indexes project structure
// ============================================================================
class ProjectIndexer {
public:
    static ProjectIndexer& Get();

    // Index a project directory
    bool Index(const std::filesystem::path& path, ProjectInfo& info);

    // Get file count by extension
    std::map<std::string, size_t> GetFileCounts(const std::filesystem::path& path) const;

    // Find all source files
    std::vector<std::filesystem::path> FindSourceFiles(const std::filesystem::path& path) const;

    // Find all header files
    std::vector<std::filesystem::path> FindHeaderFiles(const std::filesystem::path& path) const;

    // Count lines of code
    struct CodeStats {
        size_t totalFiles = 0;
        size_t totalLines = 0;
        size_t codeLines = 0;
        size_t commentLines = 0;
        size_t blankLines = 0;
    };
    CodeStats CountLines(const std::filesystem::path& path) const;

    // Detect dependencies from build files
    std::vector<std::string> DetectDependencies(const std::filesystem::path& path, const std::string& projectType) const;

    // Persistent index cache
    bool SaveIndex(const std::filesystem::path& cachePath, const ProjectInfo& info);
    bool LoadIndex(const std::filesystem::path& cachePath, ProjectInfo& info);

private:
    ProjectIndexer() = default;

    static const std::unordered_set<std::string> SOURCE_EXTENSIONS;
    static const std::unordered_set<std::string> HEADER_EXTENSIONS;
    static const std::unordered_set<std::string> BUILD_FILES;
};

const std::unordered_set<std::string> ProjectIndexer::SOURCE_EXTENSIONS = {
    ".cpp", ".c", ".cc", ".cxx", ".c++", ".hpp", ".h", ".hxx",
    ".js", ".ts", ".jsx", ".tsx", ".py", ".rs", ".go", ".java",
    ".cs", ".swift", ".kt", ".scala", ".rb", ".php", ".pl", ".lua"
};

const std::unordered_set<std::string> ProjectIndexer::HEADER_EXTENSIONS = {
    ".hpp", ".h", ".hxx", ".hh"
};

const std::unordered_set<std::string> ProjectIndexer::BUILD_FILES = {
    "CMakeLists.txt", "Makefile", "makefile", "GNUmakefile",
    "package.json", "Cargo.toml", "build.gradle", "pom.xml",
    "*.sln", "*.vcxproj", "*.csproj", "*.fsproj"
};

ProjectIndexer& ProjectIndexer::Get() {
    static ProjectIndexer instance;
    return instance;
}

bool ProjectIndexer::Index(const std::filesystem::path& path, ProjectInfo& info) {
    if (!std::filesystem::exists(path)) return false;

    info.rootPath = std::filesystem::absolute(path);
    info.name = path.filename().string();

    // Detect project type
    if (std::filesystem::exists(path / "CMakeLists.txt")) {
        info.type = "cmake";
        info.buildFiles.push_back(path / "CMakeLists.txt");
        info.languages.push_back("cpp");
    } else if (std::filesystem::exists(path / "package.json")) {
        info.type = "npm";
        info.buildFiles.push_back(path / "package.json");
        info.languages.push_back("javascript");
        info.languages.push_back("typescript");
    } else if (std::filesystem::exists(path / "Cargo.toml")) {
        info.type = "cargo";
        info.buildFiles.push_back(path / "Cargo.toml");
        info.languages.push_back("rust");
    } else if (std::filesystem::exists(path / "setup.py") || std::filesystem::exists(path / "pyproject.toml")) {
        info.type = "python";
        info.languages.push_back("python");
    }

    // Detect dependencies
    info.dependencies = DetectDependencies(path, info.type);

    return true;
}

std::map<std::string, size_t> ProjectIndexer::GetFileCounts(const std::filesystem::path& path) const {
    std::map<std::string, size_t> counts;
    if (!std::filesystem::exists(path)) return counts;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            counts[ext]++;
        }
    }

    return counts;
}

std::vector<std::filesystem::path> ProjectIndexer::FindSourceFiles(const std::filesystem::path& path) const {
    std::vector<std::filesystem::path> files;
    if (!std::filesystem::exists(path)) return files;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (SOURCE_EXTENSIONS.count(ext)) {
                files.push_back(entry.path());
            }
        }
    }

    return files;
}

std::vector<std::filesystem::path> ProjectIndexer::FindHeaderFiles(const std::filesystem::path& path) const {
    std::vector<std::filesystem::path> files;
    if (!std::filesystem::exists(path)) return files;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (HEADER_EXTENSIONS.count(ext)) {
                files.push_back(entry.path());
            }
        }
    }

    return files;
}

ProjectIndexer::CodeStats ProjectIndexer::CountLines(const std::filesystem::path& path) const {
    CodeStats stats;
    if (!std::filesystem::exists(path)) return stats;

    auto sourceFiles = FindSourceFiles(path);
    stats.totalFiles = sourceFiles.size();

    for (const auto& file : sourceFiles) {
        std::ifstream f(file);
        if (!f.is_open()) continue;

        std::string line;
        while (std::getline(f, line)) {
            stats.totalLines++;
            if (line.empty()) {
                stats.blankLines++;
            } else {
                std::string trimmed = line;
                trimmed.erase(0, trimmed.find_first_not_of(" \t"));
                if (trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*") || trimmed.starts_with("#")) {
                    stats.commentLines++;
                } else {
                    stats.codeLines++;
                }
            }
        }
    }

    return stats;
}

std::vector<std::string> ProjectIndexer::DetectDependencies(const std::filesystem::path& path, const std::string& projectType) const {
    std::vector<std::string> deps;

    if (projectType == "cmake") {
        auto cmakeFile = path / "CMakeLists.txt";
        if (std::filesystem::exists(cmakeFile)) {
            std::ifstream file(cmakeFile);
            std::string line;
            std::regex findDep(R"(find_package\s*\(\s*(\w+))");
            while (std::getline(file, line)) {
                std::smatch match;
                if (std::regex_search(line, match, findDep)) {
                    deps.push_back(match[1].str());
                }
            }
        }
    } else if (projectType == "npm") {
        auto pkgFile = path / "package.json";
        if (std::filesystem::exists(pkgFile)) {
            std::ifstream file(pkgFile);
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            // Simple dependency extraction
            std::regex depRegex(R"("([^"]+)"\s*:\s*"([^"]+)")");
            auto begin = std::sregex_iterator(content.begin(), content.end(), depRegex);
            auto end = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                deps.push_back((*it)[1].str());
            }
        }
    }

    return deps;
}

bool ProjectIndexer::SaveIndex(const std::filesystem::path& cachePath, const ProjectInfo& info) {
    std::ofstream file(cachePath);
    if (!file.is_open()) return false;

    file << "{\n";
    file << "  \"name\": \"" << info.name << "\",\n";
    file << "  \"type\": \"" << info.type << "\",\n";
    file << "  \"rootPath\": \"" << info.rootPath.string() << "\",\n";
    file << "  \"languages\": [";
    for (size_t i = 0; i < info.languages.size(); i++) {
        if (i > 0) file << ", ";
        file << "\"" << info.languages[i] << "\"";
    }
    file << "]\n";
    file << "}\n";
    return true;
}

bool ProjectIndexer::LoadIndex(const std::filesystem::path& cachePath, ProjectInfo& info) {
    if (!std::filesystem::exists(cachePath)) return false;

    std::ifstream file(cachePath);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        if (line.find("\"name\"") != std::string::npos) info.name = parseStr(line, "name");
        if (line.find("\"type\"") != std::string::npos) info.type = parseStr(line, "type");
        if (line.find("\"rootPath\"") != std::string::npos) info.rootPath = parseStr(line, "rootPath");
    }

    return !info.name.empty();
}

} // namespace Workspace
} // namespace RawrXD

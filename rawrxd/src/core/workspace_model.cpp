// ============================================================================
// workspace_model.cpp — Real explicit workspace/project model for IDE
// ============================================================================
// Explicit workspace = folder(s); load/save "project" (open files, layout)
// Workspace root + optional .rawrxd/workspace.json
// Provides multi-root workspace support and session persistence
// ============================================================================

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <memory>
#include <fstream>
#include <filesystem>
#include <chrono>

// RAWRXD_WORKSPACE_LOAD_001: the load path is a real parse now, so it needs a
// real parser. nlohmann::json is already used across the codebase
// (src/core/settings_persistence.cpp) and ships in 3rdparty.
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

namespace RawrXD {
namespace IDE {

// ============================================================================
// Workspace Folder
// ============================================================================

struct WorkspaceFolder {
    std::string path;
    std::string name;
    bool isRoot = false;
};

// ============================================================================
// Editor Layout
// ============================================================================

struct EditorState {
    std::string filePath;
    int cursorLine = 0;
    int cursorColumn = 0;
    int scrollPosition = 0;
    bool isPinned = false;
};

struct PanelLayout {
    bool terminalVisible = false;
    bool outputVisible = false;
    bool debugVisible = false;
    bool explorerVisible = true;
    int explorerWidth = 250;
    int terminalHeight = 200;
};

// ============================================================================
// Workspace Configuration
// ============================================================================

struct WorkspaceConfig {
    std::string name;
    std::vector<WorkspaceFolder> folders;
    std::vector<EditorState> openFiles;
    PanelLayout layout;
    std::unordered_set<std::string> expandedFolders;
    std::chrono::system_clock::time_point lastOpened;
    
    // Build/Debug settings
    std::string activeBuildConfig;
    std::string activeDebugConfig;
};

// ============================================================================
// Workspace Model
// ============================================================================

class WorkspaceModel {
private:
    std::mutex m_mutex;
    WorkspaceConfig m_config;
    std::string m_configPath;      // .rawrxd/workspace.json
    bool m_initialized = false;
    bool m_dirty = false;           // Config needs saving
    
public:
    WorkspaceModel() = default;
    ~WorkspaceModel() {
        if (m_initialized && m_dirty) {
            save();
        }
    }
    
    // Initialize workspace
    bool initialize(const std::string& rootPath) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Set config path
        m_configPath = rootPath + "/.rawrxd/workspace.json";
        
        // Load existing config or create new
        if (!load()) {
            // Create default workspace
            m_config = WorkspaceConfig{};
            
            WorkspaceFolder root;
            root.path = rootPath;
            root.name = fs::path(rootPath).filename().string();
            root.isRoot = true;
            
            m_config.folders.push_back(root);
            m_config.name = root.name;
            m_config.lastOpened = std::chrono::system_clock::now();
            
            // Default layout
            m_config.layout = PanelLayout{};
            
            m_dirty = true;
        }
        
        m_initialized = true;
        
        fprintf(stderr, "[WorkspaceModel] Initialized: %s\n", m_config.name.c_str());
        fprintf(stderr, "[WorkspaceModel] Root: %s\n", rootPath.c_str());
        fprintf(stderr, "[WorkspaceModel] %zu folders, %zu open files\n",
                m_config.folders.size(), m_config.openFiles.size());
        
        return true;
    }
    
    // Get workspace name
    std::string getName() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_mutex));
        return m_config.name;
    }
    
    // Get root path
    std::string getRootPath() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_mutex));
        
        if (!m_config.folders.empty()) {
            return m_config.folders[0].path;
        }
        
        return ".";
    }
    
    // Get all folders
    std::vector<WorkspaceFolder> getFolders() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_mutex));
        return m_config.folders;
    }
    
    // Add folder to workspace
    bool addFolder(const std::string& path, const std::string& name = "") {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Check if already added
        for (const auto& folder : m_config.folders) {
            if (folder.path == path) {
                fprintf(stderr, "[WorkspaceModel] Folder already in workspace: %s\n",
                        path.c_str());
                return false;
            }
        }
        
        WorkspaceFolder folder;
        folder.path = path;
        folder.name = name.empty() ? fs::path(path).filename().string() : name;
        folder.isRoot = false;
        
        m_config.folders.push_back(folder);
        m_dirty = true;
        
        fprintf(stderr, "[WorkspaceModel] Added folder: %s\n", path.c_str());
        return true;
    }
    
    // Remove folder from workspace
    bool removeFolder(const std::string& path) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (auto it = m_config.folders.begin(); it != m_config.folders.end(); ++it) {
            if (it->path == path) {
                if (it->isRoot && m_config.folders.size() == 1) {
                    fprintf(stderr, "[WorkspaceModel] Cannot remove last root folder\n");
                    return false;
                }
                
                m_config.folders.erase(it);
                m_dirty = true;
                
                fprintf(stderr, "[WorkspaceModel] Removed folder: %s\n", path.c_str());
                return true;
            }
        }
        
        return false;
    }
    
    // Register open file
    void addOpenFile(const std::string& filePath, int line = 0, int column = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Check if already open
        for (auto& file : m_config.openFiles) {
            if (file.filePath == filePath) {
                // Update cursor position
                file.cursorLine = line;
                file.cursorColumn = column;
                m_dirty = true;
                return;
            }
        }
        
        EditorState state;
        state.filePath = filePath;
        state.cursorLine = line;
        state.cursorColumn = column;
        
        m_config.openFiles.push_back(state);
        m_dirty = true;
        
        fprintf(stderr, "[WorkspaceModel] Added open file: %s\n", filePath.c_str());
    }
    
    // Unregister open file
    void removeOpenFile(const std::string& filePath) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (auto it = m_config.openFiles.begin(); it != m_config.openFiles.end(); ++it) {
            if (it->filePath == filePath) {
                m_config.openFiles.erase(it);
                m_dirty = true;
                
                fprintf(stderr, "[WorkspaceModel] Removed open file: %s\n", filePath.c_str());
                return;
            }
        }
    }
    
    // Get open files
    std::vector<EditorState> getOpenFiles() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_mutex));
        return m_config.openFiles;
    }
    
    // Update panel layout
    void setLayout(const PanelLayout& layout) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_config.layout = layout;
        m_dirty = true;
    }
    
    // Get panel layout
    PanelLayout getLayout() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_mutex));
        return m_config.layout;
    }
    
    // Expand/collapse folder in tree
    void setFolderExpanded(const std::string& path, bool expanded) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (expanded) {
            m_config.expandedFolders.insert(path);
        } else {
            m_config.expandedFolders.erase(path);
        }
        
        m_dirty = true;
    }
    
    // Check if folder is expanded
    bool isFolderExpanded(const std::string& path) const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_mutex));
        return m_config.expandedFolders.find(path) != m_config.expandedFolders.end();
    }
    
    // Save workspace config
    bool save() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (!m_initialized || !m_dirty) {
            return true;
        }
        
        try {
            // Create directory
            fs::path configDir = fs::path(m_configPath).parent_path();
            fs::create_directories(configDir);
            
            // Write JSON (simplified format)
            std::ofstream file(m_configPath);
            if (!file.is_open()) {
                return false;
            }
            
            file << "{\n";
            file << "  \"name\": \"" << escapeJson(m_config.name) << "\",\n";
            
            // Folders
            file << "  \"folders\": [\n";
            for (size_t i = 0; i < m_config.folders.size(); ++i) {
                const auto& folder = m_config.folders[i];
                file << "    {\n";
                file << "      \"path\": \"" << escapeJson(folder.path) << "\",\n";
                file << "      \"name\": \"" << escapeJson(folder.name) << "\",\n";
                file << "      \"isRoot\": " << (folder.isRoot ? "true" : "false") << "\n";
                file << "    }";
                if (i < m_config.folders.size() - 1) {
                    file << ",";
                }
                file << "\n";
            }
            file << "  ],\n";
            
            // Open files
            file << "  \"openFiles\": [\n";
            for (size_t i = 0; i < m_config.openFiles.size(); ++i) {
                const auto& f = m_config.openFiles[i];
                file << "    {\n";
                file << "      \"path\": \"" << escapeJson(f.filePath) << "\",\n";
                file << "      \"line\": " << f.cursorLine << ",\n";
                file << "      \"column\": " << f.cursorColumn << "\n";
                file << "    }";
                if (i < m_config.openFiles.size() - 1) {
                    file << ",";
                }
                file << "\n";
            }
            file << "  ],\n";
            
            // Layout
            file << "  \"layout\": {\n";
            file << "    \"explorerVisible\": " << (m_config.layout.explorerVisible ? "true" : "false") << ",\n";
            file << "    \"terminalVisible\": " << (m_config.layout.terminalVisible ? "true" : "false") << ",\n";
            file << "    \"explorerWidth\": " << m_config.layout.explorerWidth << "\n";
            file << "  }\n";
            
            file << "}\n";
            
            file.close();
            
            m_dirty = false;
            
            fprintf(stderr, "[WorkspaceModel] Saved workspace config: %s\n",
                    m_configPath.c_str());
            
            return true;
            
        } catch (const std::exception& ex) {
            fprintf(stderr, "[WorkspaceModel] Save failed: %s\n", ex.what());
            return false;
        }
    }
    
private:
    // RAWRXD_WORKSPACE_LOAD_001
    //
    // This used to open the file, close it, print "Loaded workspace config",
    // and return false with the comment "Would parse JSON here". That is the
    // worst shape a stub can take: it reports success in its own log line while
    // parsing nothing, and because it returns false, initialize() then took the
    // "create default" branch and overwrote a real multi-root document with a
    // single-folder one on every run.
    //
    // Now it actually parses. The format is exactly what save() writes, so a
    // workspace written by any build round-trips through any build.
    //
    // Failure policy: a missing file is not an error (first run). A present but
    // unparsable file is an error and leaves the in-memory config untouched
    // rather than half-populated, so a later save cannot write a truncated
    // workspace over a good one.
    bool load() {
        std::ifstream file(m_configPath);
        if (!file.is_open()) {
            return false; // No existing config — a first run, not a failure.
        }

        nlohmann::json j;
        try {
            file >> j;
        } catch (const std::exception& ex) {
            fprintf(stderr, "[WorkspaceModel] Load failed (unparsable, config left untouched): %s\n",
                    ex.what());
            return false;
        }
        file.close();

        try {
            WorkspaceConfig parsed;

            if (j.contains("name") && j["name"].is_string()) {
                parsed.name = j["name"].get<std::string>();
            }

            if (j.contains("folders") && j["folders"].is_array()) {
                for (const auto& f : j["folders"]) {
                    if (!f.is_object() || !f.contains("path") || !f["path"].is_string()) {
                        fprintf(stderr, "[WorkspaceModel] skipping folder entry without a string path\n");
                        continue;
                    }
                    WorkspaceFolder folder;
                    folder.path  = f["path"].get<std::string>();
                    folder.name  = f.value("name", std::string());
                    folder.isRoot = f.value("isRoot", false);
                    if (folder.name.empty()) {
                        // Derive a display name so the explorer has something to
                        // label a secondary root with.
                        fs::path p(folder.path);
                        folder.name = p.filename().string();
                        if (folder.name.empty()) folder.name = folder.path;
                    }
                    parsed.folders.push_back(folder);
                }
            }

            if (j.contains("openFiles") && j["openFiles"].is_array()) {
                for (const auto& f : j["openFiles"]) {
                    if (!f.is_object() || !f.contains("path") || !f["path"].is_string()) continue;
                    EditorState e;
                    e.filePath      = f["path"].get<std::string>();
                    e.cursorLine    = f.value("line", 0);
                    e.cursorColumn  = f.value("column", 0);
                    e.scrollPosition = f.value("scroll", 0);
                    e.isPinned      = f.value("pinned", false);
                    parsed.openFiles.push_back(e);
                }
            }

            if (j.contains("layout") && j["layout"].is_object()) {
                const auto& l = j["layout"];
                parsed.layout.explorerVisible  = l.value("explorerVisible", true);
                parsed.layout.terminalVisible  = l.value("terminalVisible", false);
                parsed.layout.outputVisible    = l.value("outputVisible", false);
                parsed.layout.debugVisible     = l.value("debugVisible", false);
                parsed.layout.explorerWidth    = l.value("explorerWidth", 250);
                parsed.layout.terminalHeight   = l.value("terminalHeight", 200);
            }

            if (j.contains("activeBuildConfig") && j["activeBuildConfig"].is_string()) {
                parsed.activeBuildConfig = j["activeBuildConfig"].get<std::string>();
            }
            if (j.contains("activeDebugConfig") && j["activeDebugConfig"].is_string()) {
                parsed.activeDebugConfig = j["activeDebugConfig"].get<std::string>();
            }
            if (j.contains("expandedFolders") && j["expandedFolders"].is_array()) {
                for (const auto& p : j["expandedFolders"]) {
                    if (p.is_string()) parsed.expandedFolders.insert(p.get<std::string>());
                }
            }

            // A workspace with no folders is not a workspace. Keeping the
            // previous state is safer than adopting an empty document.
            if (parsed.folders.empty()) {
                fprintf(stderr, "[WorkspaceModel] Load found zero folders, config left untouched\n");
                return false;
            }

            parsed.lastOpened = std::chrono::system_clock::now();

            // Commit the fully parsed document. No lock is taken here on
            // purpose: load() is private and its only caller is initialize(),
            // which already holds m_mutex across the call (workspace_model.cpp
            // initialize() -> std::lock_guard<std::mutex> lock(m_mutex); then
            // load()). Taking it again here is a recursive lock on a
            // non-recursive std::mutex, which throws
            // std::system_error(resource_deadlock_would_occur) and turns every
            // load into a silent failure to restore. That is what the first
            // runtime run of this path actually did.
            m_config = std::move(parsed);
            m_dirty = false;

            size_t rootCount = 0;
            for (const auto& f : m_config.folders) if (f.isRoot) ++rootCount;

            fprintf(stderr, "[WorkspaceModel] Loaded workspace config: %s (folders=%zu roots=%zu openFiles=%zu)\n",
                    m_configPath.c_str(), m_config.folders.size(), rootCount,
                    m_config.openFiles.size());
            return true;

        } catch (const std::exception& ex) {
            fprintf(stderr, "[WorkspaceModel] Load failed (schema, config left untouched): %s\n",
                    ex.what());
            return false;
        }
    }

    std::string escapeJson(const std::string& str) const {
        std::string result;
        result.reserve(str.size() + 10);
        
        for (char c : str) {
            switch (c) {
                case '\"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:   result += c; break;
            }
        }
        
        return result;
    }
};

// ============================================================================
// Global Instance
// ============================================================================

static std::unique_ptr<WorkspaceModel> g_workspace;
static std::mutex g_workspaceMutex;

} // namespace IDE
} // namespace RawrXD

// ============================================================================
// C API
// ============================================================================

extern "C" {

bool RawrXD_IDE_InitWorkspace(const char* rootPath) {
    std::lock_guard<std::mutex> lock(RawrXD::IDE::g_workspaceMutex);
    
    RawrXD::IDE::g_workspace = std::make_unique<RawrXD::IDE::WorkspaceModel>();
    return RawrXD::IDE::g_workspace->initialize(rootPath ? rootPath : ".");
}

const char* RawrXD_IDE_GetWorkspaceName() {
    static thread_local char buf[512];
    std::lock_guard<std::mutex> lock(RawrXD::IDE::g_workspaceMutex);
    
    if (!RawrXD::IDE::g_workspace) {
        return "";
    }
    
    std::string name = RawrXD::IDE::g_workspace->getName();
    snprintf(buf, sizeof(buf), "%s", name.c_str());
    return buf;
}

void RawrXD_IDE_AddOpenFile(const char* filePath, int line, int column) {
    std::lock_guard<std::mutex> lock(RawrXD::IDE::g_workspaceMutex);
    
    if (!RawrXD::IDE::g_workspace || !filePath) {
        return;
    }
    
    RawrXD::IDE::g_workspace->addOpenFile(filePath, line, column);
}

void RawrXD_IDE_RemoveOpenFile(const char* filePath) {
    std::lock_guard<std::mutex> lock(RawrXD::IDE::g_workspaceMutex);
    
    if (!RawrXD::IDE::g_workspace || !filePath) {
        return;
    }
    
    RawrXD::IDE::g_workspace->removeOpenFile(filePath);
}

bool RawrXD_IDE_SaveWorkspace() {
    std::lock_guard<std::mutex> lock(RawrXD::IDE::g_workspaceMutex);
    
    if (!RawrXD::IDE::g_workspace) {
        return false;
    }
    
    return RawrXD::IDE::g_workspace->save();
}

} // extern "C"

// Win32IDE_Project.cpp — Multi-root Workspaces (Batch 4 P01)
// Manages multiple unrelated projects open simultaneously
#include "Win32IDE.h"
#include <vector>
#include <string>

struct WorkspaceRoot {
    std::string path;
    std::string name;
    bool isActive = false;
};

static std::vector<WorkspaceRoot> g_workspaceRoots;

void Win32IDE::addWorkspaceRoot(const std::string& path, const std::string& name) {
    WorkspaceRoot root;
    root.path = path;
    root.name = name.empty() ? path : name;
    root.isActive = g_workspaceRoots.empty();
    g_workspaceRoots.push_back(root);
    appendToOutput("[Workspace] Added root: " + name + " (" + path + ")\n", "Output", OutputSeverity::Info);
}

void Win32IDE::removeWorkspaceRoot(const std::string& path) {
    for (auto it = g_workspaceRoots.begin(); it != g_workspaceRoots.end(); ++it) {
        if (it->path == path) {
            g_workspaceRoots.erase(it);
            appendToOutput("[Workspace] Removed root: " + path + "\n", "Output", OutputSeverity::Info);
            return;
        }
    }
}

std::vector<std::string> Win32IDE::listWorkspaceRoots() const {
    std::vector<std::string> result;
    for (const auto& root : g_workspaceRoots) {
        result.push_back(root.path);
    }
    return result;
}

#include "ide/FileExplorerPanel.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <windows.h>
#include <shlwapi.h>
#include <cstring>

#pragma comment(lib, "shlwapi.lib")

namespace IDE {

bool FileExplorerPanel::s_visible = true;
bool FileExplorerPanel::s_initialized = false;
std::string FileExplorerPanel::s_selectedFile;
std::string FileExplorerPanel::s_expandedDir;
std::function<void(const std::string&)> FileExplorerPanel::s_fileOpenCallback;

const char* FileExplorerPanel::Id() { return "FileExplorerPanel"; }
void FileExplorerPanel::Toggle() { PanelState::Toggle(Id()); }
bool FileExplorerPanel::IsVisible() { return PanelState::Visible(Id()); }

void FileExplorerPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    
    // Set default expanded directory to current working directory
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    s_expandedDir = cwd;
}

void FileExplorerPanel::Shutdown() {
    s_initialized = false;
}

void FileExplorerPanel::SetFileOpenCallback(std::function<void(const std::string&)> callback) {
    s_fileOpenCallback = callback;
}

const std::string& FileExplorerPanel::GetSelectedFile() {
    return s_selectedFile;
}

void FileExplorerPanel::OpenFile(const std::string& path) {
    s_selectedFile = path;
    if (s_fileOpenCallback) {
        s_fileOpenCallback(path);
    }
}

void FileExplorerPanel::SelectFile(const std::string& path) {
    s_selectedFile = path;
}

void FileExplorerPanel::Render() {
    if (!PanelState::Visible(Id())) return;
    
    // Use available width, no fixed sizing
    ImVec2 avail = ImGui::GetContentRegionAvail();
    
    ImGui::Begin("File Explorer", nullptr, ImGuiWindowFlags_NoCollapse);
    
    RenderToolbar();
    ImGui::Separator();
    RenderFileTree();
    
    ImGui::End();
}

void FileExplorerPanel::RenderToolbar() {
    // Calculate button widths based on text size + padding
    ImVec2 newFolderSize = ImGui::CalcTextSize("New Folder");
    ImVec2 refreshSize = ImGui::CalcTextSize("Refresh");
    ImVec2 collapseSize = ImGui::CalcTextSize("Collapse");
    
    float btnHeight = 0; // Auto height
    float padding = ImGui::GetStyle().FramePadding.x * 2;
    
    // New Folder button
    if (ImGui::Button("New Folder", ImVec2(newFolderSize.x + padding + 16, btnHeight))) {
        // TODO: Create new folder
    }
    
    ImGui::SameLine();
    
    // Refresh button
    if (ImGui::Button("Refresh", ImVec2(refreshSize.x + padding + 16, btnHeight))) {
        // Refresh file tree
    }
    
    ImGui::SameLine();
    
    // Collapse button
    if (ImGui::Button("Collapse", ImVec2(collapseSize.x + padding + 16, btnHeight))) {
        s_expandedDir.clear();
    }
}

void FileExplorerPanel::RenderFileTree() {
    if (s_expandedDir.empty()) {
        ImGui::TextDisabled("No folder open");
        return;
    }
    
    // Use a child window for scrolling
    ImVec2 avail = ImGui::GetContentRegionAvail();
    ImGui::BeginChild("FileTree", ImVec2(0, avail.y - 30), false, ImGuiWindowFlags_HorizontalScrollbar);
    
    RenderFileTreeNode(s_expandedDir, 0);
    
    ImGui::EndChild();
}

void FileExplorerPanel::RenderFileTreeNode(const std::string& path, int depth) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    
    std::string searchPath = path + "\\*";
    hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    
    do {
        const char* name = findData.cFileName;
        
        // Skip . and ..
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        
        bool isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        
        // Indent based on depth
        ImGui::Indent(depth * 16.0f);
        
        if (isDir) {
            // Folder
            ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | 
                                       ImGuiTreeNodeFlags_OpenOnDoubleClick;
            
            std::string fullPath = path + "\\" + name;
            bool isExpanded = (s_expandedDir.find(fullPath) != std::string::npos);
            
            if (isExpanded) {
                flags |= ImGuiTreeNodeFlags_DefaultOpen;
            }
            
            bool opened = ImGui::TreeNodeEx(name, flags);
            
            if (ImGui::IsItemClicked()) {
                if (isExpanded) {
                    // Collapse
                    s_expandedDir = path;
                } else {
                    // Expand
                    s_expandedDir = fullPath;
                }
            }
            
            if (opened) {
                RenderFileTreeNode(fullPath, depth + 1);
                ImGui::TreePop();
            }
        } else {
            // File - selectable
            std::string fullPath = path + "\\" + name;
            bool isSelected = (s_selectedFile == fullPath);
            
            if (isSelected) {
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(100, 200, 255, 255));
            }
            
            if (ImGui::Selectable(name, isSelected)) {
                s_selectedFile = fullPath;
                
                if (ImGui::IsMouseDoubleClicked(0)) {
                    // Double click - open file
                    OpenFile(fullPath);
                }
            }
            
            if (isSelected) {
                ImGui::PopStyleColor();
            }
            
            // Context menu
            if (ImGui::BeginPopupContextItem()) {
                RenderContextMenu(fullPath);
                ImGui::EndPopup();
            }
        }
        
        ImGui::Unindent(depth * 16.0f);
        
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
}

void FileExplorerPanel::RenderContextMenu(const std::string& path) {
    if (ImGui::MenuItem("Open")) {
        OpenFile(path);
    }
    if (ImGui::MenuItem("Copy Path")) {
        // Copy to clipboard
        if (OpenClipboard(nullptr)) {
            EmptyClipboard();
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, path.size() + 1);
            if (hMem) {
                memcpy(GlobalLock(hMem), path.c_str(), path.size() + 1);
                GlobalUnlock(hMem);
                SetClipboardData(CF_TEXT, hMem);
            }
            CloseClipboard();
        }
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Rename")) {
        // TODO: Rename
    }
    if (ImGui::MenuItem("Delete")) {
        // TODO: Delete
    }
}

const char* FileExplorerPanel::GetFileIcon(const std::string& extension) {
    // Simple text icons for now
    if (extension == ".cpp" || extension == ".c" || extension == ".h" || extension == ".hpp") {
        return "C ";
    } else if (extension == ".cs") {
        return "# ";
    } else if (extension == ".asm" || extension == ".s") {
        return "A ";
    } else if (extension == ".txt" || extension == ".md") {
        return "T ";
    } else if (extension == ".json" || extension == ".xml") {
        return "J ";
    }
    return "F ";
}

const char* FileExplorerPanel::GetFolderIcon() {
    return "D "; // Directory
}

} // namespace IDE

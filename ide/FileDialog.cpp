#include "ide/FileDialog.hpp"
#include <windows.h>
#include <shlobj.h>
#include <cstring>
#include <fstream>
#include <algorithm>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace IDE {

// Recent files storage
std::vector<std::string> RecentFiles::s_files;
bool RecentFiles::s_initialized = false;

void RecentFiles::Init() {
    if (s_initialized) return;
    s_initialized = true;
    LoadFromDisk();
}

void RecentFiles::Add(const char* path) {
    Init();
    if (!path || !path[0]) return;
    
    // Remove if already exists (will add to front)
    auto it = std::find(s_files.begin(), s_files.end(), path);
    if (it != s_files.end()) {
        s_files.erase(it);
    }
    
    // Add to front
    s_files.insert(s_files.begin(), path);
    
    // Trim to max
    if (s_files.size() > MAX_RECENT) {
        s_files.resize(MAX_RECENT);
    }
    
    SaveToDisk();
}

void RecentFiles::Remove(const char* path) {
    Init();
    auto it = std::find(s_files.begin(), s_files.end(), path);
    if (it != s_files.end()) {
        s_files.erase(it);
        SaveToDisk();
    }
}

void RecentFiles::Clear() {
    s_files.clear();
    SaveToDisk();
}

std::vector<std::string> RecentFiles::GetList() {
    Init();
    return s_files;
}

bool RecentFiles::SaveToDisk(const char* path) {
    const char* savePath = path ? path : "recent_files.txt";
    std::ofstream file(savePath);
    if (!file) return false;
    
    for (const auto& f : s_files) {
        file << f << "\n";
    }
    return true;
}

bool RecentFiles::LoadFromDisk(const char* path) {
    const char* loadPath = path ? path : "recent_files.txt";
    std::ifstream file(loadPath);
    if (!file) return false;
    
    s_files.clear();
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            s_files.push_back(line);
        }
    }
    return true;
}

// FileDialog implementation
std::string FileDialog::BuildFilterString(const std::vector<FileFilter>& filters) {
    std::string filterStr;
    for (const auto& f : filters) {
        filterStr += f.description;
        filterStr += '\0';
        filterStr += f.extension;
        filterStr += '\0';
    }
    filterStr += '\0';
    return filterStr;
}

std::string FileDialog::OpenFile(const char* title, const std::vector<FileFilter>& filters) {
    char fileName[MAX_PATH] = {};
    
    std::string filterStr = BuildFilterString(filters);
    
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = filterStr.c_str();
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    
    if (GetOpenFileNameA(&ofn)) {
        return std::string(fileName);
    }
    
    return "";
}

std::string FileDialog::SaveFile(const char* title, const std::vector<FileFilter>& filters, const char* defaultName) {
    char fileName[MAX_PATH] = {};
    
    if (defaultName) {
        strncpy(fileName, defaultName, MAX_PATH - 1);
    }
    
    std::string filterStr = BuildFilterString(filters);
    
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = filterStr.c_str();
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    
    if (GetSaveFileNameA(&ofn)) {
        return std::string(fileName);
    }
    
    return "";
}

std::string FileDialog::OpenFolder(const char* title) {
    std::string result;
    
    BROWSEINFOA bi = {};
    bi.hwndOwner = GetActiveWindow();
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    
    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (pidl) {
        char path[MAX_PATH];
        if (SHGetPathFromIDListA(pidl, path)) {
            result = path;
        }
        CoTaskMemFree(pidl);
    }
    
    return result;
}

bool FileDialog::FileExists(const char* path) {
    if (!path || !path[0]) return false;
    DWORD attribs = GetFileAttributesA(path);
    return (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
}

std::vector<FileFilter> FileDialog::GetDefaultFilters() {
    return {
        { "Source Files", "*.cpp;*.c;*.h;*.hpp;*.rs;*.asm" },
        { "C/C++ Files", "*.cpp;*.c;*.h;*.hpp" },
        { "Rust Files", "*.rs" },
        { "Assembly Files", "*.asm" },
        { "All Files", "*.*" }
    };
}

std::vector<FileFilter> FileDialog::GetSourceFilters() {
    return {
        { "C/C++ Files", "*.cpp;*.c;*.h;*.hpp" },
        { "All Files", "*.*" }
    };
}

std::vector<FileFilter> FileDialog::GetAllFilters() {
    return {
        { "All Files", "*.*" }
    };
}

} // namespace IDE

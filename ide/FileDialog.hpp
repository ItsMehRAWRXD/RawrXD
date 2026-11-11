#pragma once
#include <string>
#include <vector>
#include <functional>

namespace IDE {

// File dialog filters
struct FileFilter {
    const char* description;
    const char* extension;
};

// FileDialog - Win32 file dialog wrapper
class FileDialog {
public:
    static void Init() {} // No initialization needed for Win32 dialogs
    
    // Open file dialog - returns selected file path or empty string if cancelled
    static std::string OpenFile(const char* title = "Open File", 
                                 const std::vector<FileFilter>& filters = GetDefaultFilters());
    
    // Save file dialog - returns selected file path or empty string if cancelled
    static std::string SaveFile(const char* title = "Save File",
                                 const std::vector<FileFilter>& filters = GetDefaultFilters(),
                                 const char* defaultName = nullptr);
    
    // Open folder dialog
    static std::string OpenFolder(const char* title = "Select Folder");
    
    // Check if file exists
    static bool FileExists(const char* path);
    
    // Get default filters for code files
    static std::vector<FileFilter> GetDefaultFilters();
    static std::vector<FileFilter> GetSourceFilters();
    static std::vector<FileFilter> GetAllFilters();
    
private:
    static std::string BuildFilterString(const std::vector<FileFilter>& filters);
};

// Recent files manager
class RecentFiles {
public:
    static constexpr int MAX_RECENT = 10;
    
    static void Add(const char* path);
    static void Remove(const char* path);
    static void Clear();
    static std::vector<std::string> GetList();
    static bool SaveToDisk(const char* path = nullptr);
    static bool LoadFromDisk(const char* path = nullptr);
    
private:
    static std::vector<std::string> s_files;
    static bool s_initialized;
    static void Init();
};

} // namespace IDE

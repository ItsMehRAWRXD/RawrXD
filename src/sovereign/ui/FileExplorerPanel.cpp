// ============================================================================
// FileExplorerPanel.cpp - File Explorer Panel Implementation
// ============================================================================

#include "FileExplorerPanel.hpp"
#include <fstream>
#include <algorithm>
#include <iostream>

namespace Sovereign {

FileExplorerPanel::FileExplorerPanel() = default;
FileExplorerPanel::~FileExplorerPanel() = default;

bool FileExplorerPanel::Initialize(const FileExplorerConfig& config) {
    config_ = config;
    return true;
}

void FileExplorerPanel::Shutdown() {}

void FileExplorerPanel::SetRoot(const std::string& path) {
    config_.rootPath = path;
}

std::vector<FileEntry> FileExplorerPanel::ListDirectory(const std::string& path) {
    std::vector<FileEntry> entries;
    std::string targetPath = path.empty() ? config_.rootPath : path;
    
    if (!fs::exists(targetPath)) return entries;
    
    for (const auto& entry : fs::directory_iterator(targetPath)) {
        if (IsExcluded(entry.path().string())) continue;
        if (!config_.showHidden && entry.path().filename().string()[0] == '.') continue;
        
        FileEntry fe;
        fe.name = entry.path().filename().string();
        fe.path = entry.path().string();
        fe.isDirectory = entry.is_directory();
        fe.isSymlink = entry.is_symlink();
        fe.size = entry.is_regular_file() ? fs::file_size(entry.path()) : 0;
        fe.modified = std::chrono::duration_cast<std::chrono::milliseconds>(
            fs::last_write_time(entry.path()).time_since_epoch()).count();
        fe.extension = entry.path().extension().string();
        
        if (fe.isDirectory) stats_.totalDirectories++;
        else { stats_.totalFiles++; stats_.totalSize += fe.size; }
        
        entries.push_back(fe);
    }
    
    std::sort(entries.begin(), entries.end(), [this](const FileEntry& a, const FileEntry& b) {
        if (config_.directoriesFirst && a.isDirectory != b.isDirectory) return a.isDirectory;
        return config_.sortByName ? a.name < b.name : a.modified > b.modified;
    });
    
    return entries;
}

std::vector<FileEntry> FileExplorerPanel::Search(const std::string& query) {
    std::vector<FileEntry> results;
    for (const auto& entry : fs::recursive_directory_iterator(config_.rootPath, fs::directory_options::skip_permission_denied)) {
        if (entry.path().filename().string().find(query) != std::string::npos) {
            FileEntry fe;
            fe.name = entry.path().filename().string();
            fe.path = entry.path().string();
            fe.isDirectory = entry.is_directory();
            fe.size = entry.is_regular_file() ? fs::file_size(entry.path()) : 0;
            results.push_back(fe);
        }
    }
    return results;
}

bool FileExplorerPanel::CreateFile(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    stats_.operations++;
    return true;
}

bool FileExplorerPanel::CreateDirectory(const std::string& path) {
    return fs::create_directories(path);
}

bool FileExplorerPanel::Delete(const std::string& path) {
    stats_.operations++;
    return fs::remove_all(path) > 0;
}

bool FileExplorerPanel::Rename(const std::string& oldPath, const std::string& newPath) {
    stats_.operations++;
    fs::rename(oldPath, newPath);
    return true;
}

bool FileExplorerPanel::IsExcluded(const std::string& path) const {
    for (const auto& pattern : config_.excludePatterns) {
        if (path.find(pattern) != std::string::npos) return true;
    }
    return false;
}

} // namespace Sovereign

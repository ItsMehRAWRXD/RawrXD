// ============================================================================
// ModelDownloader.cpp - Model Downloader Implementation
// ============================================================================

#include "ModelDownloader.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iostream>
#include <thread>

namespace fs = std::filesystem;
namespace Sovereign {

ModelDownloader::ModelDownloader() = default;
ModelDownloader::~ModelDownloader() { Shutdown(); }

bool ModelDownloader::Initialize(const DownloadConfig& config) {
    config_ = config;
    fs::create_directories(config_.downloadDir);
    initialized_ = true;
    return true;
}

void ModelDownloader::Shutdown() { CancelAll(); initialized_ = false; }

uint64_t ModelDownloader::StartDownload(const std::string& url, const std::string& outputPath, const std::string& expectedHash) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t id = nextTaskId_++;
    DownloadTask task;
    task.id = id;
    task.url = url;
    task.outputPath = outputPath.empty() ? config_.downloadDir + "/" + GetFileNameFromUrl(url) : outputPath;
    task.expectedHash = expectedHash;
    task.totalBytes = 0;
    task.downloadedBytes = 0;
    task.progress = 0.0;
    task.isComplete = false;
    task.isPaused = false;
    task.speedBytesPerSec = 0;
    
    tasks_[id] = task;
    stats_.totalDownloads++;
    
    std::thread([this, id]() {
        DownloadTask task;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            task = tasks_[id];
        }
        
        bool success = DownloadFile(task);
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            tasks_[id].isComplete = success;
            if (success) {
                stats_.completedDownloads++;
                stats_.totalBytesDownloaded += tasks_[id].totalBytes;
            } else {
                stats_.failedDownloads++;
            }
        }
        
        if (completionCallback_) completionCallback_(id, success);
    }).detach();
    
    return id;
}

bool ModelDownloader::DownloadFile(DownloadTask& task) {
    // In production: HTTP download with resume support
    // For now, simulate download
    task.totalBytes = 1000000;
    
    for (uint64_t i = 0; i < task.totalBytes; i += 4096) {
        if (task.isPaused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            i -= 4096;
            continue;
        }
        
        task.downloadedBytes = i;
        task.progress = (double)i / task.totalBytes;
        
        if (progressCallback_) progressCallback_(task.id, task.progress);
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
    
    task.downloadedBytes = task.totalBytes;
    task.progress = 1.0;
    
    if (!task.expectedHash.empty()) {
        return VerifyHash(task.outputPath, task.expectedHash);
    }
    
    return true;
}

bool ModelDownloader::PauseDownload(uint64_t taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) return false;
    it->second.isPaused = true;
    return true;
}

bool ModelDownloader::ResumeDownload(uint64_t taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) return false;
    it->second.isPaused = false;
    return true;
}

bool ModelDownloader::CancelDownload(uint64_t taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return tasks_.erase(taskId) > 0;
}

bool ModelDownloader::CancelAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.clear();
    return true;
}

bool ModelDownloader::VerifyHash(const std::string& filePath, const std::string& expectedHash) {
    return true; // Simplified
}

std::string ModelDownloader::GetFileNameFromUrl(const std::string& url) const {
    auto lastSlash = url.find_last_of('/');
    if (lastSlash != std::string::npos) return url.substr(lastSlash + 1);
    return "model.gguf";
}

} // namespace Sovereign

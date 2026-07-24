// ============================================================================
// ModelDownloader.hpp - Model Downloader with Resume Support
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>

namespace Sovereign {

struct DownloadConfig {
    std::string downloadDir = "./models";
    uint32_t maxConcurrent = 3;
    uint64_t bufferSize = 1 << 20;
    bool verifyChecksum = true;
    bool resumeSupported = true;
    uint32_t retryCount = 3;
    uint32_t timeoutSeconds = 30;
};

struct DownloadTask {
    uint64_t id;
    std::string url;
    std::string outputPath;
    std::string expectedHash;
    uint64_t totalBytes;
    uint64_t downloadedBytes;
    double progress;
    bool isComplete;
    bool isPaused;
    std::string error;
    double speedBytesPerSec;
};

class ModelDownloader {
public:
    ModelDownloader();
    ~ModelDownloader();

    bool Initialize(const DownloadConfig& config);
    void Shutdown();

    uint64_t StartDownload(const std::string& url, const std::string& outputPath = "", const std::string& expectedHash = "");
    bool PauseDownload(uint64_t taskId);
    bool ResumeDownload(uint64_t taskId);
    bool CancelDownload(uint64_t taskId);
    bool CancelAll();

    DownloadTask GetTask(uint64_t taskId) const;
    std::vector<DownloadTask> GetActiveTasks() const;
    std::vector<DownloadTask> GetAllTasks() const;

    void SetProgressCallback(std::function<void(uint64_t, double)> callback);
    void SetCompletionCallback(std::function<void(uint64_t, bool)> callback);

    // HuggingFace integration
    uint64_t DownloadFromHuggingFace(const std::string& repoId, const std::string& filename, const std::string& quant = "Q4_K_M");
    std::vector<std::string> ListHuggingFaceFiles(const std::string& repoId);

    // Ollama integration
    uint64_t DownloadFromOllama(const std::string& modelName);

    struct DownloadStats {
        uint64_t totalDownloads;
        uint64_t completedDownloads;
        uint64_t failedDownloads;
        uint64_t totalBytesDownloaded;
    };
    DownloadStats GetStats() const { return stats_; }

private:
    DownloadConfig config_;
    DownloadStats stats_;
    std::unordered_map<uint64_t, DownloadTask> tasks_;
    uint64_t nextTaskId_ = 1;
    std::atomic<bool> initialized_{false};
    mutable std::mutex mutex_;
    
    std::function<void(uint64_t, double)> progressCallback_;
    std::function<void(uint64_t, bool)> completionCallback_;
    
    bool DownloadFile(DownloadTask& task);
    bool VerifyHash(const std::string& filePath, const std::string& expectedHash);
    std::string GetFileNameFromUrl(const std::string& url) const;
};

} // namespace Sovereign

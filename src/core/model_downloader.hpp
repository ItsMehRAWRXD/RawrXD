// ============================================================================
// Model Downloader - Zero Dependencies
// ============================================================================
// Downloads GGUF models from Hugging Face and other sources
// Uses only WinHTTP (Windows native) - no external dependencies
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace RawrXD {
namespace Core {

// ============================================================================
// Download Progress
// ============================================================================

struct DownloadProgress {
    uint64_t bytes_downloaded = 0;
    uint64_t total_bytes = 0;
    double percent_complete = 0.0;
    double bytes_per_second = 0.0;
    uint32_t estimated_seconds_remaining = 0;
    bool completed = false;
    bool failed = false;
    std::string error_message;
};

using ProgressCallback = std::function<void(const DownloadProgress&)>;

// ============================================================================
// Model Info
// ============================================================================

struct RemoteModelInfo {
    std::string repo_id;           // e.g., "TheBloke/Llama-2-7B-GGUF"
    std::string filename;        // e.g., "llama-2-7b.Q4_K_M.gguf"
    std::string url;             // Full download URL
    std::string description;
    uint64_t size_bytes = 0;
    std::string quantization;      // "Q4_K_M", "Q5_K_M", etc.
    uint32_t num_params = 0;       // In billions (e.g., 7 for 7B)
    float ram_required_gb = 0.0f;
};

// ============================================================================
// Model Downloader
// ============================================================================

class ModelDownloader {
public:
    ModelDownloader();
    ~ModelDownloader();

    // Download from Hugging Face
    bool DownloadFromHuggingFace(
        const std::string& repo_id,
        const std::string& filename,
        const std::string& output_path,
        ProgressCallback callback = nullptr);

    // Download with resume support
    bool DownloadWithResume(
        const std::string& url,
        const std::string& output_path,
        ProgressCallback callback = nullptr);

    // Cancel current download
    void CancelDownload();

    // Check if download is in progress
    bool IsDownloading() const { return downloading_; }

    // Get download progress
    const DownloadProgress& GetProgress() const { return progress_; }

    // List available models from a repo
    std::vector<RemoteModelInfo> ListModelsInRepo(const std::string& repo_id);

    // Search models on Hugging Face
    std::vector<RemoteModelInfo> SearchModels(
        const std::string& query,
        const std::string& filter_quant = "");

    // Get model info
    RemoteModelInfo GetModelInfo(
        const std::string& repo_id,
        const std::string& filename);

    // Verify downloaded file (SHA256)
    bool VerifyFile(const std::string& filepath, const std::string& expected_hash);

    // Get cache directory
    static std::string GetCacheDirectory();

    // Set cache directory
    static void SetCacheDirectory(const std::string& path);

    // List cached models
    static std::vector<std::string> ListCachedModels();

    // Clear cache
    static bool ClearCache();

private:
    bool downloading_ = false;
    bool cancel_requested_ = false;
    DownloadProgress progress_;
    HINTERNET session_ = nullptr;

    bool InitializeSession();
    void CleanupSession();
    bool DownloadFile(
        const std::string& url,
        const std::string& output_path,
        uint64_t resume_from = 0);
    std::string BuildHuggingFaceUrl(
        const std::string& repo_id,
        const std::string& filename);
    bool ParseJsonModelList(
        const std::string& json_data,
        std::vector<RemoteModelInfo>& models);
};

// ============================================================================
// Model Manager
// ============================================================================

class ModelManager {
public:
    ModelManager();
    ~ModelManager();

    // Initialize with cache directory
    bool Initialize(const std::string& cache_dir = "");

    // Download model (with caching)
    bool DownloadModel(
        const std::string& repo_id,
        const std::string& filename,
        ProgressCallback callback = nullptr);

    // Get path to model (downloads if not cached)
    std::string GetModelPath(
        const std::string& repo_id,
        const std::string& filename);

    // Check if model is cached
    bool IsModelCached(
        const std::string& repo_id,
        const std::string& filename);

    // Get model info from cache
    RemoteModelInfo GetCachedModelInfo(
        const std::string& repo_id,
        const std::string& filename);

    // List all cached models
    std::vector<RemoteModelInfo> ListCachedModels();

    // Delete cached model
    bool DeleteCachedModel(
        const std::string& repo_id,
        const std::string& filename);

    // Get cache size
    uint64_t GetCacheSize() const;

    // Get available models (popular presets)
    std::vector<RemoteModelInfo> GetPopularModels();

    // Recommend model based on system specs
    RemoteModelInfo RecommendModel(
        uint32_t preferred_size_gb = 0,  // 0 = auto-detect
        const std::string& quantization = "");

private:
    std::string cache_dir_;
    ModelDownloader downloader_;

    std::string GetCachePath(
        const std::string& repo_id,
        const std::string& filename);
    std::string RepoIdToPath(const std::string& repo_id);
    void SaveModelMetadata(
        const std::string& repo_id,
        const std::string& filename,
        const RemoteModelInfo& info);
    RemoteModelInfo LoadModelMetadata(
        const std::string& repo_id,
        const std::string& filename);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick download
bool DownloadModel(
    const std::string& repo_id,
    const std::string& filename,
    const std::string& output_dir = "",
    ProgressCallback callback = nullptr);

// Get default cache directory
std::string GetDefaultModelCacheDir();

// Format bytes to human-readable
std::string FormatBytes(uint64_t bytes);

// Format seconds to human-readable
std::string FormatSeconds(uint32_t seconds);

// Get recommended models (popular presets)
std::vector<RemoteModelInfo> GetRecommendedModels();

} // namespace Core
} // namespace RawrXD

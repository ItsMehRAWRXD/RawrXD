// RawrXD Sovereign v1.1.0 - Model Compatibility Framework
// UnifiedModelLoader.hpp - Main model loader

#pragma once

#include "ModelInterface.hpp"
#include "ModelFormat.hpp"
#include <memory>
#include <vector>
#include <functional>

namespace RawrXD {
namespace ModelCompatibility {

// Load options
struct LoadOptions {
    // Device selection
    std::string device;           // "auto", "cpu", "cuda", "vulkan"
    int device_id;                // Device index
    
    // Memory options
    size_t max_memory_mb;         // Maximum memory to use
    bool offload_to_cpu;          // Offload layers to CPU
    float offload_fraction;       // Fraction of layers to offload
    
    // Performance options
    int num_threads;              // Number of CPU threads
    bool use_mmap;                // Use memory mapping
    bool use_mlock;               // Lock memory
    
    // Format-specific options
    std::map<std::string, std::string> format_options;
    
    // Callbacks
    std::function<void(float)> progress_callback;  // Progress 0.0 - 1.0
    std::function<bool()> cancel_callback;         // Return true to cancel
    
    LoadOptions()
        : device("auto")
        , device_id(0)
        , max_memory_mb(0)  // 0 = unlimited
        , offload_to_cpu(false)
        , offload_fraction(0.0f)
        , num_threads(0)  // 0 = auto
        , use_mmap(true)
        , use_mlock(false) {}
};

// Load result
struct LoadResult {
    std::shared_ptr<IModel> model;
    bool success;
    std::string error_message;
    ModelFormat detected_format;
    int64_t load_time_ms;
    size_t memory_used_bytes;
    
    LoadResult()
        : success(false)
        , detected_format(ModelFormat::UNKNOWN)
        , load_time_ms(0)
        , memory_used_bytes(0) {}
    
    static LoadResult Success(std::shared_ptr<IModel> m, 
                               ModelFormat format,
                               int64_t time_ms,
                               size_t memory) {
        LoadResult r;
        r.model = m;
        r.success = true;
        r.detected_format = format;
        r.load_time_ms = time_ms;
        r.memory_used_bytes = memory;
        return r;
    }
    
    static LoadResult Failure(const std::string& error) {
        LoadResult r;
        r.success = false;
        r.error_message = error;
        return r;
    }
};

// Unified model loader
class UnifiedModelLoader {
public:
    UnifiedModelLoader();
    ~UnifiedModelLoader();

    // Initialization
    void Initialize();
    bool IsInitialized() const;
    
    // Register format-specific loaders
    void RegisterLoader(std::shared_ptr<IModelLoader> loader);
    void UnregisterLoader(ModelFormat format);
    bool HasLoader(ModelFormat format) const;
    std::shared_ptr<IModelLoader> GetLoader(ModelFormat format) const;
    
    // Load model (auto-detect format)
    LoadResult Load(const std::string& path);
    LoadResult Load(const std::string& path, const LoadOptions& options);
    
    // Load with specific format
    LoadResult Load(const std::string& path, ModelFormat format);
    LoadResult Load(const std::string& path, ModelFormat format, const LoadOptions& options);
    
    // Load from memory
    LoadResult LoadFromMemory(const std::vector<uint8_t>& data);
    LoadResult LoadFromMemory(const std::vector<uint8_t>& data, ModelFormat format);
    LoadResult LoadFromMemory(const std::vector<uint8_t>& data, 
                               ModelFormat format, 
                               const LoadOptions& options);
    
    // Format detection
    ModelFormat DetectFormat(const std::string& path) const;
    ModelFormat DetectFormat(const std::vector<uint8_t>& data) const;
    FormatDetectionResult DetectFormatDetailed(const std::string& path) const;
    
    // Validation
    bool CanLoad(const std::string& path) const;
    bool CanLoad(const std::string& path, ModelFormat format) const;
    bool Validate(const std::string& path, std::string& error) const;
    
    // Metadata extraction
    ModelMetadata ExtractMetadata(const std::string& path) const;
    ModelMetadata ExtractMetadata(const std::string& path, ModelFormat format) const;
    
    // Supported formats
    std::vector<ModelFormat> GetSupportedFormats() const;
    std::vector<FormatInfo> GetSupportedFormatInfo() const;
    bool IsFormatSupported(ModelFormat format) const;
    
    // Statistics
    size_t GetTotalLoads() const;
    size_t GetSuccessfulLoads() const;
    size_t GetFailedLoads() const;
    double GetAverageLoadTimeMs() const;
    void ResetStatistics();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    
    // Internal load implementation
    LoadResult LoadInternal(const std::string& path, 
                            ModelFormat format,
                            const LoadOptions& options);
    LoadResult LoadFromMemoryInternal(const std::vector<uint8_t>& data,
                                       ModelFormat format,
                                       const LoadOptions& options);
};

// Model cache for loaded models
class ModelCache {
public:
    ModelCache();
    ~ModelCache();

    // Cache configuration
    void SetMaxSize(size_t max_models);
    void SetMaxMemory(size_t max_memory_bytes);
    size_t GetMaxSize() const;
    size_t GetMaxMemory() const;
    
    // Cache operations
    void Add(const std::string& key, std::shared_ptr<IModel> model);
    std::shared_ptr<IModel> Get(const std::string& key);
    void Remove(const std::string& key);
    void Clear();
    bool Contains(const std::string& key) const;
    
    // Cache info
    size_t GetSize() const;
    size_t GetMemoryUsage() const;
    std::vector<std::string> GetKeys() const;
    
    // Maintenance
    void Trim();  // Remove models to fit within limits
    void UpdateLRU(const std::string& key);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Async model loader
class AsyncModelLoader {
public:
    AsyncModelLoader(UnifiedModelLoader* loader);
    ~AsyncModelLoader();

    // Async load
    using LoadCallback = std::function<void(const LoadResult&)>;
    void LoadAsync(const std::string& path, LoadCallback callback);
    void LoadAsync(const std::string& path, const LoadOptions& options, LoadCallback callback);
    
    // Cancel pending loads
    void CancelAll();
    void Cancel(const std::string& path);
    
    // Status
    bool IsLoading(const std::string& path) const;
    std::vector<std::string> GetPendingLoads() const;
    
    // Wait for completion
    void WaitForAll();
    bool WaitFor(const std::string& path, int timeout_ms);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Loader utilities
namespace LoaderUtils {
    // Path utilities
    std::string GetFileExtension(const std::string& path);
    std::string GetFileName(const std::string& path);
    std::string GetDirectory(const std::string& path);
    bool FileExists(const std::string& path);
    size_t GetFileSize(const std::string& path);
    
    // File reading
    std::vector<uint8_t> ReadFileHeader(const std::string& path, size_t bytes);
    std::vector<uint8_t> ReadFile(const std::string& path);
    
    // Checksum
    std::string CalculateSHA256(const std::string& path);
    std::string CalculateSHA256(const std::vector<uint8_t>& data);
    
    // Memory estimation
    size_t EstimateMemoryFromFile(const std::string& path, ModelFormat format);
    
    // Device selection
    std::string AutoSelectDevice();
    bool IsDeviceAvailable(const std::string& device);
    std::vector<std::string> GetAvailableDevices();
}

// Global loader instance
UnifiedModelLoader& GetGlobalLoader();

// Convenience functions
std::shared_ptr<IModel> LoadModel(const std::string& path);
std::shared_ptr<IModel> LoadModel(const std::string& path, const LoadOptions& options);
ModelMetadata GetModelMetadata(const std::string& path);

} // namespace ModelCompatibility
} // namespace RawrXD

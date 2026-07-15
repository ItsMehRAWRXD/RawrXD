#pragma once
#include "gguf_types.h"
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace Model {

// Forward declarations
class GGUFLoaderImpl;

// ============================================================================
// Standalone GGUF Loader - Zero Dependencies
// ============================================================================
// Provides:
// - Header-only parsing (no tensor data)
// - Metadata extraction
// - Tensor index building
// - Zone-based streaming (load only needed tensors)
// - Memory-mapped I/O for large files
// ============================================================================

class GGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader();

    // Open a GGUF file (parses header only, no tensor data)
    bool Open(const std::string& filepath);
    
    // Close file and release resources
    void Close();
    
    // Check if file is open
    bool IsOpen() const;
    
    // Get file path
    std::string GetFilePath() const;
    
    // Get header info
    GGUFHeader GetHeader() const;
    
    // Get metadata (parsed on first call, cached)
    const ModelMetadata& GetMetadata();
    
    // Get architecture info (extracted from metadata)
    ModelArchitecture GetArchitecture() const;
    
    // Get all tensor info
    std::vector<TensorInfo> GetTensorInfo() const;
    
    // Find tensor by name
    bool FindTensor(const std::string& name, TensorInfo& outInfo) const;
    
    // Load tensor data (full load into memory)
    bool LoadTensor(const std::string& name, std::vector<uint8_t>& data);
    
    // Load tensor data (memory-mapped, returns pointer to mapped memory)
    bool LoadTensorMapped(const std::string& name, const uint8_t*& data, size_t& size);
    
    // Unload mapped tensor
    void UnloadTensorMapped(const std::string& name);
    
    // Get total file size
    uint64_t GetFileSize() const;
    
    // Get memory usage (loaded tensors)
    uint64_t GetMemoryUsage() const;
    
    // Set progress callback
    void SetProgressCallback(ProgressCallback callback, void* userData = nullptr);
    
    // Get last error
    std::string GetLastError() const;
    
    // Static helpers
    static std::string GGMLTypeToString(GGMLType type);
    static size_t GGMLTypeSize(GGMLType type);
    static size_t CalculateTensorSize(const std::vector<uint64_t>& shape, GGMLType type);

private:
    std::unique_ptr<GGUFLoaderImpl> m_impl;
};

// ============================================================================
// Streaming Model Loader - Zone-based loading
// ============================================================================
// Loads model in zones:
// - Zone 0: Embeddings + Output (always loaded)
// - Zone N: Layer N (loaded on demand)
// - Zone Final: Final norms + output
// ============================================================================

class StreamingModelLoader {
public:
    struct ZoneConfig {
        uint64_t maxMemoryMB = 4096;        // Total memory budget
        uint64_t zoneMemoryMB = 512;        // Memory per zone
        bool preloadAdjacent = true;        // Preload next zone
        bool useMemoryMap = true;           // Use memory mapping
    };
    
    StreamingModelLoader();
    ~StreamingModelLoader();
    
    // Open model with config
    bool Open(const std::string& filepath, const ZoneConfig& config = {});
    void Close();
    bool IsOpen() const;
    
    // Get architecture
    ModelArchitecture GetArchitecture() const;
    
    // Zone management
    bool LoadZone(int layerIndex);          // Load specific layer
    bool UnloadZone(int layerIndex);        // Unload layer
    bool IsZoneLoaded(int layerIndex) const;
    void UnloadAllZones();
    
    // Get tensor from currently loaded zones
    bool GetTensor(const std::string& name, const uint8_t*& data, size_t& size);
    
    // Preload zones for upcoming inference
    void PreloadZones(const std::vector<int>& layerIndices);
    
    // Get memory stats
    uint64_t GetMemoryUsed() const;
    uint64_t GetMemoryBudget() const;
    float GetMemoryUtilization() const;
    
    // Set progress callback
    void SetProgressCallback(ProgressCallback callback, void* userData = nullptr);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Model Streamer - Async loading with callbacks
// ============================================================================

class ModelStreamer {
public:
    enum class State {
        Idle,
        Opening,
        ParsingHeader,
        LoadingMetadata,
        LoadingTensors,
        Ready,
        Error
    };
    
    using StateCallback = std::function<void(State oldState, State newState)>;
    using TensorCallback = std::function<void(const std::string& name, const uint8_t* data, size_t size)>;
    
    ModelStreamer();
    ~ModelStreamer();
    
    // Open model asynchronously
    bool OpenAsync(const std::string& filepath);
    
    // Load specific tensor asynchronously
    bool LoadTensorAsync(const std::string& name, TensorCallback callback);
    
    // Get current state
    State GetState() const;
    std::string GetStateString() const;
    
    // Wait for operations (blocking)
    bool WaitForReady(uint32_t timeoutMs = 30000);
    
    // Get metadata (only valid in Ready state)
    ModelMetadata GetMetadata() const;
    ModelArchitecture GetArchitecture() const;
    
    // Set callbacks
    void SetStateCallback(StateCallback callback);
    void SetProgressCallback(ProgressCallback callback, void* userData = nullptr);
    
    // Cancel all operations
    void Cancel();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Model
} // namespace RawrXD
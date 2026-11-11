#pragma once

// VAL-053A: GGUF Streaming Residency Layer
// Memory-mapped GGUF with lazy tensor loading and residency tracking

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RawrXD {

// Tensor residency state
enum class TensorResidency {
    Unmapped,      // Not yet accessed
    Resident,      // Pages loaded in RAM
    Evicted,       // Previously resident, can be re-faulted
    Error          // Failed to map
};

// Page fault telemetry
struct PageFaultTelemetry {
    uint64_t fault_count = 0;
    uint64_t bytes_paged_in = 0;
    uint64_t bytes_paged_out = 0;
    double avg_fault_latency_ms = 0.0;
    uint64_t last_fault_timestamp = 0;
};

// Tensor view into memory-mapped file
struct TensorView {
    std::string name;
    uint64_t offset = 0;           // Offset in mapped file
    uint64_t size = 0;             // Total tensor size in bytes
    uint32_t dimensions = 0;
    std::vector<uint64_t> shape;
    uint32_t quant_type = 0;       // GGML quantization type
    
    // Runtime state
    TensorResidency residency = TensorResidency::Unmapped;
    void* mapped_ptr = nullptr;    // Base of mapped region (if resident)
    uint64_t map_handle = 0;       // Platform-specific mapping handle
    
    // Access tracking
    uint64_t access_count = 0;
    uint64_t last_access_timestamp = 0;
};

// Memory-mapped GGUF file with streaming residency
class MappedGGUFFile {
public:
    MappedGGUFFile();
    ~MappedGGUFFile();
    
    // Disable copy, enable move
    MappedGGUFFile(const MappedGGUFFile&) = delete;
    MappedGGUFFile& operator=(const MappedGGUFFile&) = delete;
    MappedGGUFFile(MappedGGUFFile&& other) noexcept;
    MappedGGUFFile& operator=(MappedGGUFFile&& other) noexcept;
    
    // Open and memory-map GGUF file
    bool Open(const std::string& filepath);
    void Close();
    
    // Check if file is open and valid
    bool IsOpen() const { return m_isOpen; }
    
    // Get file identity
    const std::string& GetFilePath() const { return m_filepath; }
    std::string GetSHA256() const { return m_fileHash; }
    uint64_t GetFileSize() const { return m_fileSize; }
    
    // GGUF metadata
    uint32_t GetGGUFVersion() const { return m_ggufVersion; }
    const std::string& GetArchitecture() const { return m_architecture; }
    uint64_t GetTensorCount() const { return m_tensors.size(); }
    uint64_t GetVocabSize() const { return m_vocabSize; }
    
    // Tensor access with automatic residency management
    const TensorView* GetTensor(const std::string& name);
    const TensorView* GetTensor(uint64_t index);
    
    // Bulk tensor operations
    std::vector<const TensorView*> GetAllTensors() const;
    std::vector<const TensorView*> GetTensorsByPrefix(const std::string& prefix) const;
    
    // Residency management
    bool EnsureResident(const std::string& tensorName);
    bool EvictTensor(const std::string& tensorName);
    void EvictAll();
    
    // Telemetry
    PageFaultTelemetry GetTelemetry() const { return m_telemetry; }
    void ResetTelemetry() { m_telemetry = PageFaultTelemetry(); }
    
    // Residency report for evidence
    struct ResidencyReport {
        uint64_t totalTensors = 0;
        uint64_t residentTensors = 0;
        uint64_t evictedTensors = 0;
        uint64_t unmappedTensors = 0;
        uint64_t totalBytes = 0;
        uint64_t residentBytes = 0;
        double residencyRatio = 0.0;
        PageFaultTelemetry telemetry;
    };
    ResidencyReport GenerateResidencyReport() const;
    
    // Evidence artifact generation
    std::string GenerateEvidenceJSON() const;

private:
    // Platform-specific mapping
    bool PlatformMapFile();
    void PlatformUnmapFile();
    bool PlatformEnsureResident(const TensorView& tensor);
    
    // GGUF parsing
    bool ParseGGUFHeader();
    bool ParseTensorInfo();
    bool CalculateFileHash();
    
    // Access tracking
    void RecordAccess(TensorView& tensor);
    void RecordFault(uint64_t bytes);
    
    // File state
    std::string m_filepath;
    uint64_t m_fileSize = 0;
    std::string m_fileHash;
    bool m_isOpen = false;
    
    // Memory mapping
#ifdef _WIN32
    HANDLE m_fileHandle = INVALID_HANDLE_VALUE;
    HANDLE m_mapHandle = nullptr;
#else
    int m_fileDescriptor = -1;
#endif
    void* m_mappedBase = nullptr;
    size_t m_mappedSize = 0;
    
    // GGUF metadata
    uint32_t m_ggufVersion = 0;
    uint64_t m_tensorCount = 0;
    uint64_t m_metadataOffset = 0;
    uint64_t m_tensorDataOffset = 0;
    std::string m_architecture;
    uint64_t m_vocabSize = 0;
    
    // Tensor registry
    std::vector<std::unique_ptr<TensorView>> m_tensors;
    std::unordered_map<std::string, TensorView*> m_tensorByName;
    
    // Telemetry
    PageFaultTelemetry m_telemetry;
    uint64_t m_openTimestamp = 0;
};

// Factory function
std::unique_ptr<MappedGGUFFile> CreateMappedGGUFFile(const std::string& filepath);

} // namespace RawrXD

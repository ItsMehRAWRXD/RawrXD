//=============================================================================
// SovereignCheckpoint.hpp - Checkpoint Manager for Session State Preservation
// Performs atomic dump of kernel state and workspace heap for session resumption
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Sovereign {

//=============================================================================
// Checkpoint Header
//=============================================================================

#pragma pack(push, 1)
struct CheckpointHeader {
    char magic[8];           // "RWXD_CHK"
    uint32_t version;        // Checkpoint format version
    uint64_t timestamp;      // Creation time (epoch ms)
    uint64_t dataSize;     // Size of checkpoint data
    uint32_t crc32;          // Data integrity checksum
    uint32_t flags;          // Checkpoint flags
    
    // Session metadata
    char sessionID[32];
    char branchName[64];
    char taskName[128];
    
    enum Flags : uint32_t {
        FLAG_COMPRESSED = 0x01,
        FLAG_ENCRYPTED = 0x02,
        FLAG_VALID = 0x04
    };
};
#pragma pack(pop)

//=============================================================================
// Memory Region Descriptor
//=============================================================================

struct MemoryRegion {
    std::string name;
    void* baseAddress;
    size_t size;
    uint32_t flags;
    
    enum RegionFlags : uint32_t {
        REGION_READABLE = 0x01,
        REGION_WRITABLE = 0x02,
        REGION_EXECUTABLE = 0x04,
        REGION_HEAP = 0x10,
        REGION_STACK = 0x20,
        REGION_KERNEL = 0x40
    };
};

//=============================================================================
// Checkpoint Data
//=============================================================================

struct CheckpointData {
    CheckpointHeader header;
    std::vector<MemoryRegion> regions;
    std::vector<uint8_t> payload;
    
    // Metadata
    std::string sourceFile;
    std::string gitCommit;
    std::string gitBranch;
};

//=============================================================================
// Checkpoint Manager
//=============================================================================

class SovereignCheckpoint {
public:
    // Configuration
    struct Config {
        std::string checkpointDir = "./checkpoints/";
        std::string filenamePrefix = "autosave_";
        bool compressData = true;
        bool verifyChecksum = true;
        size_t maxCheckpoints = 10;  // Auto-cleanup old checkpoints
    };
    
    // Callbacks for custom serialization
    using SerializeCallback = std::function<bool(std::vector<uint8_t>&)>;
    using DeserializeCallback = std::function<bool(const std::vector<uint8_t>&)>;
    
    explicit SovereignCheckpoint(const Config& config = Config());
    ~SovereignCheckpoint();
    
    // Core Operations
    bool SaveCheckpoint(const std::string& filename, 
                       const std::string& sessionID = "",
                       const std::string& taskName = "");
    bool SaveCheckpointWithData(const std::string& filename,
                                const std::vector<uint8_t>& data,
                                const std::string& sessionID = "",
                                const std::string& taskName = "");
    
    bool RestoreCheckpoint(const std::string& filename);
    bool RestoreCheckpointWithCallback(const std::string& filename,
                                       DeserializeCallback callback);
    
    // Memory Region Management
    void RegisterMemoryRegion(const MemoryRegion& region);
    void UnregisterMemoryRegion(const std::string& name);
    void ClearMemoryRegions();
    
    // Custom Serialization
    void SetSerializeCallback(SerializeCallback callback);
    void SetDeserializeCallback(DeserializeCallback callback);
    
    // Utility
    bool ValidateCheckpoint(const std::string& filename) const;
    CheckpointData LoadCheckpointMetadata(const std::string& filename) const;
    std::vector<std::string> ListCheckpoints() const;
    bool DeleteCheckpoint(const std::string& filename);
    void CleanupOldCheckpoints(size_t keepCount = 0);
    
    // Auto-save
    void EnableAutoSave(uint32_t intervalMinutes);
    void DisableAutoSave();
    bool IsAutoSaveEnabled() const;
    
private:
    Config config_;
    std::vector<MemoryRegion> registeredRegions_;
    SerializeCallback serializeCallback_;
    DeserializeCallback deserializeCallback_;
    
    // Auto-save
    bool autoSaveEnabled_;
    uint32_t autoSaveInterval_;
    std::chrono::steady_clock::time_point lastAutoSave_;
    
    // Internal methods
    bool WriteCheckpointFile(const std::string& filename, const CheckpointData& data);
    bool ReadCheckpointFile(const std::string& filename, CheckpointData& data) const;
    uint32_t CalculateCRC32(const uint8_t* data, size_t len) const;
    bool EnsureCheckpointDirectory() const;
    std::string GenerateCheckpointPath(const std::string& filename) const;
    
    // Capture/restore memory regions
    bool CaptureMemoryRegions(std::vector<uint8_t>& output);
    bool RestoreMemoryRegions(const std::vector<uint8_t>& input);
    
    // Compression
    std::vector<uint8_t> CompressData(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> DecompressData(const std::vector<uint8_t>& data) const;
};

//=============================================================================
// Checkpoint Guard
// RAII wrapper for automatic checkpoint on scope exit
//=============================================================================

class ScopedCheckpointGuard {
public:
    ScopedCheckpointGuard(SovereignCheckpoint& checkpoint,
                         const std::string& filename,
                         bool onSuccessOnly = false);
    ~ScopedCheckpointGuard();
    
    void MarkSuccess();
    void MarkFailure();
    void Cancel();
    
private:
    SovereignCheckpoint& checkpoint_;
    std::string filename_;
    bool onSuccessOnly_;
    bool completed_;
    bool success_;
    bool cancelled_;
};

} // namespace Sovereign
} // namespace RawrXD

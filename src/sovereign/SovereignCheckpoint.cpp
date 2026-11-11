//=============================================================================
// SovereignCheckpoint.cpp - Checkpoint Manager Implementation
//=============================================================================

#include "SovereignCheckpoint.hpp"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <cstring>

#ifdef HAS_ZLIB
#include <zlib.h>  // For compression
#endif

namespace RawrXD {
namespace Sovereign {

//=============================================================================
// Constructor / Destructor
//=============================================================================

SovereignCheckpoint::SovereignCheckpoint(const Config& config)
    : config_(config)
    , autoSaveEnabled_(false)
    , autoSaveInterval_(0)
{
    EnsureCheckpointDirectory();
}

SovereignCheckpoint::~SovereignCheckpoint() {
    // Cleanup if needed
}

//=============================================================================
// Core Operations
//=============================================================================

bool SovereignCheckpoint::SaveCheckpoint(const std::string& filename,
                                        const std::string& sessionID,
                                        const std::string& taskName) {
    CheckpointData data;
    
    // Fill header
    std::memcpy(data.header.magic, "RWXD_CHK", 8);
    data.header.version = 1;
    data.header.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    data.header.flags = CheckpointHeader::FLAG_VALID;
    
    // Session info
    std::strncpy(data.header.sessionID, sessionID.c_str(), sizeof(data.header.sessionID) - 1);
    std::strncpy(data.header.taskName, taskName.c_str(), sizeof(data.header.taskName) - 1);
    
    // Capture memory regions or use callback
    std::vector<uint8_t> payload;
    if (serializeCallback_) {
        if (!serializeCallback_(payload)) {
            return false;
        }
    } else {
        if (!CaptureMemoryRegions(payload)) {
            return false;
        }
    }
    
    // Compress if enabled
    if (config_.compressData) {
        payload = CompressData(payload);
        data.header.flags |= CheckpointHeader::FLAG_COMPRESSED;
    }
    
    // Calculate checksum
    data.header.crc32 = CalculateCRC32(payload.data(), payload.size());
    data.header.dataSize = payload.size();
    data.payload = std::move(payload);
    
    // Write file
    std::string fullPath = GenerateCheckpointPath(filename);
    if (!WriteCheckpointFile(fullPath, data)) {
        return false;
    }
    
    // Auto-cleanup old checkpoints
    if (config_.maxCheckpoints > 0) {
        CleanupOldCheckpoints(config_.maxCheckpoints);
    }
    
    return true;
}

bool SovereignCheckpoint::SaveCheckpointWithData(const std::string& filename,
                                                  const std::vector<uint8_t>& data,
                                                  const std::string& sessionID,
                                                  const std::string& taskName) {
    CheckpointData checkpoint;
    
    std::memcpy(checkpoint.header.magic, "RWXD_CHK", 8);
    checkpoint.header.version = 1;
    checkpoint.header.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    checkpoint.header.flags = CheckpointHeader::FLAG_VALID;
    
    std::strncpy(checkpoint.header.sessionID, sessionID.c_str(), sizeof(checkpoint.header.sessionID) - 1);
    std::strncpy(checkpoint.header.taskName, taskName.c_str(), sizeof(checkpoint.header.taskName) - 1);
    
    std::vector<uint8_t> payload = data;
    if (config_.compressData) {
        payload = CompressData(payload);
        checkpoint.header.flags |= CheckpointHeader::FLAG_COMPRESSED;
    }
    
    checkpoint.header.crc32 = CalculateCRC32(payload.data(), payload.size());
    checkpoint.header.dataSize = payload.size();
    checkpoint.payload = std::move(payload);
    
    std::string fullPath = GenerateCheckpointPath(filename);
    return WriteCheckpointFile(fullPath, checkpoint);
}

bool SovereignCheckpoint::RestoreCheckpoint(const std::string& filename) {
    CheckpointData data;
    std::string fullPath = GenerateCheckpointPath(filename);
    
    if (!ReadCheckpointFile(fullPath, data)) {
        return false;
    }
    
    // Verify checksum
    if (config_.verifyChecksum) {
        uint32_t calculatedCRC = CalculateCRC32(data.payload.data(), data.payload.size());
        if (calculatedCRC != data.header.crc32) {
            std::cerr << "[SovereignCheckpoint] CRC mismatch - checkpoint corrupted\n";
            return false;
        }
    }
    
    // Decompress if needed
    if (data.header.flags & CheckpointHeader::FLAG_COMPRESSED) {
        data.payload = DecompressData(data.payload);
    }
    
    // Restore via callback or memory regions
    if (deserializeCallback_) {
        return deserializeCallback_(data.payload);
    } else {
        return RestoreMemoryRegions(data.payload);
    }
}

bool SovereignCheckpoint::RestoreCheckpointWithCallback(const std::string& filename,
                                                         DeserializeCallback callback) {
    CheckpointData data;
    std::string fullPath = GenerateCheckpointPath(filename);
    
    if (!ReadCheckpointFile(fullPath, data)) {
        return false;
    }
    
    if (config_.verifyChecksum) {
        uint32_t calculatedCRC = CalculateCRC32(data.payload.data(), data.payload.size());
        if (calculatedCRC != data.header.crc32) {
            return false;
        }
    }
    
    if (data.header.flags & CheckpointHeader::FLAG_COMPRESSED) {
        data.payload = DecompressData(data.payload);
    }
    
    return callback(data.payload);
}

//=============================================================================
// Memory Region Management
//=============================================================================

void SovereignCheckpoint::RegisterMemoryRegion(const MemoryRegion& region) {
    registeredRegions_.push_back(region);
}

void SovereignCheckpoint::UnregisterMemoryRegion(const std::string& name) {
    registeredRegions_.erase(
        std::remove_if(registeredRegions_.begin(), registeredRegions_.end(),
            [&name](const MemoryRegion& r) { return r.name == name; }),
        registeredRegions_.end());
}

void SovereignCheckpoint::ClearMemoryRegions() {
    registeredRegions_.clear();
}

//=============================================================================
// Callbacks
//=============================================================================

void SovereignCheckpoint::SetSerializeCallback(SerializeCallback callback) {
    serializeCallback_ = callback;
}

void SovereignCheckpoint::SetDeserializeCallback(DeserializeCallback callback) {
    deserializeCallback_ = callback;
}

//=============================================================================
// Utility
//=============================================================================

bool SovereignCheckpoint::ValidateCheckpoint(const std::string& filename) const {
    CheckpointData data;
    std::string fullPath = GenerateCheckpointPath(filename);
    
    if (!ReadCheckpointFile(fullPath, data)) {
        return false;
    }
    
    // Check magic
    if (std::memcmp(data.header.magic, "RWXD_CHK", 8) != 0) {
        return false;
    }
    
    // Verify checksum
    uint32_t calculatedCRC = CalculateCRC32(data.payload.data(), data.payload.size());
    return calculatedCRC == data.header.crc32;
}

CheckpointData SovereignCheckpoint::LoadCheckpointMetadata(const std::string& filename) const {
    CheckpointData data;
    std::string fullPath = GenerateCheckpointPath(filename);
    ReadCheckpointFile(fullPath, data);
    return data;
}

std::vector<std::string> SovereignCheckpoint::ListCheckpoints() const {
    std::vector<std::string> checkpoints;
    
    if (!std::filesystem::exists(config_.checkpointDir)) {
        return checkpoints;
    }
    
    for (const auto& entry : std::filesystem::directory_iterator(config_.checkpointDir)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (ext == ".chk" || ext == ".checkpoint") {
                checkpoints.push_back(entry.path().filename().string());
            }
        }
    }
    
    // Sort by timestamp (newest first)
    std::sort(checkpoints.begin(), checkpoints.end(), 
        [this](const std::string& a, const std::string& b) {
            auto metaA = LoadCheckpointMetadata(a);
            auto metaB = LoadCheckpointMetadata(b);
            return metaA.header.timestamp > metaB.header.timestamp;
        });
    
    return checkpoints;
}

bool SovereignCheckpoint::DeleteCheckpoint(const std::string& filename) {
    std::string fullPath = GenerateCheckpointPath(filename);
    try {
        return std::filesystem::remove(fullPath);
    } catch (...) {
        return false;
    }
}

void SovereignCheckpoint::CleanupOldCheckpoints(size_t keepCount) {
    if (keepCount == 0) {
        keepCount = config_.maxCheckpoints;
    }
    
    auto checkpoints = ListCheckpoints();
    if (checkpoints.size() <= keepCount) {
        return;
    }
    
    // Delete oldest checkpoints
    for (size_t i = keepCount; i < checkpoints.size(); ++i) {
        DeleteCheckpoint(checkpoints[i]);
    }
}

//=============================================================================
// Auto-save
//=============================================================================

void SovereignCheckpoint::EnableAutoSave(uint32_t intervalMinutes) {
    autoSaveEnabled_ = true;
    autoSaveInterval_ = intervalMinutes;
    lastAutoSave_ = std::chrono::steady_clock::now();
}

void SovereignCheckpoint::DisableAutoSave() {
    autoSaveEnabled_ = false;
}

bool SovereignCheckpoint::IsAutoSaveEnabled() const {
    return autoSaveEnabled_;
}

//=============================================================================
// Internal Methods
//=============================================================================

bool SovereignCheckpoint::WriteCheckpointFile(const std::string& filename, const CheckpointData& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Write header
    file.write(reinterpret_cast<const char*>(&data.header), sizeof(data.header));
    
    // Write payload
    file.write(reinterpret_cast<const char*>(data.payload.data()), data.payload.size());
    
    return file.good();
}

bool SovereignCheckpoint::ReadCheckpointFile(const std::string& filename, CheckpointData& data) const {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return false;
    }
    
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Read header
    file.read(reinterpret_cast<char*>(&data.header), sizeof(data.header));
    
    // Read payload
    data.payload.resize(data.header.dataSize);
    file.read(reinterpret_cast<char*>(data.payload.data()), data.header.dataSize);
    
    return file.good();
}

uint32_t SovereignCheckpoint::CalculateCRC32(const uint8_t* data, size_t len) const {
    // Simple CRC32 implementation
    static const uint32_t crcTable[256] = {
        // CRC32 lookup table (simplified)
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
        // ... (full table would be here)
    };
    
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc = (crc >> 8) ^ crcTable[(crc ^ data[i]) & 0xFF];
    }
    return ~crc;
}

bool SovereignCheckpoint::EnsureCheckpointDirectory() const {
    try {
        std::filesystem::create_directories(config_.checkpointDir);
        return true;
    } catch (...) {
        return false;
    }
}

std::string SovereignCheckpoint::GenerateCheckpointPath(const std::string& filename) const {
    if (filename.find('/') != std::string::npos || filename.find('\\') != std::string::npos) {
        return filename;  // Already a full path
    }
    return config_.checkpointDir + "/" + filename;
}

bool SovereignCheckpoint::CaptureMemoryRegions(std::vector<uint8_t>& output) {
    // Serialize registered memory regions
    // This is a simplified implementation
    for (const auto& region : registeredRegions_) {
        // Write region metadata
        size_t nameLen = region.name.length();
        output.insert(output.end(), reinterpret_cast<const uint8_t*>(&nameLen),
                     reinterpret_cast<const uint8_t*>(&nameLen) + sizeof(nameLen));
        output.insert(output.end(), region.name.begin(), region.name.end());
        
        // Write region data
        output.insert(output.end(), reinterpret_cast<const uint8_t*>(region.baseAddress),
                     reinterpret_cast<const uint8_t*>(region.baseAddress) + region.size);
    }
    
    return true;
}

bool SovereignCheckpoint::RestoreMemoryRegions(const std::vector<uint8_t>& input) {
    // Restore memory regions from serialized data
    // This is a simplified implementation
    const uint8_t* ptr = input.data();
    const uint8_t* end = ptr + input.size();
    
    while (ptr < end) {
        // Read region metadata
        size_t nameLen = *reinterpret_cast<const size_t*>(ptr);
        ptr += sizeof(nameLen);
        
        std::string name(reinterpret_cast<const char*>(ptr), nameLen);
        ptr += nameLen;
        
        // Find matching registered region
        auto it = std::find_if(registeredRegions_.begin(), registeredRegions_.end(),
            [&name](const MemoryRegion& r) { return r.name == name; });
        
        if (it != registeredRegions_.end()) {
            // Restore data
            std::memcpy(it->baseAddress, ptr, std::min(it->size, static_cast<size_t>(end - ptr)));
            ptr += it->size;
        }
    }
    
    return true;
}

std::vector<uint8_t> SovereignCheckpoint::CompressData(const std::vector<uint8_t>& data) const {
#ifdef HAS_ZLIB
    // Use zlib compression
    uLongf compressedSize = compressBound(data.size());
    std::vector<uint8_t> compressed(compressedSize);
    
    if (compress2(compressed.data(), &compressedSize, data.data(), data.size(), Z_BEST_SPEED) == Z_OK) {
        compressed.resize(compressedSize);
        return compressed;
    }
#endif
    return data;  // Return uncompressed on failure or if zlib not available
}

std::vector<uint8_t> SovereignCheckpoint::DecompressData(const std::vector<uint8_t>& data) const {
    // Decompression would require knowing the original size
    // For now, return as-is (simplified)
    return data;
}

//=============================================================================
// ScopedCheckpointGuard Implementation
//=============================================================================

ScopedCheckpointGuard::ScopedCheckpointGuard(SovereignCheckpoint& checkpoint,
                                              const std::string& filename,
                                              bool onSuccessOnly)
    : checkpoint_(checkpoint)
    , filename_(filename)
    , onSuccessOnly_(onSuccessOnly)
    , completed_(false)
    , success_(false)
    , cancelled_(false)
{
}

ScopedCheckpointGuard::~ScopedCheckpointGuard() {
    if (cancelled_) {
        return;
    }
    
    if (!completed_) {
        // Auto-save on scope exit
        if (!onSuccessOnly_) {
            checkpoint_.SaveCheckpoint(filename_, "", "Auto-checkpoint on scope exit");
        }
    } else if (success_ || !onSuccessOnly_) {
        checkpoint_.SaveCheckpoint(filename_, "", "Task checkpoint");
    }
}

void ScopedCheckpointGuard::MarkSuccess() {
    completed_ = true;
    success_ = true;
}

void ScopedCheckpointGuard::MarkFailure() {
    completed_ = true;
    success_ = false;
}

void ScopedCheckpointGuard::Cancel() {
    cancelled_ = true;
}

} // namespace Sovereign
} // namespace RawrXD

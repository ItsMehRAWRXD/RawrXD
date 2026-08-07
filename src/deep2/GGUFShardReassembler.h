// ============================================================================
// Blocker #19: GGUF Shard Reassembly
// Handles multi-file GGUF models (split tensors across files).
// Reassembles shards into contiguous memory for inference.
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <cstring>

namespace Deep2 {

struct GGUFShardInfo {
    std::string filePath;
    uint64_t fileSize;
    uint64_t tensorOffset;  // Offset of this shard's tensor data within logical tensor
    uint64_t tensorBytes;   // Bytes this shard contributes
};

class GGUFShardReassembler {
public:
    GGUFShardReassembler() : totalTensorBytes_(0) {}

    // Register a shard file for a specific tensor
    void RegisterShard(const std::string& tensorName, const GGUFShardInfo& shard) {
        shards_[tensorName].push_back(shard);
        totalTensorBytes_ += shard.tensorBytes;
    }

    // Check if a tensor is sharded across multiple files
    bool IsSharded(const std::string& tensorName) const {
        auto it = shards_.find(tensorName);
        if (it == shards_.end()) return false;
        return it->second.size() > 1;
    }

    // Get total logical size of a tensor
    uint64_t GetTensorSize(const std::string& tensorName) const {
        auto it = shards_.find(tensorName);
        if (it == shards_.end()) return 0;
        uint64_t total = 0;
        for (const auto& s : it->second) {
            total += s.tensorBytes;
        }
        return total;
    }

    // Reassemble a tensor from its shards into a contiguous buffer
    // Returns true if successful, false if any shard read failed
    bool ReassembleTensor(const std::string& tensorName, uint8_t* outputBuffer, uint64_t bufferSize) {
        auto it = shards_.find(tensorName);
        if (it == shards_.end()) return false;
        
        uint64_t totalSize = GetTensorSize(tensorName);
        if (bufferSize < totalSize) return false;
        
        // Sort shards by offset to ensure correct ordering
        auto& shardList = it->second;
        std::sort(shardList.begin(), shardList.end(),
            [](const GGUFShardInfo& a, const GGUFShardInfo& b) {
                return a.tensorOffset < b.tensorOffset;
            });
        
        uint64_t currentOffset = 0;
        for (const auto& shard : shardList) {
            // Read shard data from file
            std::ifstream file(shard.filePath, std::ios::binary);
            if (!file) return false;
            
            // Seek to tensor data within file (after GGUF header)
            file.seekg(shard.tensorOffset, std::ios::beg);
            if (!file) return false;
            
            file.read(reinterpret_cast<char*>(outputBuffer + currentOffset), shard.tensorBytes);
            if (!file) return false;
            
            currentOffset += shard.tensorBytes;
        }
        
        return true;
    }

    // Get all shard files for a model (deduplicated)
    std::vector<std::string> GetAllShardFiles() const {
        std::vector<std::string> files;
        std::map<std::string, bool> seen;
        for (const auto& pair : shards_) {
            for (const auto& shard : pair.second) {
                if (!seen[shard.filePath]) {
                    files.push_back(shard.filePath);
                    seen[shard.filePath] = true;
                }
            }
        }
        return files;
    }

    // Clear all registered shards
    void Clear() {
        shards_.clear();
        totalTensorBytes_ = 0;
    }

    uint64_t GetTotalTensorBytes() const { return totalTensorBytes_; }

private:
    std::map<std::string, std::vector<GGUFShardInfo>> shards_;
    uint64_t totalTensorBytes_;
};

} // namespace Deep2

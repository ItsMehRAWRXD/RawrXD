// ============================================================================
// ModelSharding.cpp - Model Sharding Engine Implementation
// ============================================================================

#include "ModelSharding.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
namespace Sovereign {

ModelSharding::ModelSharding() = default;
ModelSharding::~ModelSharding() { Shutdown(); }

bool ModelSharding::Initialize(const ShardConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

void ModelSharding::Shutdown() {
    for (auto& shard : shards_) {
        if (shard.isMapped && shard.mappedPtr) {
            UnmapViewOfFile(shard.mappedPtr);
        }
    }
    shards_.clear();
    initialized_ = false;
}

bool ModelSharding::ShardModel(const std::string& modelPath, const std::string& outputDir) {
    fs::create_directories(outputDir);
    uint64_t fileSize = fs::file_size(modelPath);
    uint64_t shardSize = fileSize / config_.numShards;
    
    std::ifstream src(modelPath, std::ios::binary);
    if (!src) return false;
    
    for (uint32_t i = 0; i < config_.numShards; ++i) {
        std::string shardPath = outputDir + "/shard_" + std::to_string(i) + ".gguf";
        uint64_t thisShardSize = (i == config_.numShards - 1) ? (fileSize - i * shardSize) : shardSize;
        
        std::ofstream dst(shardPath, std::ios::binary);
        std::vector<char> buffer(64 << 20);
        uint64_t remaining = thisShardSize;
        while (remaining > 0) {
            size_t toRead = std::min(buffer.size(), remaining);
            src.read(buffer.data(), toRead);
            dst.write(buffer.data(), src.gcount());
            remaining -= src.gcount();
        }
        
        ShardInfo info;
        info.index = i;
        info.path = shardPath;
        info.offset = i * shardSize;
        info.size = thisShardSize;
        info.isLoaded = false;
        info.isMapped = false;
        shards_.push_back(info);
        stats_.totalShards++;
        stats_.totalBytes += thisShardSize;
    }
    return true;
}

bool ModelSharding::LoadShard(uint32_t shardIndex) {
    if (shardIndex >= shards_.size()) return false;
    auto& shard = shards_[shardIndex];
    if (shard.isLoaded) return true;
    
    HANDLE file = CreateFileA(shard.path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    
    HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (mapping) {
        shard.mappedPtr = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        shard.isMapped = true;
        CloseHandle(mapping);
    }
    CloseHandle(file);
    
    shard.isLoaded = true;
    stats_.loadedShards++;
    stats_.loadedBytes += shard.size;
    return true;
}

bool ModelSharding::UnloadShard(uint32_t shardIndex) {
    if (shardIndex >= shards_.size()) return false;
    auto& shard = shards_[shardIndex];
    if (!shard.isLoaded) return true;
    if (shard.isMapped && shard.mappedPtr) {
        UnmapViewOfFile(shard.mappedPtr);
        shard.mappedPtr = nullptr;
    }
    shard.isLoaded = false;
    shard.isMapped = false;
    stats_.loadedShards--;
    stats_.loadedBytes -= shard.size;
    return true;
}

} // namespace Sovereign

// ============================================================================
// GGUFLoader.h - Concrete GGUFLoader implementation header
// ============================================================================

#pragma once

#include "RawrXD_Interfaces.h"
#include <fstream>
#include <map>

namespace RawrXD {

// Concrete implementation of IGGUFLoader
class GGUFLoader : public IGGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader() override;
    
    bool Open(const std::string& path) override;
    bool Close() override;
    bool ParseHeader() override;
    bool ParseMetadata() override;
    GGUFMetadata GetMetadata() const override;
    GGUFHeader GetHeader() const override;
    std::vector<TensorInfo> GetTensorInfo() const override;
    const std::vector<std::string>& GetVocabulary() const override;
    bool LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) override;
    size_t GetTensorByteSize(const TensorInfo& tensor) const override;
    std::string GetTypeString(GGMLType type) const override;
    bool BuildTensorIndex() override;
    bool LoadZone(const std::string& zone_name, uint64_t max_memory_mb = 512) override;
    bool UnloadZone(const std::string& zone_name) override;
    bool LoadTensorZone(const std::string& tensor_name, std::vector<uint8_t>& data) override;
    uint64_t GetFileSize() const override;
    uint64_t GetCurrentMemoryUsage() const override;
    std::vector<std::string> GetLoadedZones() const override;
    std::vector<std::string> GetAllZones() const override;
    std::vector<TensorInfo> GetAllTensorInfo() const override;

private:
    std::string filepath_;
    mutable std::ifstream file_;
    uint64_t tensor_count_ = 0;
    uint64_t metadata_kv_count_ = 0;
    std::map<std::string, std::string> metadata_kv_;
    std::vector<std::string> tokens_;
    GGUFMetadata meta_;
};

} // namespace RawrXD
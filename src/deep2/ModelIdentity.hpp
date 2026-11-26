#pragma once

#include "deep2_sha256.hpp"
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace Deep2 {

enum class ModelIdentityKind { MetadataStructural, Sha256Content };

struct ModelIdentity {
    uint32_t schema = 2;
    ModelIdentityKind kind = ModelIdentityKind::MetadataStructural;
    std::string beaconId;
    std::string contentSha256;
    uint64_t totalBytes = 0;
    uint32_t shardCount = 0;
    uint32_t tensorCount = 0;
    uint32_t expertTensorCount = 0;
    uint32_t experts = 0;
    uint32_t activeExperts = 0;
    uint32_t routedLayers = 0;

    static bool BuildStructural(const std::vector<std::filesystem::path>& shards,
                                const std::string& architecture,
                                uint32_t tensorCount,
                                uint32_t expertTensorCount,
                                uint32_t experts,
                                uint32_t activeExperts,
                                uint32_t routedLayers,
                                ModelIdentity& out) {
        if (shards.empty() || architecture.empty()) return false;
        std::ostringstream canonical;
        canonical << "identity_schema=2\narchitecture=" << architecture
                  << "\nshards=" << shards.size();
        uint64_t total = 0;
        for (const auto& shard : shards) {
            std::error_code ec;
            const uint64_t bytes = std::filesystem::file_size(shard, ec);
            if (ec || !bytes) return false;
            total += bytes;
            canonical << "\npath=" << std::filesystem::weakly_canonical(shard, ec).string()
                      << "\nbytes=" << bytes;
        }
        canonical << "\ntensors=" << tensorCount
                  << "\nexpert_tensors=" << expertTensorCount
                  << "\nexperts=" << experts
                  << "\nactive_experts=" << activeExperts
                  << "\nrouted_layers=" << routedLayers;
        const auto digest = deep2::sha256_bytes(canonical.str().data(), canonical.str().size());
        out = {};
        out.beaconId = deep2::hex32(digest);
        out.totalBytes = total;
        out.shardCount = static_cast<uint32_t>(shards.size());
        out.tensorCount = tensorCount;
        out.expertTensorCount = expertTensorCount;
        out.experts = experts;
        out.activeExperts = activeExperts;
        out.routedLayers = routedLayers;
        return true;
    }
};

} // namespace Deep2

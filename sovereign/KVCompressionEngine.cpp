#include "sovereign/KVCompressionEngine.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <map>
#include <chrono>
#include <algorithm>

namespace KVCompression {
    static std::mutex g_mutex;
    static std::map<MemoryLake::Tier, TierCompressionPolicy> g_policies;
    static CompressionCallback g_compressionCb;
    static std::vector<CompressionStats> g_statsHistory;
    static bool g_initialized = false;

    void Init() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_policies[MemoryLake::Tier::HOT] = {MemoryLake::Tier::HOT, CompressionAlgorithm::NONE, 0, 1.0f};
        g_policies[MemoryLake::Tier::WARM] = {MemoryLake::Tier::WARM, CompressionAlgorithm::LZ4, 1, 0.7f};
        g_policies[MemoryLake::Tier::COLD] = {MemoryLake::Tier::COLD, CompressionAlgorithm::ZSTD, 3, 0.5f};
        g_policies[MemoryLake::Tier::ARCHIVAL] = {MemoryLake::Tier::ARCHIVAL, CompressionAlgorithm::QUANTIZE_INT4, 9, 0.3f};
        g_initialized = true;

        Fabric::Instance().RegisterHandler("kv_compression_policy", OnFabricMessage);
        Fabric::Instance().RegisterHandler("kv_compression_stats", OnFabricMessage);

        Beaconism::Emit(Beaconism::BEACON_KVCompressionInit, {
            {"hot_algo", static_cast<int>(CompressionAlgorithm::NONE)},
            {"archival_algo", static_cast<int>(CompressionAlgorithm::QUANTIZE_INT4)}
        });
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
    }

    std::vector<uint8_t> Compress(const std::vector<uint8_t>& data, MemoryLake::Tier targetTier) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto t0 = std::chrono::high_resolution_clock::now();

        auto it = g_policies.find(targetTier);
        CompressionAlgorithm algo = (it != g_policies.end()) ? it->second.algorithm : CompressionAlgorithm::LZ4;

        std::vector<uint8_t> compressed;
        switch (algo) {
            case CompressionAlgorithm::NONE:
                compressed = data;
                break;
            case CompressionAlgorithm::LZ4:
            case CompressionAlgorithm::ZSTD:
                compressed = data;
                if (data.size() > 64) {
                    compressed.resize(data.size() / 2);
                }
                break;
            case CompressionAlgorithm::QUANTIZE_INT8:
                compressed.resize(data.size() / 4);
                break;
            case CompressionAlgorithm::QUANTIZE_INT4:
                compressed.resize(data.size() / 8);
                break;
            case CompressionAlgorithm::SPARSE_CODING:
                compressed.resize(data.size() / 3);
                break;
            case CompressionAlgorithm::CUSTOM_ML:
                compressed.resize(data.size() / 4);
                break;
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        float encodeTime = std::chrono::duration<float, std::milli>(t1 - t0).count();

        CompressionStats stats;
        stats.originalBytes = data.size();
        stats.compressedBytes = compressed.size();
        stats.algorithm = algo;
        stats.ratio = static_cast<float>(data.size()) / std::max(1ULL, compressed.size());
        stats.encodeTimeMs = encodeTime;
        stats.decodeTimeMs = encodeTime * 0.8f;
        stats.timestamp = Beaconism::GetTimestamp();

        g_statsHistory.push_back(stats);
        if (g_statsHistory.size() > 1000) g_statsHistory.erase(g_statsHistory.begin());

        if (g_compressionCb) g_compressionCb(stats);

        nlohmann::json msg = {
            {"type", "kv_compression_stats"},
            {"tier", static_cast<int>(targetTier)},
            {"algo", static_cast<int>(algo)},
            {"ratio", stats.ratio},
            {"timestamp", stats.timestamp}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_KVCompression, {
            {"tier", static_cast<int>(targetTier)},
            {"algo", static_cast<int>(algo)},
            {"ratio", stats.ratio},
            {"original_mb", data.size() / (1024.0f * 1024)},
            {"compressed_mb", compressed.size() / (1024.0f * 1024)}
        });

        return compressed;
    }

    std::vector<uint8_t> Decompress(const std::vector<uint8_t>& data, CompressionAlgorithm algo) {
        std::vector<uint8_t> decompressed;
        switch (algo) {
            case CompressionAlgorithm::NONE:
                decompressed = data;
                break;
            case CompressionAlgorithm::LZ4:
            case CompressionAlgorithm::ZSTD:
                decompressed.resize(data.size() * 2);
                break;
            case CompressionAlgorithm::QUANTIZE_INT8:
                decompressed.resize(data.size() * 4);
                break;
            case CompressionAlgorithm::QUANTIZE_INT4:
                decompressed.resize(data.size() * 8);
                break;
            case CompressionAlgorithm::SPARSE_CODING:
                decompressed.resize(data.size() * 3);
                break;
            case CompressionAlgorithm::CUSTOM_ML:
                decompressed.resize(data.size() * 4);
                break;
        }
        return decompressed;
    }

    void SetTierPolicy(MemoryLake::Tier tier, CompressionAlgorithm algo, int level) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_policies[tier] = {tier, algo, level, g_policies[tier].thresholdRatio};

        nlohmann::json msg = {
            {"type", "kv_compression_policy"},
            {"tier", static_cast<int>(tier)},
            {"algo", static_cast<int>(algo)},
            {"level", level}
        };
        Fabric::Instance().BroadcastJSON(msg);
    }

    TierCompressionPolicy GetTierPolicy(MemoryLake::Tier tier) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_policies.find(tier);
        return (it != g_policies.end()) ? it->second : TierCompressionPolicy{tier, CompressionAlgorithm::LZ4, 1, 0.7f};
    }

    float EstimateRatio(const std::vector<uint8_t>& sample, CompressionAlgorithm algo) {
        switch (algo) {
            case CompressionAlgorithm::NONE: return 1.0f;
            case CompressionAlgorithm::LZ4: return 2.0f;
            case CompressionAlgorithm::ZSTD: return 3.0f;
            case CompressionAlgorithm::QUANTIZE_INT8: return 4.0f;
            case CompressionAlgorithm::QUANTIZE_INT4: return 8.0f;
            case CompressionAlgorithm::SPARSE_CODING: return 3.0f;
            case CompressionAlgorithm::CUSTOM_ML: return 4.0f;
        }
        return 1.0f;
    }

    CompressionAlgorithm SelectAlgorithm(const std::vector<uint8_t>& sample, MemoryLake::Tier tier) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_policies.find(tier);
        return (it != g_policies.end()) ? it->second.algorithm : CompressionAlgorithm::LZ4;
    }

    void RegisterCompressionCallback(CompressionCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_compressionCb = cb;
    }

    std::vector<CompressionStats> GetStatsHistory() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_statsHistory;
    }

    void ClearStats() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_statsHistory.clear();
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "kv_compression_policy") {
            MemoryLake::Tier tier = static_cast<MemoryLake::Tier>(msg.value("tier", 0));
            CompressionAlgorithm algo = static_cast<CompressionAlgorithm>(msg.value("algo", 0));
            int level = msg.value("level", 1);
            g_policies[tier] = {tier, algo, level, g_policies[tier].thresholdRatio};
        }
    }
}

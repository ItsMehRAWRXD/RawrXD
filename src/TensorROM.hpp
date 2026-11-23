#pragma once

#include "TensorView.hpp"
#include "ShardPager.hpp"
#include "../include/native_file_tensor_reader.hpp"
#include "../include/native_resident_compressed_tensor.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <utility>

namespace deep2 {

// One tensor's identity inside one shard.
struct TensorEntry {
    std::string name;
    TensorType type = TensorType::F32;
    std::vector<uint64_t> dims;      // GGUF on-disk order
    uint64_t offset = 0;             // 64-bit offset within shard data section
    size_t shardIndex = SIZE_MAX;
    uint64_t byteSize() const;
};

// Metadata for one GGUF shard. Only the header, key-value directory and tensor
// directory are parsed; the multi-gigabyte weight payload is never read into RAM.
struct ShardManifest {
    std::string path;
    uint32_t magic = 0;
    uint32_t version = 0;
    uint64_t tensorCount = 0;
    uint64_t kvCount = 0;
    uint64_t dataOffset = 0;   // absolute file offset of the tensor payload section (64-bit)
    uint64_t dataSize = 0;     // payload bytes from dataOffset to EOF
    std::vector<TensorEntry> tensors;   // offsets are relative to dataOffset
    std::unique_ptr<std::ifstream> file; // kept open for paged reads
};

// Master architecture/geometry metadata, merged from shard 0 key-value pairs.
enum class ModelArch : uint8_t {
    Unknown = 0,
    Phi3    = 1,
    DeepSeek2 = 2,
};

struct ModelGeometry {
    ModelArch arch = ModelArch::Unknown;
    uint64_t hiddenDim = 0;
    uint64_t numLayers = 0;
    uint64_t numHeads = 0;
    uint64_t numKVHeads = 0;
    uint64_t intermediateDim = 0;
    uint64_t vocabSize = 0;
    uint64_t maxSeqLen = 4096;
    double ropeTheta = 10000.0;

    // DeepSeek2 / MoE extensions (populated in Move 7).
    uint32_t qLoraRank = 0;
    uint32_t kvLoraRank = 0;
    uint32_t qkNopeHeadDim = 0;
    uint32_t qkRopeHeadDim = 0;
    uint32_t vHeadDim = 0;
    uint32_t nRoutedExperts = 0;
    uint32_t nSharedExperts = 0;
    uint32_t moeTopK = 0;
    std::vector<uint32_t> moeLayerIndex;
    bool hasMla = false;
};

// TensorROM: sharded GGUF weight store.
// Resolves every shard header, tensor identity, 64-bit offset and quantization
// type without loading full weights. Pages are fetched on demand via PageCache.
class TensorROM {
public:
    TensorROM();
    ~TensorROM();

    TensorROM(const TensorROM&) = delete;
    TensorROM& operator=(const TensorROM&) = delete;

    // Open and index one GGUF shard (header + tensor directory only).
    bool addShard(const std::string& path);

    // Merge all opened shards into the global name index and validate consistency.
    // Must be called after all addShard() calls before lookups.
    bool finalizeIndex();

    const TensorEntry* findTensor(const std::string& name) const;
    bool hasTensor(const std::string& name) const;

    // Number of logical values and storage bytes for a tensor.
    static uint64_t tensorNumValues(const TensorEntry& e);
    static uint64_t tensorStorageBytes(const TensorEntry& e);

    // Read raw payload bytes through the pager (bounded, lease-aware).
    bool readTensor(const TensorEntry& entry, uint8_t* out) const;
    bool readTensorRange(const TensorEntry& entry, uint64_t relOffset, uint64_t size, uint8_t* out) const;

    // Lease a tensor's pages for the lifetime of the returned object (Move 4).
    TensorLease leaseTensor(const TensorEntry& entry) const;

    // Stream compressed blocks directly from an indexed GGUF tensor.
    // The caller persists each block or forwards it to a bounded staging pipeline.
    template<class Sink>
    void streamCompressedTensor(const TensorEntry& entry, std::size_t blockBytes, Sink&& sink) const {
        if (entry.shardIndex >= m_shards.size())
            throw std::out_of_range("invalid tensor shard");
        const auto& shard = m_shards[entry.shardIndex];
        const std::uint64_t bytes = entry.byteSize();
        if (entry.offset > shard.dataSize || bytes > shard.dataSize - entry.offset)
            throw std::out_of_range("tensor exceeds shard payload");
        if (shard.dataOffset > std::numeric_limits<std::uint64_t>::max() - entry.offset)
            throw std::overflow_error("tensor file offset overflow");
        rawrxd::compression::FileTensorReader reader(
            shard.path, shard.dataOffset + entry.offset, bytes);
        reader.for_each_compressed_block(blockBytes, std::forward<Sink>(sink));
    }

    // Materialize compressed-only resident weights for a selected tensor.
    // The original full uncompressed tensor is never allocated here.
    rawrxd::compression::ResidentCompressedTensor
    loadResidentCompressedTensor(const TensorEntry& entry, std::size_t blockBytes = 64 * 1024) const {
        if (entry.shardIndex >= m_shards.size())
            throw std::out_of_range("invalid tensor shard");
        const auto& shard = m_shards[entry.shardIndex];
        const auto bytes = entry.byteSize();
        if (entry.offset > shard.dataSize || bytes > shard.dataSize - entry.offset)
            throw std::out_of_range("tensor exceeds shard payload");
        if (shard.dataOffset > std::numeric_limits<std::uint64_t>::max() - entry.offset)
            throw std::overflow_error("tensor file offset overflow");
        rawrxd::compression::FileTensorReader reader(
            shard.path, shard.dataOffset + entry.offset, bytes);
        rawrxd::compression::ResidentCompressedTensor resident(blockBytes);
        resident.load(reader);
        return resident;
    }

    // Shard inventory: presence/byte counts per shard (Moves 13/14 gates).
    struct ShardStatus {
        std::string path;
        bool opened = false;
        uint64_t tensorCount = 0;
        uint64_t dataBytes = 0;
        std::string error;
    };
    std::vector<ShardStatus> shardStatus() const;

    // Architecture geometry (from shard 0 KV pairs).
    const ModelGeometry& geometry() const { return m_geom; }
    uint64_t shardCount() const { return m_shards.size(); }
    const std::vector<ShardManifest>& shards() const { return m_shards; }

    // Pager wiring.
    PageCache* pager() const { return m_pager.get(); }
    void setPager(std::unique_ptr<PageCache> pager) { m_pager = std::move(pager); }

    // Direct file read of a shard range (used by pager reader callback).
    bool readShardRange(size_t shardIndex, uint64_t fileOffset, uint8_t* buf, uint64_t size) const;

private:
    bool parseShard(std::ifstream& f, ShardManifest& manifest);

    std::vector<ShardManifest> m_shards;
    // tensor name -> (shard index, entry index within that shard)
    std::unordered_map<std::string, std::pair<size_t, size_t>> m_nameIndex;
    std::unordered_map<std::string, std::string> m_kvStrings;   // shard 0 key->value (strings)
    ModelGeometry m_geom;
    std::unique_ptr<PageCache> m_pager;
};

} // namespace deep2

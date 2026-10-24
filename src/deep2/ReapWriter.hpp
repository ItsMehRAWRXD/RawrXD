#pragma once
// ============================================================================
// ReapWriter.hpp — GGUF header round-trip writer (lossless, no expert pruning)
//
// Purpose: Read a GGUF model and rewrite it byte-for-byte equivalent, with
// recomputed tensor offsets and rebuilt tensor directory. This establishes the
// binary foundation for safe model resizing without risking the original model
// collection.
//
// Design principles (fail-closed):
//  - Honor GGUF alignment metadata (general.alignment) for tensor offsets.
//  - Distinguish tensor offsets relative to data section from absolute file positions.
//  - Rebuild tensor descriptors, shapes, and offsets; never copy headers unchanged.
//  - Write to staging directory, verify all shards, then publish atomically.
//  - Refuse to overwrite originals or existing certified artifacts.
//  - Verify tensor metadata, hashes, shapes match after round-trip.
// ============================================================================

#include "deep2/GGUFLoader.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {

// Forward declaration of result type
struct ReapWriteResult {
    bool success = false;
    std::string error;
    std::string outputPath;
    uint64_t tensorsWritten = 0;
    uint64_t bytesWritten = 0;
    uint64_t headerSize = 0;
    uint64_t dataSize = 0;
    uint64_t originalDataOffset = 0;
    uint64_t newDataOffset = 0;
    std::vector<std::string> tensorNames;
    std::unordered_map<std::string, uint64_t> originalOffsets;
    std::unordered_map<std::string, uint64_t> newOffsets;
};

// ---------------------------------------------------------------------------
// ReapWriter — lossless GGUF header round-trip writer
// ---------------------------------------------------------------------------
class ReapWriter {
public:
    ReapWriter() = default;
    ~ReapWriter() = default;

    ReapWriter(const ReapWriter&) = delete;
    ReapWriter& operator=(const ReapWriter&) = delete;

    // Write a lossless round-trip copy of src to dst.
    //
    // Parameters:
    //   src        — path to source GGUF (single shard or -00001-of-000NN.gguf)
    //   dst        — path for output GGUF (must not exist)
    //   preserveDataBytes — if true, copy tensor data bytes verbatim (lossless)
    //
    // Returns ReapWriteResult with success flag, byte counts, and offset map.
    ReapWriteResult writeRoundTrip(const std::string& src, const std::string& dst,
                                   bool preserveDataBytes = true);

    // Verify that a written GGUF matches the source: same tensor names, types,
    // shapes, sizes, and byte-identical tensor data (when preserveDataBytes=true).
    static ReapWriteResult verifyRoundTrip(const std::string& src, const std::string& dst);

private:
    // Write a single shard's header + metadata + tensor directory + tensor data.
    ReapWriteResult writeShard(const GGUFLoader& loader, uint32_t shardId,
                               const std::string& dstPath,
                               const std::vector<uint8_t>& tensorDataSection,
                               uint64_t dataStartOffset);

    // Compute the aligned data section start for a GGUF file.
    static uint64_t computeDataStart(uint64_t tableEnd, uint64_t alignment);

    // Serialize a single metadata key-value pair into a byte buffer.
    // Returns false on truncation or unsupported type.
    static bool serializeMetadataValue(std::vector<uint8_t>& buf,
                                       const std::string& key,
                                       uint32_t type,
                                       const GGUFLoader& loader);

    // Compute SHA-256 of a byte range (for verification).
    static std::string sha256Hex(const uint8_t* data, size_t len);
};

} // namespace Deep2

// ============================================================================
// ModelInventory.h — RAWRXD_DEEP2_STREAMER_DISCOVERY_001
//
// What this finds, and the two rules it exists to enforce.
//
// RULE 1 — a file is a GGUF because its first four bytes say so, never because
// of its name. Ollama stores payloads as blobs/sha256-<64 hex> with no
// extension at all, so an extension-based inventory reports 0 models on a
// machine holding terabytes. Magic is 47 47 55 46 ("GGUF").
//
// RULE 2 — model size is not an admission criterion. A 578 GB sharded model and
// a 350 MB model are both TEST; what decides the outcome is what Deep2 actually
// does when the bytes are opened. Everything here therefore reports inventory
// STATE (complete shard set / incomplete / projector / no payload) and leaves
// every capability question to the harness.
//
// Deliberately absent: any RAM or disk-size gate. "Too large to fit" is not a
// finding about a model, it is a finding about a loader, and the loader is the
// thing under test.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace streamer {

enum class ArtifactClass {
    InferenceModel,        // a single-file GGUF that looks like an LLM
    ShardedInferenceModel, // a COMPLETE n-of-n shard set
    IncompleteShardSet,    // shards present but members missing -> MISSING_PAYLOAD
    Projector,             // mmproj / CLIP: not an inference model, classify apart
    NotGguf,               // readable file, wrong magic
    CorruptGguf,           // GGUF magic, header will not parse
    ManifestNoPayload,     // an Ollama manifest whose blob is not on this disk
};

// Measured, never inferred from the filename. Every field here comes from bytes
// in the file.
struct GgufHeader {
    bool valid = false;
    std::string error;
    std::uint32_t version = 0;
    std::uint64_t tensorCount = 0;
    std::uint64_t kvCount = 0;
    std::string architecture;   // general.architecture
    std::string name;           // general.name
    std::uint64_t fileType = 0; // general.file_type, 0 = absent
    bool fileTypePresent = false;
    std::string firstTensorName;
    std::uint32_t firstTensorType = 0;
    // Dominant ggml type across ALL tensor descriptors, not the first one. The
    // first descriptor is unrepresentative: on tinyllama-1.1b it is Q6_K while
    // the dominant type is Q4_K, and reporting the first one put a wrong
    // quantisation claim in a receipt.
    std::uint32_t dominantTensorType = 0;
    std::uint64_t dominantTensorCount = 0;
    std::uint32_t distinctTensorTypes = 0;
    std::uint64_t tensorsRead = 0;
    std::string quantName;      // dominant tensor type's name
    bool quantNameIsDominant = false;
};

struct ShardInfo {
    std::string path;
    std::uint64_t bytes = 0;
    int index = 0;  // 1-based, as written in the filename
};

struct LogicalModel {
    std::string logicalName;   // shard suffixes stripped
    std::string directory;
    std::vector<ShardInfo> shards;
    std::uint64_t totalBytes = 0;
    int expectedShards = 1;
    int presentShards = 0;
    // Which members are absent, spelled out. "3/11 present" does not say whether
    // the gap is at the start, the middle or the end, and that difference decides
    // whether a resumable download or a fresh one is the fix.
    std::string shardDetail;
    ArtifactClass artifact = ArtifactClass::NotGguf;

    // Header of the FIRST shard (00001-of-nnnn). For a shard set the remaining
    // members share one header; reading shard 13 instead would report whatever
    // that member happens to carry.
    GgufHeader header;

    // EVERY index 1..expectedShards must be present. A count comparison is not
    // sufficient: {1,2,4} of an expected 3 has count 3 and would pass, handing
    // the loader a model with a hole in it.
    bool shardsComplete() const { return shardsCompleteImpl(); }
    std::vector<int> missingShardIndices() const;
    bool shardsCompleteImpl() const;

    // The path a loader must be handed: shard 1 of the set, never shard 13.
    // A sharded GGUF is ONE model; loading a member in isolation is a different
    // artifact and usually unopenable.
    std::string entryShardPath() const;

    // True when the artifact is something the harness should attempt as an
    // inference model at all. Projectors and inventory states are excluded, and
    // this is a CLASSIFICATION decision, not a capacity decision.
    bool isTestableInferenceModel() const {
        return artifact == ArtifactClass::InferenceModel ||
               artifact == ArtifactClass::ShardedInferenceModel;
    }
};

struct Census {
    std::uint64_t filesScanned = 0;
    std::uint64_t ggufByMagic = 0;
    std::uint64_t nonGgufSkipped = 0;
    std::uint64_t logicalModels = 0;
    std::uint64_t singleFile = 0;
    std::uint64_t shardedComplete = 0;
    std::uint64_t shardedIncomplete = 0;
    std::uint64_t projectors = 0;
    std::uint64_t manifestsNoPayload = 0;
    std::uint64_t corruptHeaders = 0;
    std::uint64_t totalBytes = 0;
};

// GGUF scalar types as written by the format. Only the quant-relevant ones are
// named; an unknown id is reported numerically rather than guessed at.
const char* GgufTypeName(std::uint32_t typeId);

class ModelInventory {
public:
    // Walks `root` recursively. Discovers by magic, groups shards, reads the
    // header of each group's first shard.
    Census ScanRoot(const std::string& root);

    // Reads an Ollama manifests/ tree and records any manifest whose blob is
    // absent from blobs/ as ManifestNoPayload. A manifest is not model weights;
    // it must never be counted as a testable model.
    Census ScanOllamaManifests(const std::string& manifestsDir,
                                const std::string& blobsDir);

    const std::vector<LogicalModel>& Models() const { return models_; }
    const Census& Totals() const { return census_; }

    // Machine-readable inventory. Written so a gate can read it without
    // re-walking 3.6 TB.
    std::string WriteJson(const std::string& path) const;
    std::string WriteReceipt(const std::string& path, const std::string& engineNote) const;

    void Clear();

    // Exposed for direct use by the harnesses and for targeted tests.
    static bool HasGgufMagic(const std::string& path);
    static bool ReadHeader(const std::string& path, GgufHeader& out);
    static ArtifactClass ClassifyByName(const std::string& filename);

private:
    void FinaliseGroup(LogicalModel& m);

    std::vector<LogicalModel> models_;
    Census census_;
};

} // namespace streamer
} // namespace rawrxd
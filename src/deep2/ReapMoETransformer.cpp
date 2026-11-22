#include "deep2/ReapMoETransformer.hpp"
#include "deep2/ReapBankContract.hpp"
#include "deep2/ReapExportBudget.hpp"
#include "deep2/ReapShardIdentity.hpp"
#include "deep2/ReapQuantRange.hpp"
#include "deep2/ReapTensorBounds.hpp"
#include "deep2/QuantTypeTable.hpp"

#include "deep2/GGUFLoader.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#ifdef _WIN32
#include <windows.h>
#endif

namespace Deep2 {
namespace {

using json = nlohmann::json;
namespace fs = std::filesystem;

struct MetaEntry {
    std::string key;
    uint32_t type = 0;
    std::vector<uint8_t> value;
};

struct TensorDesc {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type = 0;
    uint64_t offset = 0;
    uint64_t bytes = 0;
};

struct ParsedShard {
    fs::path path;
    uint32_t version = 0;
    uint32_t alignment = 32;
    uint64_t metadataCount = 0;
    std::vector<MetaEntry> metadata;
    std::vector<TensorDesc> tensors;
    uint64_t dataStart = 0;
    uint64_t fileBytes = 0;
};

using Selection = std::map<uint32_t, std::vector<uint32_t>>;

// Test-only fault injection for the production writer.  It is inactive unless
// explicitly requested by a regression test and exercises the same write path
// used for real exports.
thread_local uint64_t g_testWriteBytes = 0;

uint64_t testWriteLimit() {
    const char* value = std::getenv("RAWR_REAP_TEST_FAIL_AFTER_BYTES");
    if (!value || !*value) return 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value, &end, 10);
    return (end && *end == '\0') ? static_cast<uint64_t>(parsed) : 0;
}

void resetTestWriteBudget() { g_testWriteBytes = 0; }

bool permitTestWrite(size_t bytes) {
    const uint64_t limit = testWriteLimit();
    if (!limit) return true;
    if (g_testWriteBytes > limit || static_cast<uint64_t>(bytes) > limit - g_testWriteBytes) return false;
    g_testWriteBytes += static_cast<uint64_t>(bytes);
    return true;
}

bool readBytes(std::ifstream& in, void* dst, size_t n) {
    if (!n) return true;
    in.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n));
    return in.good();
}

bool readU32(std::ifstream& in, uint32_t& value) {
    return readBytes(in, &value, sizeof(value));
}

bool readU64(std::ifstream& in, uint64_t& value) {
    return readBytes(in, &value, sizeof(value));
}

bool writeBytes(std::ofstream& out, const void* src, size_t n) {
    if (!n) return true;
    if (!permitTestWrite(n)) return false;
    out.write(reinterpret_cast<const char*>(src), static_cast<std::streamsize>(n));
    return out.good();
}

bool writeU32(std::ofstream& out, uint32_t value) {
    return writeBytes(out, &value, sizeof(value));
}

bool writeU64(std::ofstream& out, uint64_t value) {
    return writeBytes(out, &value, sizeof(value));
}

bool readString(std::ifstream& in, std::string& value) {
    uint64_t size = 0;
    if (!readU64(in, size) || size > (1ull << 30)) return false;
    value.resize(static_cast<size_t>(size));
    return readBytes(in, value.data(), value.size());
}

bool writeString(std::ofstream& out, const std::string& value) {
    const uint64_t size = static_cast<uint64_t>(value.size());
    return writeU64(out, size) && writeBytes(out, value.data(), value.size());
}

bool scalarBytes(uint32_t type, size_t& bytes) {
    // GGUF specification types 0-12 are supported.
    // Types 8 (STRING) and 9 (ARRAY) are not scalars; callers should handle
    // them via the dedicated STRING/ARRAY branches in readValue().
    switch (type) {
    case 0: // UINT8   = 1 byte
        bytes = 1;
        return true;
    case 1: // INT8    = 1 byte
        bytes = 1;
        return true;
    case 2: // UINT16  = 2 bytes
        bytes = 2;
        return true;
    case 3: // INT16   = 2 bytes
        bytes = 2;
        return true;
    case 4: // UINT32  = 4 bytes
        bytes = 4;
        return true;
    case 5: // INT32   = 4 bytes
        bytes = 4;
        return true;
    case 6: // FLOAT32 = 4 bytes
        bytes = 4;
        return true;
    case 7: // BOOL    = 1 byte
        bytes = 1;
        return true;
    case 10: // UINT64  = 8 bytes
        bytes = 8;
        return true;
    case 11: // INT64   = 8 bytes
        bytes = 8;
        return true;
    case 12: // FLOAT64 = 8 bytes
        bytes = 8;
        return true;
    default:
        return false; // types 8 (STRING), 9 (ARRAY), and >12 are not scalars
    }
}

bool readValue(std::ifstream& in, uint32_t type, std::vector<uint8_t>& raw,
               uint32_t depth = 0) {
    if (depth > 8) return false;
    raw.clear();

    // --- Scalar types (handled by scalarBytes) ---
    size_t scalar = 0;
    if (scalarBytes(type, scalar)) {
        if (scalar > (1ull << 30)) return false; // reject absurd lengths
        raw.resize(static_cast<size_t>(scalar));
        return readBytes(in, raw.data(), raw.size());
    }

    // --- STRING type (GGUFMetaType::STRING = 8) ---
    if (type == static_cast<uint32_t>(GGUFMetaType::STRING)) {
        uint64_t size = 0;
        if (!readU64(in, size) || size > (1ull << 30)) return false;
        // Bounded: do not allocate tokenizer-size arrays silently.
        if (size > (1ull << 20)) return false; // >1 MiB string = reject / flag
        raw.resize(sizeof(uint64_t) + static_cast<size_t>(size));
        std::memcpy(raw.data(), &size, sizeof(size));
        return readBytes(in, raw.data() + sizeof(size), static_cast<size_t>(size));
    }

    // --- ARRAY type (GGUFMetaType::ARRAY = 9) ---
    if (type == static_cast<uint32_t>(GGUFMetaType::ARRAY)) {
        uint32_t elementType = 0;
        uint64_t count = 0;
        if (!readU32(in, elementType) || !readU64(in, count)) return false;
        if (count > (1ull << 20)) return false; // reject absurdly large arrays
        // Bounded element count; recursive readValue will reject unsupported element types.
        raw.resize(sizeof(elementType) + sizeof(count));
        std::memcpy(raw.data(), &elementType, sizeof(elementType));
        std::memcpy(raw.data() + sizeof(elementType), &count, sizeof(count));
        for (uint64_t i = 0; i < count; ++i) {
            std::vector<uint8_t> child;
            if (!readValue(in, elementType, child, depth + 1)) return false;
            // Guard against child allocations that would overflow the outer buffer.
            if (raw.size() + child.size() > (1ull << 30)) return false;
            raw.insert(raw.end(), child.begin(), child.end());
        }
        return true;
    }

    // Unknown or unsupported metadata type -> fail closed.
    return false;
}

uint64_t alignUp(uint64_t value, uint64_t alignment) {
    if (!alignment) return value;
    const uint64_t rem = value % alignment;
    if (!rem) return value;
    const uint64_t add = alignment - rem;
    if (value > std::numeric_limits<uint64_t>::max() - add) return 0;
    return value + add;
}

bool tensorGeometry(uint32_t type, const std::vector<uint64_t>& dims,
                    uint64_t& bytes) {
    const auto* descriptor=LookupQuantType(type);
    return descriptor && descriptor->persistedGGUF &&
        ReapBounds::ByteSize(dims,descriptor->blockElements,descriptor->blockBytes,bytes);
}

bool parseShard(const fs::path& path, ParsedShard& shard, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { error = "open failed: " + path.string(); return false; }
    std::error_code ec;
    shard.fileBytes = fs::file_size(path, ec);
    if (ec || shard.fileBytes < 24) { error = "invalid shard size: " + path.string(); return false; }
    uint32_t magic = 0, version = 0;
    uint64_t tensorCount = 0;
    if (!readU32(in, magic) || !readU32(in, version) || !readU64(in, tensorCount) ||
        !readU64(in, shard.metadataCount) || magic != 0x46554747u ||
        (version != 2 && version != 3) || tensorCount > 1000000 || shard.metadataCount > 1000000) {
        error = "invalid GGUF header: " + path.string(); return false;
    }
    shard.version = version;
    shard.metadata.reserve(static_cast<size_t>(shard.metadataCount));
    for (uint64_t i = 0; i < shard.metadataCount; ++i) {
        MetaEntry entry;
        if (!readString(in, entry.key) || !readU32(in, entry.type) ||
            !readValue(in, entry.type, entry.value)) {
            error = "invalid metadata entry in " + path.string(); return false;
        }
        if (entry.key == "general.alignment" && entry.type == static_cast<uint32_t>(GGUFMetaType::UINT32) &&
            entry.value.size() == sizeof(uint32_t)) {
            std::memcpy(&shard.alignment, entry.value.data(), sizeof(uint32_t));
        }
        shard.metadata.emplace_back(std::move(entry));
    }
    shard.tensors.reserve(static_cast<size_t>(tensorCount));
    for (uint64_t i = 0; i < tensorCount; ++i) {
        TensorDesc tensor;
        uint32_t dims = 0;
        if (!readString(in, tensor.name) || !readU32(in, dims) || dims == 0 || dims > 8) {
            error = "invalid tensor descriptor in " + path.string(); return false;
        }
        tensor.dims.resize(dims);
        for (uint64_t& dim : tensor.dims) if (!readU64(in, dim) || !dim) {
            error = "invalid tensor shape in " + path.string(); return false;
        }
        if (!readU32(in, tensor.type) || !readU64(in, tensor.offset) ||
            !tensorGeometry(tensor.type, tensor.dims, tensor.bytes)) {
            error = "unsupported tensor geometry: " + tensor.name; return false;
        }
        shard.tensors.emplace_back(std::move(tensor));
    }
    const auto headerEnd = static_cast<uint64_t>(in.tellg());
    shard.dataStart = alignUp(headerEnd, shard.alignment ? shard.alignment : 32);
    if (!shard.dataStart || shard.dataStart > shard.fileBytes) {
        error = "invalid tensor data start in " + path.string(); return false;
    }
    std::vector<ReapBounds::Range> ranges;
    ranges.reserve(shard.tensors.size());
    for (const auto& tensor : shard.tensors)
        ranges.push_back({tensor.offset,tensor.bytes});
    if (!ReapBounds::ValidRanges(std::move(ranges),shard.fileBytes-shard.dataStart,
                                 shard.alignment ? shard.alignment : 32)) {
        error = "invalid, overlapping or misaligned tensor ranges: " + path.string();
        return false;
    }
    shard.path = path;
    return true;
}

bool isProjection(const std::string& name, const char* part) {
    return name.find(".ffn_" + std::string(part) + "_exps.weight") != std::string::npos;
}

// GGUF dimension layout for packed MoE tensors:
//   GGUF/ggml stores dimensions slowest-varying last. For Kimi K2 packed expert
//   projections the expert dimension is dims.back() (384), and experts are laid
//   out contiguously: expert k occupies [k*stride, (k+1)*stride) where
//   stride = total_bytes / dims.back().
//
//   This is verified against the real model: all ffn_gate_exps/ffn_up_exps
//   tensors have dims [7168, 2048, 384] (Q4_K), all ffn_down_exps have dims
//   [2048, 7168, 384] (Q4_K/Q6_K), routers have dims [7168, 384] (F32), and
//   biases have dims [384] (F32). In every case dims.back() == 384 equals the
//   packed expert count and the per-expert byte range is contiguous.
//
//   The writer relies on this layout. If a future model stores the expert
//   dimension elsewhere, validateExpertTensorGeometry() below will reject it
//   rather than silently producing corrupted output.
bool validateExpertTensorGeometry(const TensorDesc& tensor, uint32_t layer,
                                   const Selection& selection, std::string& error) {
    if (tensor.dims.empty()) {
        error = "expert tensor has no dimensions: " + tensor.name;
        return false;
    }
    const uint64_t expertDim = tensor.dims.back();
    if (expertDim == 0) {
        error = "expert tensor has zero expert dimension: " + tensor.name;
        return false;
    }
    if (tensor.bytes % expertDim != 0) {
        error = "expert tensor bytes not divisible by expert dimension: " + tensor.name +
                " bytes=" + std::to_string(tensor.bytes) +
                " expert_dim=" + std::to_string(expertDim);
        return false;
    }
    const auto it = selection.find(layer);
    if (it == selection.end() || it->second.empty()) {
        error = "selection missing layer " + std::to_string(layer) + " for " + tensor.name;
        return false;
    }
    const uint64_t stride = tensor.bytes / expertDim;
    for (uint32_t expert : it->second) {
        if (expert >= expertDim) {
            error = "selected expert " + std::to_string(expert) +
                    " exceeds expert dimension " + std::to_string(expertDim) +
                    " at layer " + std::to_string(layer) + " for " + tensor.name;
            return false;
        }
        // Overflow guard: stride * expert must not wrap.
        if (expert > 0 && stride > std::numeric_limits<uint64_t>::max() / expert) {
            error = "expert slice offset overflow at layer " + std::to_string(layer) +
                    " expert " + std::to_string(expert) + " for " + tensor.name;
            return false;
        }
    }
    return true;
}

bool layerFromName(const std::string& name, uint32_t& layer) {
    return ReapBounds::LayerIndex(name,layer);
}

bool loadSelection(const std::string& path, uint32_t activeExperts,
                   Selection& selection, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { error = "selection manifest open failed"; return false; }
    try {
        json doc; in >> doc;
        const bool experimentalOffline = doc.value("experimental_offline", false);
        if (doc.value("schema", std::string{}) != "RAWRXD_REAP_EXPERT_SELECTION_001" ||
            (doc.value("rewrite_authorized", false) != true && !experimentalOffline)) {
            error = "selection manifest is not rewrite-authorized"; return false;
        }
        if (doc.value("reference_parity_pass", false) != true && !experimentalOffline) {
            error = "selection manifest lacks independent reference parity"; return false;
        }
        const auto layers = doc.find("layers");
        if (layers == doc.end() || !layers->is_array()) { error = "selection layers missing"; return false; }
        for (const auto& layer : *layers) {
            const uint32_t id = layer.value("layer", std::numeric_limits<uint32_t>::max());
            const auto selected = layer.find("selected");
            if (id == std::numeric_limits<uint32_t>::max() || selected == layer.end() || !selected->is_array()) {
                error = "invalid selection layer"; return false;
            }
            if (selection.find(id) != selection.end()) {
                error = "duplicate selection layer"; return false;
            }
            auto& dst = selection[id];
            for (const auto& item : *selected) dst.push_back(item.value("expert", std::numeric_limits<uint32_t>::max()));
            std::unordered_set<uint32_t> seen;
            for (const uint32_t expert : dst) {
                if (!seen.insert(expert).second) {
                    error = "selection layer contains duplicate expert IDs";
                    return false;
                }
            }
            if (dst.empty() || (activeExperts && dst.size() != activeExperts)) {
                error = "selection layer has invalid expert count"; return false;
            }
        }
        if (selection.empty()) { error = "selection is empty"; return false; }
        return true;
    } catch (const std::exception& ex) {
        error = std::string("selection parse failed: ") + ex.what();
        return false;
    }
}

// Patch the expert-bank SIZE metadata only.
//
// Two different fields live side by side in MoE GGUF headers and they mean
// different things:
//
//   *.expert_count       how many experts exist in the physical bank
//   *.expert_used_count  how many experts each token activates (top-k)
//
// An earlier version matched either substring and wrote the retained count into
// both. That silently turned a top-4 router into a top-59 router on GLM-4.7,
// top-6 into top-81 on Nemotron, and top-8 into top-199 on Qwen3.6. The
// resulting exports routed every token through every surviving expert: the graph
// and its allocation grew accordingly, and llama.cpp aborted with
// GGML_ASSERT(obj_new) on GLM and Nemotron.
//
// Rewrite only the physical routed bank size. Top-k is validated globally
// before output creation; it must never be silently clamped or rewritten.
void patchMetadata(std::vector<MetaEntry>& metadata, uint32_t originalExperts,
                   uint32_t activeExperts, uint32_t shardNo, uint32_t shardCount,
                   uint32_t groups) {
    bool foundExpertCount = false;
    for (auto& entry : metadata) {
        const bool count = ReapBank::HasField(entry.key, "expert_count");
        const bool width = ReapBank::HasField(entry.key, "experts_per_group");
        if (!count && !width) continue;
        foundExpertCount = foundExpertCount || count;
        const uint64_t value = count ? activeExperts : activeExperts / groups;
        // Keep explicit group width consistent with the compact bank. Preserve
        // original group count and groups-used; preserve the integral field type.
        for (size_t i = 0; i < entry.value.size(); ++i)
            entry.value[i] = static_cast<uint8_t>(value >> (i * 8u));
    }

    if (!foundExpertCount) {
        MetaEntry entry;
        entry.key = "rawrxd.reap.active_experts";
        entry.type = static_cast<uint32_t>(GGUFMetaType::UINT32);
        entry.value.resize(sizeof(uint32_t));
        std::memcpy(entry.value.data(), &activeExperts, sizeof(uint32_t));
        metadata.emplace_back(std::move(entry));
    }
    MetaEntry original;
    original.key = "rawrxd.reap.original_experts";
    original.type = static_cast<uint32_t>(GGUFMetaType::UINT32);
    original.value.resize(sizeof(uint32_t));
    std::memcpy(original.value.data(), &originalExperts, sizeof(uint32_t));
    metadata.emplace_back(std::move(original));

    auto setSplit = [&](const char* key, uint64_t value) {
        metadata.erase(std::remove_if(metadata.begin(), metadata.end(),
                                      [&](const MetaEntry& entry) { return entry.key == key; }),
                       metadata.end());
        MetaEntry added;
        added.key = key;
        added.type = static_cast<uint32_t>(GGUFMetaType::UINT16);
        added.value.resize(2);
        const uint16_t v = static_cast<uint16_t>(value);
        std::memcpy(added.value.data(), &v, 2);
        metadata.emplace_back(std::move(added));
    };
    setSplit("split.count", shardCount);
    setSplit("split.no", shardNo);
}

bool writeMeta(std::ofstream& out, const MetaEntry& entry) {
    return writeString(out, entry.key) && writeU32(out, entry.type) &&
           writeBytes(out, entry.value.data(), entry.value.size());
}

// Read a positive, exact-width integral GGUF count. Never truncate a u64 or
// reinterpret a negative signed count as a valid routed bank cardinality.
bool metadataCountValue(const MetaEntry& entry, uint64_t& value) {
    size_t width = 0;
    bool signedType = false;
    switch (static_cast<GGUFMetaType>(entry.type)) {
    case GGUFMetaType::UINT8: width=1; break;
    case GGUFMetaType::INT8: width=1; signedType=true; break;
    case GGUFMetaType::UINT16: width=2; break;
    case GGUFMetaType::INT16: width=2; signedType=true; break;
    case GGUFMetaType::UINT32: width=4; break;
    case GGUFMetaType::INT32: width=4; signedType=true; break;
    case GGUFMetaType::UINT64: width=8; break;
    case GGUFMetaType::INT64: width=8; signedType=true; break;
    default: return false;
    }
    if (entry.value.size()!=width || (signedType && (entry.value.back() & 0x80))) return false;
    value=0;
    for (size_t i=0; i<width; ++i) value |= uint64_t(entry.value[i]) << (i*8u);
    return value!=0 && value<=UINT32_MAX;
}

bool copyRange(std::ifstream& in, std::ofstream& out, uint64_t offset, uint64_t bytes) {
    if (!in.seekg(static_cast<std::streamoff>(offset), std::ios::beg)) return false;
    std::vector<char> buffer(1u << 20);
    while (bytes) {
        const size_t chunk = static_cast<size_t>((std::min)(bytes, static_cast<uint64_t>(buffer.size())));
        in.read(buffer.data(), static_cast<std::streamsize>(chunk));
        if (in.gcount() != static_cast<std::streamsize>(chunk)) return false;
        if (!permitTestWrite(chunk)) return false;
        out.write(buffer.data(), static_cast<std::streamsize>(chunk));
        if (!out) return false;
        bytes -= chunk;
    }
    return true;
}

bool writeZeros(std::ofstream& out, uint64_t bytes) {
    static const std::vector<char> zeros(1u << 20, 0);
    while (bytes) {
        const size_t chunk = static_cast<size_t>((std::min)(bytes, static_cast<uint64_t>(zeros.size())));
        if (!permitTestWrite(chunk)) return false;
        out.write(zeros.data(), static_cast<std::streamsize>(chunk));
        if (!out) return false;
        bytes -= chunk;
    }
    return true;
}

struct OutputCleanup {
    fs::path path;
    bool active = false;
    bool removeDirectory = false;
    std::vector<fs::path> files;

    ~OutputCleanup() {
        if (!active) return;
        std::error_code error;
        for (const auto& file : files) {
            std::error_code fileError;
            fs::remove(file, fileError);
        }
        if (removeDirectory) fs::remove_all(path, error);
    }
};

} // namespace

static ReapMoETransformResult transformImpl(ReapMoETransformRequest request,
                                           ReapMoEBudgetResult* inspection) {
    resetTestWriteBudget();
    ReapMoETransformResult result;
    if (request.sourceFirstShard.empty() || (!inspection &&
        (request.outputDirectory.empty() || request.selectionManifest.empty() || !request.activeExperts))) {
        result.error = "source, output directory, selection manifest and active experts are required";
        return result;
    }
    if (!inspection && request.requantizeQ4KToQ2K &&
        (!std::isfinite(request.maxQuantRelativeRmse) || request.maxQuantRelativeRmse<0)) {
        result.error="explicit finite requantization error limit required";return result;
    }
    Selection selection;
    if (!inspection && !loadSelection(request.selectionManifest, request.activeExperts, selection, result.error)) return result;

    const fs::path source(request.sourceFirstShard);
    std::vector<fs::path> paths;
    if (!ReapState::ShardPaths(source,paths) || paths.empty()) {
        result.error="invalid canonical first shard";return result;
    }
    const uint32_t shardCount=static_cast<uint32_t>(paths.size());
    std::vector<ParsedShard> shards;
    shards.reserve(shardCount);
    for (const auto& p : paths) {
        ParsedShard shard;
        if (!parseShard(p, shard, result.error)) return result;
        if (!ReapExport::Add(result.sourceBytes,shard.fileBytes,result.sourceBytes) ||
            !ReapExport::Add(result.sourceTensors,shard.tensors.size(),result.sourceTensors)) {
            result.error="source inventory overflow";return result;
        }
        shards.emplace_back(std::move(shard));
    }

    // Resolve the physical bank and original top-k across the full checkpoint
    // before writing a single output byte. A dense-only shard is legitimate.
    ReapBank::Contract bank;
    ReapExport::GroupFields groupFields;
    std::unordered_set<std::string> sourceTensorNames;
    for (const auto& shard : shards) {
        for (const auto& tensor : shard.tensors) {
            if (!sourceTensorNames.insert(tensor.name).second) {
                result.error="duplicate source tensor name across checkpoint: "+tensor.name;return result;
            }
            const bool expertTensor = isProjection(tensor.name, "gate") ||
                isProjection(tensor.name, "up") || isProjection(tensor.name, "down") ||
                tensor.name.find(".ffn_gate_inp.weight") != std::string::npos ||
                tensor.name.find(".exp_probs_b.bias") != std::string::npos;
            if (expertTensor && (tensor.dims.empty() || !bank.ObserveAxis(tensor.dims.back()))) {
                result.error = "inconsistent expert axis across checkpoint: " + tensor.name;
                return result;
            }
        }
    }
    if (!bank.original) {
        result.error = "checkpoint has no supported expert tensors";
        return result;
    }
    for (const auto& shard : shards) {
        for (const auto& entry : shard.metadata) {
            const bool count = ReapBank::HasField(entry.key, "expert_count");
            const bool topK = ReapBank::HasField(entry.key, "expert_used_count");
            const bool groups = ReapBank::HasField(entry.key, "expert_group_count");
            const bool groupsUsed = ReapBank::HasField(entry.key, "expert_group_used_count");
            const bool width = ReapBank::HasField(entry.key, "experts_per_group");
            if (!count && !topK && !groups && !groupsUsed && !width) continue;
            uint64_t value = 0;
            if (!metadataCountValue(entry, value) ||
                (count && value != bank.original) ||
                (topK && !bank.ObserveTopK(value)) ||
                (groups && !groupFields.Observe(groupFields.groups,value)) ||
                (groupsUsed && !groupFields.Observe(groupFields.used,value)) ||
                (width && !groupFields.Observe(groupFields.width,value))) {
                result.error = "inconsistent or invalid routed expert metadata: " + entry.key;
                return result;
            }
        }
    }
    ReapExport::Router routerGeometry;
    if (inspection) request.activeExperts=bank.original;
    if (!bank.Allows(request.activeExperts) ||
        !groupFields.Resolve(bank.original,bank.topK,routerGeometry) ||
        !routerGeometry.Allows(request.activeExperts)) {
        result.error = "retained expert count violates checkpoint bank/top-k/group contract";
        return result;
    }
    for (const auto& entry : selection) {
        if (!routerGeometry.Preserves(entry.second)) {
            result.error = "selection does not preserve original expert group membership and order at layer " +
                           std::to_string(entry.first);
            return result;
        }
    }

    // The selection manifest is a topology contract, not merely a list of
    // optional slices.  Reject stale selectors that contain transformer
    // blocks which are not routed MoE layers (for example, an erroneous
    // layer 0 entry), or omit a routed layer.  Silently ignoring an extra
    // entry would make the manifest appear valid while exporting a different
    // model than the calibration evidence describes.
    std::set<uint32_t> sourceMoeLayers;
    for (const auto& shard : shards) {
        for (const auto& tensor : shard.tensors) {
            if (!isProjection(tensor.name, "gate") &&
                !isProjection(tensor.name, "up") &&
                !isProjection(tensor.name, "down")) continue;
            uint32_t layer = 0;
            if (!layerFromName(tensor.name, layer)) {
                result.error = "expert tensor has invalid layer name: " + tensor.name;
                return result;
            }
            sourceMoeLayers.insert(layer);
        }
    }
    if (sourceMoeLayers.empty()) { result.error="no routed projection layers";return result; }
    if (!inspection && sourceMoeLayers.size() != selection.size()) {
        result.error = "selection topology mismatch: source MoE layers=" +
                       std::to_string(sourceMoeLayers.size()) +
                       " manifest layers=" + std::to_string(selection.size());
        return result;
    }
    for (const uint32_t layer : sourceMoeLayers) {
        if (!inspection && selection.find(layer) == selection.end()) {
            result.error = "selection missing source MoE layer " + std::to_string(layer);
            return result;
        }
    }
    for (const auto& entry : selection) {
        if (sourceMoeLayers.find(entry.first) == sourceMoeLayers.end()) {
            result.error = "selection contains non-MoE layer " + std::to_string(entry.first);
            return result;
        }
    }

    // Exact prune-only serialization preflight, using the same metadata patch
    // and tensor ordering as the writer. No output paths are created yet.
    std::vector<ReapExport::Shard> layouts;
    std::vector<uint64_t> predictedShardBytes;
    uint64_t requantizableTensors=0;
    for (size_t i=0;i<shards.size();++i) {
        const auto& shard=shards[i];
        auto metadata=shard.metadata;
        patchMetadata(metadata,bank.original,request.activeExperts,
                      static_cast<uint32_t>(i),shardCount,
                      static_cast<uint32_t>(routerGeometry.groups));
        ReapExport::Shard layout;
        layout.header=24; // magic, version, tensor count, metadata count
        layout.alignment=shard.alignment ? shard.alignment : 32;
        for (const auto& entry : metadata) {
            if (!ReapExport::Add(layout.header,12,layout.header) ||
                !ReapExport::Add(layout.header,entry.key.size(),layout.header) ||
                !ReapExport::Add(layout.header,entry.value.size(),layout.header)) {
                result.error="metadata size overflow";return result;
            }
        }
        for (const auto& tensor : shard.tensors) {
            const bool projection=isProjection(tensor.name,"gate") ||
                isProjection(tensor.name,"up") || isProjection(tensor.name,"down");
            const bool router=tensor.name.find(".ffn_gate_inp.weight")!=std::string::npos ||
                tensor.name.find(".exp_probs_b.bias")!=std::string::npos;
            const bool unsupported=tensor.name.find(".ffn_")!=std::string::npos &&
                tensor.name.find("_exps.")!=std::string::npos && !projection && !router;
            uint32_t layer=0;
            if (unsupported) {
                result.error="unsupported expert tensor layout: "+tensor.name;return result;
            }
            const auto* descriptor=LookupQuantType(tensor.type);
            uint64_t sliceStride=0;
            if ((projection||router) && (!layerFromName(tensor.name,layer) ||
                !sourceMoeLayers.count(layer) || tensor.dims.empty() ||
                tensor.dims.back()!=bank.original || !descriptor ||
                !ReapBounds::SliceStride(tensor.dims,descriptor->blockElements,
                    descriptor->blockBytes,tensor.bytes,sliceStride) ||
                (!inspection && !validateExpertTensorGeometry(tensor,layer,selection,result.error)))) {
                if(result.error.empty())result.error="invalid expert tensor layer";
                return result;
            }
            if (!ReapExport::Add(layout.header,24,layout.header) ||
                !ReapExport::Add(layout.header,tensor.name.size(),layout.header) ||
                tensor.dims.size()>UINT64_MAX/8 ||
                !ReapExport::Add(layout.header,8ull*tensor.dims.size(),layout.header)) {
                result.error="descriptor size overflow";return result;
            }
            uint64_t storedBytes=tensor.bytes;
            if (request.requantizeQ4KToQ2K && projection && tensor.type==12) {
                if (!ReapQuant::ConvertedBytes(tensor.dims.front(),tensor.bytes,storedBytes) ||
                    storedBytes%bank.original) {
                    result.error="unsupported Q4_K expert row geometry for conversion: "+tensor.name;return result;
                }
                ++requantizableTensors;
            }
            layout.tensors.push_back({storedBytes,projection||router});
        }
        uint64_t bytes=0;
        if (!ReapExport::Measure(layout,routerGeometry,request.activeExperts,bytes)) {
            result.error="invalid serialized shard geometry";return result;
        }
        predictedShardBytes.push_back(bytes);
        layouts.push_back(std::move(layout));
    }
    if (request.requantizeQ4KToQ2K && !requantizableTensors) {
        result.error="no Q4_K routed projections available for conversion";return result;
    }
    uint64_t predictedBytes=0;
    if (!ReapExport::MeasureAll(layouts,routerGeometry,request.activeExperts,predictedBytes)) {
        result.error="serialized checkpoint size overflow";return result;
    }
    if (inspection) {
        inspection->requantizableTensors=requantizableTensors;
        inspection->requantizeQ4KToQ2K=request.requantizeQ4KToQ2K;
        inspection->originalExperts=routerGeometry.original;
        inspection->topK=routerGeometry.top;
        inspection->groups=routerGeometry.groups;
        inspection->groupsUsed=routerGeometry.used;
        inspection->routedLayers.assign(sourceMoeLayers.begin(),sourceMoeLayers.end());
        const uint64_t minRetained=routerGeometry.groups*
            ((routerGeometry.top+routerGeometry.used-1)/routerGeometry.used);
        if (!ReapExport::MeasureAll(layouts,routerGeometry,minRetained,inspection->minimumBytes) ||
            !ReapExport::MaxRetained(layouts,routerGeometry,inspection->budgetBytes,inspection->maxRetained) ||
            (inspection->maxRetained && !ReapExport::MeasureAll(layouts,routerGeometry,
                inspection->maxRetained,inspection->predictedBytes))) {
            result.error="invalid budget inspection";return result;
        }
        result.success=true;return result;
    }
    if (request.targetSizeBytes && predictedBytes>request.targetSizeBytes) {
        uint64_t maxRetained=0;
        if (!ReapExport::MaxRetained(layouts,routerGeometry,request.targetSizeBytes,maxRetained)) {
            result.error="invalid compression budget";return result;
        }
        result.error="prune-only export exceeds budget: predicted="+std::to_string(predictedBytes)+
            " target="+std::to_string(request.targetSizeBytes)+
            " max_uniform_retained_at_current_dtype="+std::to_string(maxRetained);
        return result;
    }

    std::error_code ec;
    const fs::path outputDir(request.outputDirectory);
    if (fs::exists(outputDir, ec)) {
        if (!fs::is_directory(outputDir, ec) || fs::directory_iterator(outputDir, ec) != fs::directory_iterator()) {
            result.error = "output directory must be new or empty";
            return result;
        }
    } else {
        const fs::path parent = outputDir.parent_path().empty()
            ? fs::current_path(ec) : outputDir.parent_path();
        if (ec || (!fs::exists(parent, ec) && !fs::create_directories(parent, ec)) || ec) {
            result.error = "output parent directory could not be created";
            return result;
        }
    }
    const auto txnId = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path stagingDir = outputDir.parent_path() /
        (outputDir.filename().string() + ".reap-txn-" + std::to_string(txnId));
    if (!fs::create_directory(stagingDir, ec) || ec) {
        result.error = "transaction staging directory could not be created";
        return result;
    }
    OutputCleanup cleanup{stagingDir, true, true};

    for (size_t shardIndex = 0; shardIndex < shards.size(); ++shardIndex) {
        const auto& shard = shards[shardIndex];
        std::vector<TensorDesc> outputTensors;
        outputTensors.reserve(shard.tensors.size());
        for (const auto& tensor : shard.tensors) {
            TensorDesc out = tensor;
            uint32_t layer = 0;
            const bool projection = isProjection(tensor.name, "gate") || isProjection(tensor.name, "up") || isProjection(tensor.name, "down");
            const bool router = tensor.name.find(".ffn_gate_inp.weight") != std::string::npos ||
                                tensor.name.find(".exp_probs_b.bias") != std::string::npos;
            const bool expertTensor = projection || router || tensor.name.find(".ffn_") != std::string::npos && tensor.name.find("_exps.") != std::string::npos;
            if (expertTensor && !projection && !router) {
                result.error = "unsupported expert tensor layout: " + tensor.name;
                return result;
            }
            if (projection || router) {
                if (!layerFromName(tensor.name, layer) ||
                    !validateExpertTensorGeometry(tensor, layer, selection, result.error)) return result;
                const auto it = selection.find(layer);
                out.dims.back() = static_cast<uint64_t>(it->second.size());
                const uint64_t stride = tensor.bytes / tensor.dims.back();
                out.bytes = stride * it->second.size();
                if (request.requantizeQ4KToQ2K && projection && tensor.type==12) {
                    uint64_t converted=0;
                    if (!ReapQuant::ConvertedBytes(tensor.dims.front(),out.bytes,converted)) {
                        result.error="invalid retained Q4_K row geometry";return result;
                    }
                    out.bytes=converted;
                    out.type=10; // GGUF Q2_K
                }
                ++result.transformedTensors;
                result.selectedExpertSlices += it->second.size();
            }
            outputTensors.emplace_back(std::move(out));
        }

        auto metadata = shard.metadata;
        patchMetadata(metadata, bank.original, request.activeExperts,
                      static_cast<uint32_t>(shardIndex), shardCount,
                      static_cast<uint32_t>(routerGeometry.groups));
        const fs::path outputPath = stagingDir / shard.path.filename();
        cleanup.files.push_back(outputPath);
        std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
        if (!out) { result.error = "output shard open failed: " + outputPath.string(); return result; }
        if (!writeU32(out, 0x46554747u) || !writeU32(out, shard.version) ||
            !writeU64(out, outputTensors.size()) || !writeU64(out, metadata.size())) {
            result.error = "output header write failed"; return result;
        }
        for (const auto& entry : metadata) if (!writeMeta(out, entry)) {
            result.error = "output metadata write failed"; return result;
        }
        const auto descriptorStart = static_cast<uint64_t>(out.tellp());
        uint64_t descriptorBytes = 0;
        for (const auto& tensor : outputTensors) {
            const uint64_t nameBytes = 8ull + tensor.name.size();
            const uint64_t dimsBytes = 4ull + 8ull * tensor.dims.size();
            if (descriptorBytes > std::numeric_limits<uint64_t>::max() - nameBytes - dimsBytes - 12ull) {
                result.error = "output descriptor size overflow"; return result;
            }
            descriptorBytes += nameBytes + dimsBytes + 12ull;
        }
        const uint64_t descriptorEnd = descriptorStart + descriptorBytes;
        const uint64_t dataStart = alignUp(descriptorEnd, shard.alignment ? shard.alignment : 32);
        uint64_t cursor = 0;
        for (auto& tensor : outputTensors) {
            const uint64_t aligned = alignUp(cursor, shard.alignment ? shard.alignment : 32);
            if (aligned < cursor || tensor.bytes > std::numeric_limits<uint64_t>::max() - aligned) { result.error = "output tensor alignment failed"; return result; }
            tensor.offset = aligned;
            cursor = aligned + tensor.bytes;
        }
        for (const auto& tensor : outputTensors) {
            if (!writeString(out, tensor.name) || !writeU32(out, static_cast<uint32_t>(tensor.dims.size()))) { result.error = "output tensor name write failed"; return result; }
            for (uint64_t dim : tensor.dims) if (!writeU64(out, dim)) { result.error = "output tensor shape write failed"; return result; }
            if (!writeU32(out, tensor.type) || !writeU64(out, tensor.offset)) { result.error = "output tensor descriptor write failed"; return result; }
        }
        const auto afterDescriptors = static_cast<uint64_t>(out.tellp());
        if (afterDescriptors != descriptorEnd || !dataStart || dataStart < descriptorEnd || !writeZeros(out, dataStart - descriptorEnd)) { result.error = "output alignment failed"; return result; }
        for (const auto& tensor : outputTensors) {
            const uint64_t expectedStart = dataStart + tensor.offset;
            const uint64_t currentStart = static_cast<uint64_t>(out.tellp());
            if (currentStart > expectedStart || !writeZeros(out, expectedStart - currentStart)) {
                result.error = "tensor data alignment failed"; return result;
            }
            std::ifstream in(shard.path, std::ios::binary);
            if (!in) { result.error = "source shard reopen failed"; return result; }
            const bool projection = isProjection(tensor.name, "gate") || isProjection(tensor.name, "up") || isProjection(tensor.name, "down");
            const bool router = tensor.name.find(".ffn_gate_inp.weight") != std::string::npos ||
                                tensor.name.find(".exp_probs_b.bias") != std::string::npos;
            const auto original = std::find_if(shard.tensors.begin(), shard.tensors.end(), [&](const TensorDesc& x){ return x.name == tensor.name; });
            if (original == shard.tensors.end()) { result.error = "source tensor disappeared"; return result; }
            uint32_t layer = 0;
            if ((projection || router) && (!layerFromName(tensor.name, layer) || selection.find(layer) == selection.end())) { result.error = "selection lookup failed"; return result; }
            if (projection || router) {
                const uint64_t stride = original->bytes / original->dims.back();
                const auto it = selection.find(layer);
                ReapQuant::RangeStats quantStats;
                const bool convert=projection && original->type==12 && tensor.type==10 &&
                    request.requantizeQ4KToQ2K;
                for (uint32_t expert : it->second) {
                    // Overflow guard already checked in validateExpertTensorGeometry.
                    // Tensor offsets are relative to the source shard's data
                    // section.  Using the output data base here silently
                    // corrupts every selected expert whenever the rebuilt
                    // header has a different length from the source header.
                    const uint64_t srcOffset = shard.dataStart + original->offset + stride * expert;
                    if (convert) {
                        if (!in.seekg(static_cast<std::streamoff>(srcOffset),std::ios::beg) ||
                            !ReapQuant::ConvertRange(in,out,stride,quantStats)) {
                            result.error="native expert requantization failed: "+tensor.name;return result;
                        }
                    } else if (!copyRange(in, out, srcOffset, stride)) {
                        result.error = "expert slice copy failed"; return result;
                    }
                }
                if (convert) {
                    const double relative=quantStats.RelativeRmse();
                    if (!std::isfinite(relative) || relative>request.maxQuantRelativeRmse ||
                        !ReapExport::Add(result.requantizedBlocks,quantStats.blocks,result.requantizedBlocks)) {
                        result.error="requantization error limit exceeded: "+tensor.name;return result;
                    }
                    result.maxTensorQuantRelativeRmse=std::max(result.maxTensorQuantRelativeRmse,relative);
                }
            } else if (!copyRange(in, out, shard.dataStart + original->offset, original->bytes)) {
                result.error = "tensor copy failed: " + tensor.name; return result;
            }
            const auto written = static_cast<uint64_t>(out.tellp());
            const uint64_t expected = dataStart + tensor.offset + tensor.bytes;
            if (written < expected && !writeZeros(out, expected - written)) { result.error = "tensor padding write failed"; return result; }
            if (written > expected) { result.error = "tensor output offset mismatch"; return result; }
        }
        out.close();
        if (!out.good()) { result.error = "output shard close failed"; return result; }
        const auto measured = fs::file_size(outputPath, ec);
        if (ec || measured!=predictedShardBytes[shardIndex] ||
            !ReapExport::Add(result.outputBytes,static_cast<uint64_t>(measured),result.outputBytes)) {
            result.error="serialized shard size differs from preflight";return result;
        }
        result.outputTensors += outputTensors.size();
    }

    if (result.outputBytes!=predictedBytes) {
        result.error="serialized checkpoint size differs from preflight";return result;
    }
    if (request.targetSizeBytes != 0 && result.outputBytes > request.targetSizeBytes) {
        result.error = "rewritten GGUF exceeds target size: output=" +
                       std::to_string(result.outputBytes) +
                       " target=" + std::to_string(request.targetSizeBytes);
        return result;
    }

    const fs::path stagedFirst = stagingDir / paths.front().filename();
    uint32_t verifiedShardCount = 0;
    {
        // Release the mapped validation files before the directory publication
        // boundary; Windows will otherwise reject the rename with sharing
        // violation even though serialization and validation succeeded.
        GGUFLoader verify;
        if (!verify.load(stagedFirst.string())) {
            result.error = "rewritten GGUF reload failed: " + verify.error();
            return result;
        }
        if (verify.shardCount() != shardCount || verify.tensorCount() != result.outputTensors) {
            result.error = "rewritten GGUF inventory mismatch";
            return result;
        }
        verifiedShardCount = verify.shardCount();
    }

    // Publish only after every shard has been serialized and the complete
    // staged checkpoint reloads successfully. A single directory rename is
    // the commit boundary, so model discovery cannot observe a partial shard
    // set. Existing destinations are never replaced.
    ec.clear();
    if (fs::exists(outputDir, ec) || ec) {
        result.error = "transactional destination appeared during export";
        return result;
    }
    bool published = false;
#ifdef _WIN32
    published = MoveFileExW(stagingDir.wstring().c_str(), outputDir.wstring().c_str(),
                            MOVEFILE_WRITE_THROUGH) != 0;
    if (!published) {
        result.error = "transactional directory publication failed: win32=" +
                       std::to_string(static_cast<unsigned long>(GetLastError()));
        return result;
    }
#else
    ec.clear();
    fs::rename(stagingDir, outputDir, ec);
    if (ec) {
        result.error = "transactional directory publication failed: " + ec.message();
        return result;
    }
    published = true;
#endif
    if (!published) return result;
    cleanup.active = false;
    result.success = true;
    result.outputFirstShard = (outputDir / paths.front().filename()).string();
    result.sourceShardCount = shardCount;
    result.outputShardCount = verifiedShardCount;
    cleanup.active = false;
    return result;
}

ReapMoETransformResult transformMoEGGUF(const ReapMoETransformRequest& request) {
    return transformImpl(request,nullptr);
}

ReapMoEBudgetResult inspectMoEGGUFBudget(const std::string& sourceFirstShard,
                                      uint64_t budgetBytes,
                                      bool requantizeQ4KToQ2K) {
    ReapMoEBudgetResult inspection;
    inspection.budgetBytes=budgetBytes;
    if (!budgetBytes) { inspection.error="positive byte budget required";return inspection; }
    ReapMoETransformRequest request;
    request.sourceFirstShard=sourceFirstShard;
    request.requantizeQ4KToQ2K=requantizeQ4KToQ2K;
    const auto result=transformImpl(request,&inspection);
    inspection.success=result.success;
    inspection.error=result.error;
    return inspection;
}

ReapMoECompatibility inspectMoEGGUFCompatibility(const std::string& sourceFirstShard) {
    ReapMoECompatibility compatibility;
    GGUFLoader loader;
    if (!loader.load(sourceFirstShard)) {
        compatibility.reason = "GGUF_LOAD_FAILED:" + loader.error();
        return compatibility;
    }
    compatibility.architecture = loader.getMetaString("general.architecture", "unknown");

    ReapMoEBudgetResult inspection;
    inspection.budgetBytes = std::numeric_limits<uint64_t>::max();
    ReapMoETransformRequest request;
    request.sourceFirstShard = sourceFirstShard;
    const auto result = transformImpl(request, &inspection);
    compatibility.supported = result.success;
    compatibility.reason = result.success ? "packed_expert_axis_last" : result.error;
    compatibility.layout = result.success ? "packed_expert_axis_last" : "unsupported";
    compatibility.originalExperts = inspection.originalExperts;
    compatibility.topK = inspection.topK;
    compatibility.routedLayers = inspection.routedLayers.size();
    return compatibility;
}

} // namespace Deep2

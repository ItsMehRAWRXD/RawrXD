#include "deep2/ReapMoETransformer.hpp"

#include "deep2/GGUFLoader.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>

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
    switch (type) {
    case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
        bytes = (type == 0 || type == 1) ? 1 : 4;
        if (type == 2 || type == 3) bytes = 2;
        if (type == 4 || type == 5 || type == 6) bytes = 4;
        if (type == 7) bytes = 1;
        return true;
    case 10: case 11: case 12: return false;
    default: break;
    }
    if (type == 8) return false;
    if (type == 9) return false;
    if (type == 10 || type == 11 || type == 12) { bytes = 8; return true; }
    return false;
}

bool readValue(std::ifstream& in, uint32_t type, std::vector<uint8_t>& raw,
               uint32_t depth = 0) {
    if (depth > 8) return false;
    raw.clear();
    size_t scalar = 0;
    if (scalarBytes(type, scalar)) {
        raw.resize(scalar);
        return readBytes(in, raw.data(), raw.size());
    }
    if (type == static_cast<uint32_t>(GGUFMetaType::STRING)) {
        uint64_t size = 0;
        if (!readU64(in, size) || size > (1ull << 30)) return false;
        raw.resize(sizeof(uint64_t) + static_cast<size_t>(size));
        std::memcpy(raw.data(), &size, sizeof(size));
        return readBytes(in, raw.data() + sizeof(size), static_cast<size_t>(size));
    }
    if (type != static_cast<uint32_t>(GGUFMetaType::ARRAY)) return false;

    uint32_t elementType = 0;
    uint64_t count = 0;
    if (!readU32(in, elementType) || !readU64(in, count) || count > (1ull << 30))
        return false;
    raw.resize(sizeof(elementType) + sizeof(count));
    std::memcpy(raw.data(), &elementType, sizeof(elementType));
    std::memcpy(raw.data() + sizeof(elementType), &count, sizeof(count));
    for (uint64_t i = 0; i < count; ++i) {
        std::vector<uint8_t> child;
        if (!readValue(in, elementType, child, depth + 1)) return false;
        raw.insert(raw.end(), child.begin(), child.end());
    }
    return true;
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
    if (dims.empty()) return false;
    uint64_t blockElems = 1, blockBytes = 0;
    switch (type) {
    case 0: blockBytes = 4; break; case 1: blockBytes = 2; break;
    case 2: blockElems = 32; blockBytes = 18; break;
    case 3: blockElems = 32; blockBytes = 20; break;
    case 6: blockElems = 32; blockBytes = 22; break;
    case 7: blockElems = 32; blockBytes = 24; break;
    case 8: blockElems = 32; blockBytes = 34; break;
    case 10: blockElems = 256; blockBytes = 84; break;
    case 11: blockElems = 256; blockBytes = 110; break;
    case 12: blockElems = 256; blockBytes = 144; break;
    case 13: blockElems = 256; blockBytes = 176; break;
    case 14: blockElems = 256; blockBytes = 210; break;
    case 15: blockElems = 256; blockBytes = 292; break;
    case 16: blockElems = 256; blockBytes = 66; break;
    case 24: blockBytes = 1; break; case 25: blockBytes = 2; break;
    case 26: blockBytes = 4; break; case 27: case 28: blockBytes = 8; break;
    case 30: blockBytes = 2; break; case 40: blockElems = 64; blockBytes = 36; break;
    default: return false;
    }
    uint64_t rows = 1;
    for (size_t i = 1; i < dims.size(); ++i) {
        if (!dims[i] || rows > std::numeric_limits<uint64_t>::max() / dims[i]) return false;
        rows *= dims[i];
    }
    const uint64_t blocks = (dims[0] + blockElems - 1) / blockElems;
    if (!blocks || blocks > std::numeric_limits<uint64_t>::max() / blockBytes) return false;
    const uint64_t rowBytes = blocks * blockBytes;
    if (rows > std::numeric_limits<uint64_t>::max() / rowBytes) return false;
    bytes = rows * rowBytes;
    return true;
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
        const uint64_t absolute = alignUp(0, 1); (void)absolute;
        shard.tensors.emplace_back(std::move(tensor));
    }
    const auto headerEnd = static_cast<uint64_t>(in.tellg());
    shard.dataStart = alignUp(headerEnd, shard.alignment ? shard.alignment : 32);
    if (!shard.dataStart || shard.dataStart > shard.fileBytes) {
        error = "invalid tensor data start in " + path.string(); return false;
    }
    for (const auto& tensor : shard.tensors) {
        if (tensor.offset > shard.fileBytes - shard.dataStart ||
            tensor.bytes > shard.fileBytes - shard.dataStart - tensor.offset) {
            error = "tensor exceeds shard bounds: " + tensor.name; return false;
        }
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
    if (name.rfind("blk.", 0) != 0) return false;
    const size_t begin = 4, end = name.find('.', begin);
    if (end == std::string::npos || end == begin) return false;
    try { layer = static_cast<uint32_t>(std::stoul(name.substr(begin, end - begin))); }
    catch (...) { return false; }
    return true;
}

bool loadSelection(const std::string& path, uint32_t activeExperts,
                   Selection& selection, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { error = "selection manifest open failed"; return false; }
    try {
        json doc; in >> doc;
        if (doc.value("schema", std::string{}) != "RAWRXD_REAP_EXPERT_SELECTION_001" ||
            doc.value("rewrite_authorized", false) != true) {
            error = "selection manifest is not rewrite-authorized"; return false;
        }
        if (doc.value("reference_parity_pass", false) != true) {
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
            auto& dst = selection[id];
            for (const auto& item : *selected) dst.push_back(item.value("expert", std::numeric_limits<uint32_t>::max()));
            std::sort(dst.begin(), dst.end());
            dst.erase(std::unique(dst.begin(), dst.end()), dst.end());
            if (dst.empty() || (activeExperts && dst.size() > activeExperts)) {
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

void patchMetadata(std::vector<MetaEntry>& metadata, uint32_t activeExperts) {
    for (auto& entry : metadata) {
        const std::string key = [&] { std::string s = entry.key; std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); }); return s; }();
        if (key.find("expert_count") == std::string::npos && key.find("expert_used_count") == std::string::npos) continue;
        if (entry.type == static_cast<uint32_t>(GGUFMetaType::UINT32) && entry.value.size() == 4) {
            std::memcpy(entry.value.data(), &activeExperts, 4);
        } else if (entry.type == static_cast<uint32_t>(GGUFMetaType::INT32) && entry.value.size() == 4) {
            const int32_t value = static_cast<int32_t>(activeExperts);
            std::memcpy(entry.value.data(), &value, 4);
        } else if (entry.type == static_cast<uint32_t>(GGUFMetaType::UINT64) && entry.value.size() == 8) {
            const uint64_t value = activeExperts;
            std::memcpy(entry.value.data(), &value, 8);
        } else if (entry.type == static_cast<uint32_t>(GGUFMetaType::INT64) && entry.value.size() == 8) {
            const int64_t value = activeExperts;
            std::memcpy(entry.value.data(), &value, 8);
        } else if (entry.type == static_cast<uint32_t>(GGUFMetaType::ARRAY) && entry.value.size() >= 12) {
            uint32_t element = 0; uint64_t count = 0;
            std::memcpy(&element, entry.value.data(), 4); std::memcpy(&count, entry.value.data() + 4, 8);
            size_t width = 0;
            if (element == static_cast<uint32_t>(GGUFMetaType::UINT32) || element == static_cast<uint32_t>(GGUFMetaType::INT32)) width = 4;
            else if (element == static_cast<uint32_t>(GGUFMetaType::UINT64) || element == static_cast<uint32_t>(GGUFMetaType::INT64)) width = 8;
            if (width && count <= (entry.value.size() - 12) / width) {
                for (uint64_t i = 0; i < count; ++i) {
                    if (width == 4) { const uint32_t v = activeExperts; std::memcpy(entry.value.data() + 12 + i * width, &v, width); }
                    else { const uint64_t v = activeExperts; std::memcpy(entry.value.data() + 12 + i * width, &v, width); }
                }
            }
        }
    }
}

bool writeMeta(std::ofstream& out, const MetaEntry& entry) {
    return writeString(out, entry.key) && writeU32(out, entry.type) &&
           writeBytes(out, entry.value.data(), entry.value.size());
}

bool copyRange(std::ifstream& in, std::ofstream& out, uint64_t offset, uint64_t bytes) {
    if (!in.seekg(static_cast<std::streamoff>(offset), std::ios::beg)) return false;
    std::vector<char> buffer(1u << 20);
    while (bytes) {
        const size_t chunk = static_cast<size_t>((std::min)(bytes, static_cast<uint64_t>(buffer.size())));
        in.read(buffer.data(), static_cast<std::streamsize>(chunk));
        if (in.gcount() != static_cast<std::streamsize>(chunk)) return false;
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
        out.write(zeros.data(), static_cast<std::streamsize>(chunk));
        if (!out) return false;
        bytes -= chunk;
    }
    return true;
}

} // namespace

ReapMoETransformResult transformMoEGGUF(const ReapMoETransformRequest& request) {
    ReapMoETransformResult result;
    if (request.sourceFirstShard.empty() || request.outputDirectory.empty() ||
        request.selectionManifest.empty() || !request.activeExperts) {
        result.error = "source, output directory, selection manifest and active experts are required";
        return result;
    }
    Selection selection;
    if (!loadSelection(request.selectionManifest, request.activeExperts, selection, result.error)) return result;

    const fs::path source(request.sourceFirstShard);
    const std::string filename = source.filename().string();
    const size_t marker = filename.find("-00001-of-");
    uint32_t shardCount = 1;
    std::string prefix = filename;
    if (marker != std::string::npos) {
        prefix = filename.substr(0, marker);
        const size_t end = filename.find(".gguf", marker);
        if (end == std::string::npos) { result.error = "invalid split GGUF name"; return result; }
        try { shardCount = static_cast<uint32_t>(std::stoul(filename.substr(marker + 10, end - (marker + 10)))); }
        catch (...) { result.error = "invalid split GGUF shard count"; return result; }
    }
    if (!shardCount || shardCount > 4096) { result.error = "invalid shard count"; return result; }

    std::vector<ParsedShard> shards;
    shards.reserve(shardCount);
    for (uint32_t i = 1; i <= shardCount; ++i) {
        fs::path p = source.parent_path();
        if (marker != std::string::npos) p /= prefix + "-" + (i < 10 ? "0000" : i < 100 ? "000" : i < 1000 ? "00" : i < 10000 ? "0" : "") + std::to_string(i) + "-of-" + filename.substr(marker + 10, 5) + ".gguf";
        else p = source;
        ParsedShard shard;
        if (!parseShard(p, shard, result.error)) return result;
        result.sourceBytes += shard.fileBytes;
        result.sourceTensors += shard.tensors.size();
        shards.emplace_back(std::move(shard));
    }

    std::error_code ec;
    const fs::path outputDir(request.outputDirectory);
    if (fs::exists(outputDir, ec)) {
        if (!fs::is_directory(outputDir, ec) || fs::directory_iterator(outputDir, ec) != fs::directory_iterator()) {
            result.error = "output directory must be new or empty";
            return result;
        }
    } else if (!fs::create_directories(outputDir, ec) || ec) {
        result.error = "output directory could not be created";
        return result;
    }

    for (const auto& shard : shards) {
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
                ++result.transformedTensors;
                result.selectedExpertSlices += it->second.size();
            }
            outputTensors.emplace_back(std::move(out));
        }

        auto metadata = shard.metadata;
        patchMetadata(metadata, request.activeExperts);
        const fs::path outputPath = outputDir / shard.path.filename();
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
                for (uint32_t expert : it->second) {
                    // Overflow guard already checked in validateExpertTensorGeometry.
                    const uint64_t srcOffset = dataStart + original->offset + stride * expert;
                    if (!copyRange(in, out, srcOffset, stride)) { result.error = "expert slice copy failed"; return result; }
                }
            } else if (!copyRange(in, out, dataStart + original->offset, original->bytes)) {
                result.error = "tensor copy failed: " + tensor.name; return result;
            }
            const auto written = static_cast<uint64_t>(out.tellp());
            const uint64_t expected = dataStart + tensor.offset + tensor.bytes;
            if (written < expected && !writeZeros(out, expected - written)) { result.error = "tensor padding write failed"; return result; }
            if (written > expected) { result.error = "tensor output offset mismatch"; return result; }
        }
        out.flush();
        if (!out.good()) { result.error = "output shard flush failed"; return result; }
        result.outputBytes += static_cast<uint64_t>(fs::file_size(outputPath, ec));
        result.outputTensors += outputTensors.size();
    }

    const fs::path outputFirst = marker != std::string::npos
        ? outputDir / (prefix + "-00001-of-" + (shardCount < 10 ? "0000" : shardCount < 100 ? "000" : shardCount < 1000 ? "00" : "0") + std::to_string(shardCount) + ".gguf")
        : outputDir / filename;
    GGUFLoader verify;
    if (!verify.load(outputFirst.string())) {
        result.error = "rewritten GGUF reload failed: " + verify.error();
        return result;
    }
    if (verify.shardCount() != shardCount || verify.tensorCount() != result.outputTensors) {
        result.error = "rewritten GGUF inventory mismatch";
        return result;
    }
    result.success = true;
    result.outputFirstShard = outputFirst.string();
    result.sourceShardCount = shardCount;
    result.outputShardCount = verify.shardCount();
    return result;
}

} // namespace Deep2

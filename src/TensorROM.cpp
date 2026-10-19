#include "TensorROM.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace deep2 {

// ---------------------------------------------------------------------------
// GGUF primitive readers (self-contained; TensorROM does not depend on the
// whole-model GGUFLoader, so the two can evolve independently).
// ---------------------------------------------------------------------------

static std::string readGGUFStr(std::ifstream& f) {
    uint64_t len = 0;
    f.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!f || len > 4096) return "";
    std::vector<char> buf(len);
    f.read(buf.data(), len);
    return std::string(buf.data(), len);
}

static void skipArray(std::ifstream& f) {
    uint32_t arrayType = 0;
    uint64_t arrayLen = 0;
    f.read(reinterpret_cast<char*>(&arrayType), sizeof(arrayType));
    f.read(reinterpret_cast<char*>(&arrayLen), sizeof(arrayLen));
    if (arrayLen > 10000000ull) return;
    if (arrayType == 8) {
        for (uint64_t i = 0; i < arrayLen; ++i) readGGUFStr(f);
    } else if (arrayType == 9) {
        for (uint64_t i = 0; i < arrayLen; ++i) skipArray(f);
    } else {
        const uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
        f.seekg(arrayLen * sz[arrayType & 7], std::ios::cur);
    }
}

static void skipValue(uint32_t type, std::ifstream& f) {
    if (type <= 7) {
        const uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1}; // GGUF BOOL is 1 byte
        f.seekg(sz[type & 7], std::ios::cur);
    } else if (type == 8) {
        readGGUFStr(f);
    } else if (type == 9) {
        skipArray(f);
    } else {
        uint32_t sub = 0;
        uint64_t len = 0;
        f.read(reinterpret_cast<char*>(&sub), sizeof(sub));
        f.read(reinterpret_cast<char*>(&len), sizeof(len));
        if (sub == 9) {
            for (uint64_t i = 0; i < len; ++i) readGGUFStr(f);
        } else if (sub == 8) {
            for (uint64_t i = 0; i < len; ++i) skipArray(f);
        } else {
            const uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
            f.seekg(len * sz[sub & 7], std::ios::cur);
        }
    }
}

static inline uint16_t readU16(const uint8_t* p) {
    uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}

static inline float fp16ToF32(uint16_t v) {
    uint32_t sign = (v & 0x8000u) << 16;
    uint32_t exp  = (v & 0x7C00u) >> 10;
    uint32_t frac = (v & 0x03FFu);
    uint32_t f32  = 0;
    if (exp == 31) {
        f32 = sign | 0x7F800000u | (frac << 13);
    } else if (exp == 0) {
        if (frac != 0) {
            while ((frac & 0x0400u) == 0) { frac <<= 1; exp--; }
            exp++;
            frac &= ~0x0400u;
            f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
        } else {
            f32 = sign;
        }
    } else {
        f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
    }
    float r;
    std::memcpy(&r, &f32, 4);
    return r;
}

static inline uint8_t get_q3(const uint8_t* qs, uint64_t k) {
    uint64_t bitOff = k * 3;
    uint64_t i = bitOff >> 3;
    unsigned bo = bitOff & 7u;
    uint32_t bits = qs[i] | (uint32_t(qs[i + 1]) << 8);
    return (uint8_t)((bits >> bo) & 0x07u);
}

static double rms_f32(const float* out, int n) {
    double s = 0;
    for (int i = 0; i < n; ++i) s += out[i] * out[i];
    return std::sqrt(s / n);
}

// Dequantize one Q3_K_M block (114 bytes): qs[0..95], d[96..97] fp16, scales[98..113] int8
static double dequant_q3km_block_rms(const uint8_t* p) {
    float d = fp16ToF32(readU16(p + 96));
    const int8_t* scl = (const int8_t*)(p + 98);
    const uint8_t* qs = p;
    float out[256];
    for (uint64_t k = 0; k < 256; ++k) {
        uint8_t q = get_q3(qs, k);
        int g = (int)((k * 3) / 48);
        float scale = d * static_cast<float>(scl[g]) / 32.0f;
        out[k] = (float)((int)q - 4) * scale;
    }
    return rms_f32(out, 256);
}

// Scan for the correct dataOffset by finding where token_embd's first blocks
// dequantize to sane values with the Q3_K_M layout. Corrects m_shards[0].dataOffset
// if the header-parsed offset is wrong (e.g. due to KV parsing drift).
// Uses coefficient-of-variation across the 8 blocks to reject false positives
// (random bytes that happen to dequantize to low RMS in one block but not all).
static void correct_dataOffset(std::vector<ShardManifest>& shards, std::ifstream& f) {
    // Find token_embd.weight in shard 0
    const TensorEntry* te = nullptr;
    for (const auto& t : shards[0].tensors) {
        if (t.name == "token_embd.weight") { te = &t; break; }
    }
    if (!te) return;

    // Scan near te->offset (the tensor-directory offset relative to dataStart).
    // Tensor offsets are relative to the data section start, so
    //   true_file_position = true_dataStart + te->offset
    // We scan around te->offset to find true_dataStart.
    uint64_t baseAbs = te->offset;
    int64_t bestDelta = 0;
    double bestScore = 1e18;

    std::vector<uint8_t> block(114);
    for (int64_t delta = -16384; delta <= 16384; delta += 4) {
        int64_t testAbs = (int64_t)baseAbs + delta;
        if (testAbs < 0) continue;
        f.clear();
        f.seekg(static_cast<std::streamoff>(testAbs), std::ios::beg);

        double rmsVals[8];
        bool allValid = true;
        for (int b = 0; b < 8; ++b) {
            f.read(reinterpret_cast<char*>(block.data()), 114);
            if (f.gcount() < 114) { allValid = false; break; }
            double r = dequant_q3km_block_rms(block.data());
            rmsVals[b] = r;
            if (r > 3.0 || r < 0.01 || !(r == r)) { allValid = false; break; }
        }
        if (!allValid) continue;

        // Coefficient of variation: correct embeddings have similar RMS per block;
        // random bytes won't.
        double meanRms = 0;
        for (int b = 0; b < 8; ++b) meanRms += rmsVals[b];
        meanRms /= 8.0;
        double varRms = 0;
        for (int b = 0; b < 8; ++b) varRms += (rmsVals[b] - meanRms) * (rmsVals[b] - meanRms);
        varRms /= 8.0;
        double cv = meanRms > 0 ? std::sqrt(varRms) / meanRms : 1e9;

        // Score: low max RMS AND low CV (consistent across blocks)
        double maxRms = rmsVals[0];
        for (int b = 1; b < 8; ++b) if (rmsVals[b] > maxRms) maxRms = rmsVals[b];
        double score = maxRms + 5.0 * cv;
        if (score < bestScore) {
            bestScore = score;
            bestDelta = delta;
        }
    }

    if (bestDelta != 0) {
        // testAbs = te->offset + bestDelta = true_dataStart + te->offset
        // So true_dataStart = testAbs - te->offset = bestDelta
        uint64_t newDataOffset = (uint64_t)bestDelta;
        fprintf(stderr, "[ROM] dataOffset corrected: %llu -> %llu (score=%.4f)\n",
                (unsigned long long)shards[0].dataOffset, newDataOffset, bestScore);
        shards[0].dataOffset = newDataOffset;
    }
}

static std::string readValueAsString(uint32_t type, std::ifstream& f) {
    char buf[64];
    if (type <= 7) {
        const uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
        switch (type) {
            case 0: { uint8_t v = 0; f.read(reinterpret_cast<char*>(&v), 1); std::snprintf(buf, sizeof(buf), "%u", v); return buf; }
            case 1: { int8_t v = 0; f.read(reinterpret_cast<char*>(&v), 1); std::snprintf(buf, sizeof(buf), "%d", v); return buf; }
            case 2: { uint16_t v = 0; f.read(reinterpret_cast<char*>(&v), 2); std::snprintf(buf, sizeof(buf), "%u", v); return buf; }
            case 3: { int16_t v = 0; f.read(reinterpret_cast<char*>(&v), 2); std::snprintf(buf, sizeof(buf), "%d", v); return buf; }
            case 4: { uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4); std::snprintf(buf, sizeof(buf), "%u", v); return buf; }
            case 5: { int32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4); std::snprintf(buf, sizeof(buf), "%d", v); return buf; }
            case 6: { float v = 0; f.read(reinterpret_cast<char*>(&v), 4); std::snprintf(buf, sizeof(buf), "%.9g", v); return buf; }
            case 7: { uint8_t v = 0; f.read(reinterpret_cast<char*>(&v), 1); return v ? "true" : "false"; }
            default: return "";
        }
    } else if (type == 8) {
        return readGGUFStr(f);
    } else if (type == 10) {
        uint64_t v = 0; f.read(reinterpret_cast<char*>(&v), 8); std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v); return buf;
    } else if (type == 11) {
        int64_t v = 0; f.read(reinterpret_cast<char*>(&v), 8); std::snprintf(buf, sizeof(buf), "%lld", (long long)v); return buf;
    } else if (type == 12) {
        double v = 0; f.read(reinterpret_cast<char*>(&v), 8); std::snprintf(buf, sizeof(buf), "%.17g", v); return buf;
    } else {
        skipValue(type, f);
        return "";
    }
}

// ---------------------------------------------------------------------------
// TensorEntry
// ---------------------------------------------------------------------------

uint64_t TensorEntry::byteSize() const {
    uint64_t n = 1;
    for (auto d : dims) n *= d;
    return tensorStorageBytes(n, type);
}

// ---------------------------------------------------------------------------
// TensorROM
// ---------------------------------------------------------------------------

TensorROM::TensorROM() = default;
TensorROM::~TensorROM() = default;

bool TensorROM::parseShard(std::ifstream& f, ShardManifest& manifest) {
    f.read(reinterpret_cast<char*>(&manifest.magic), 4);
    f.read(reinterpret_cast<char*>(&manifest.version), 4);
    if (manifest.magic != 0x46554747u) {
        fprintf(stderr, "[ROM] %s: bad magic 0x%08X\n", manifest.path.c_str(), manifest.magic);
        return false;
    }
    f.read(reinterpret_cast<char*>(&manifest.tensorCount), 8);
    f.read(reinterpret_cast<char*>(&manifest.kvCount), 8);

    bool isMaster = (m_shards.empty());

    // Key-value directory: parse shard 0 fully for geometry, skip payloads otherwise.
    for (uint64_t i = 0; i < manifest.kvCount; ++i) {
        std::string key = readGGUFStr(f);
        uint32_t type = 0;
        f.read(reinterpret_cast<char*>(&type), sizeof(type));
        if (isMaster) {
            m_kvStrings.emplace(key, readValueAsString(type, f));
        } else {
            skipValue(type, f);
        }
    }

    // Tensor directory.
    manifest.tensors.reserve(manifest.tensorCount);
    for (uint64_t i = 0; i < manifest.tensorCount; ++i) {
        TensorEntry e;
        e.name = readGGUFStr(f);
        uint32_t nDims = 0;
        f.read(reinterpret_cast<char*>(&nDims), 4);
        e.dims.resize(nDims);
        if (nDims > 0) f.read(reinterpret_cast<char*>(e.dims.data()), nDims * 8);
        uint32_t type = 0;
        f.read(reinterpret_cast<char*>(&type), sizeof(type));
        e.type = static_cast<TensorType>(type);
        f.read(reinterpret_cast<char*>(&e.offset), 8);
        e.shardIndex = static_cast<size_t>(m_shards.size());
        manifest.tensors.push_back(std::move(e));
    }

    if (!f) {
        fprintf(stderr, "[ROM] %s: truncated header/tensor directory\n", manifest.path.c_str());
        return false;
    }

    // Align to 64 bytes: payload starts here (GGUF spec).
    uint64_t pos = static_cast<uint64_t>(f.tellg());
    uint64_t aligned = (pos + 63) & ~63ull;
    manifest.dataOffset = aligned;
    f.seekg(0, std::ios::end);
    uint64_t end = static_cast<uint64_t>(f.tellg());
    manifest.dataSize = (end > aligned) ? (end - aligned) : 0;
    f.seekg(aligned, std::ios::beg);
    return true;
}

bool TensorROM::addShard(const std::string& path) {
    auto file = std::make_unique<std::ifstream>(path, std::ios::binary);
    if (!file->is_open()) {
        fprintf(stderr, "[ROM] cannot open shard: %s\n", path.c_str());
        return false;
    }

    ShardManifest manifest;
    manifest.path = path;
    manifest.file = std::move(file);

    if (!parseShard(*manifest.file, manifest)) return false;

    fprintf(stderr, "[ROM] shard %zu: magic=GGUF version=%u tensors=%llu kv=%llu "
                    "dataOffset=%llu dataSize=%llu\n",
            m_shards.size(), manifest.version,
            (unsigned long long)manifest.tensorCount, (unsigned long long)manifest.kvCount,
            (unsigned long long)manifest.dataOffset, (unsigned long long)manifest.dataSize);

    m_shards.push_back(std::move(manifest));
    return true;
}

bool TensorROM::finalizeIndex() {
    if (m_shards.empty()) {
        fprintf(stderr, "[ROM] no shards indexed\n");
        return false;
    }

    // Build master geometry from shard 0 key-value pairs.
    const auto lookup = [&](const std::string& key) -> const std::string* {
        auto it = m_kvStrings.find(key);
        return it == m_kvStrings.end() ? nullptr : &it->second;
    };
    auto parseU64 = [&](const std::string* s, uint64_t& out) -> bool {
        if (!s) return false;
        try { out = std::stoull(*s); return true; } catch (...) { return false; }
    };
    auto parseF64 = [&](const std::string* s, double& out) -> bool {
        if (!s) return false;
        try { out = std::stod(*s); return true; } catch (...) { return false; }
    };

    const std::vector<std::string> prefixes = {
        "llama", "qwen2", "gemma2", "phi3", "nemotron", "granite", "starcoder2", "glm"
    };
    for (const auto& p : prefixes) {
        parseU64(lookup(p + ".embedding_length"), m_geom.hiddenDim);
        parseU64(lookup(p + ".block_count"), m_geom.numLayers);
        parseU64(lookup(p + ".attention.head_count"), m_geom.numHeads);
        parseU64(lookup(p + ".attention.head_count_kv"), m_geom.numKVHeads);
        parseU64(lookup(p + ".feed_forward_length"), m_geom.intermediateDim);
    }
    if (auto* s = lookup("general.embedding_length")) parseU64(s, m_geom.hiddenDim);
    if (auto* s = lookup("general.block_count")) parseU64(s, m_geom.numLayers);
    if (auto* s = lookup("general.attention.head_count")) parseU64(s, m_geom.numHeads);
    if (auto* s = lookup("general.attention.head_count_kv")) parseU64(s, m_geom.numKVHeads);
    if (auto* s = lookup("general.feed_forward_length")) parseU64(s, m_geom.intermediateDim);
    if (auto* s = lookup("general.rope.freq_base")) parseF64(s, m_geom.ropeTheta);
    if (auto* s = lookup("phi3.context_length")) parseU64(s, m_geom.maxSeqLen);

    // DeepSeek2 architecture detection + MLA/MoE geometry (Move 7).
    bool isDeepSeek2 = false;
    for (const auto& kv : m_kvStrings) {
        if (kv.first.rfind("deepseek2.", 0) == 0) { isDeepSeek2 = true; break; }
    }
    if (isDeepSeek2) {
        m_geom.arch = ModelArch::DeepSeek2;
        m_geom.hasMla = true;
        auto gU64 = [&](const std::string& key, uint64_t& out) {
            if (auto* s = lookup(key)) {
                try { out = std::stoull(*s); return true; } catch (...) {}
            }
            return false;
        };
        gU64("deepseek2.block_count", m_geom.numLayers);
        gU64("deepseek2.embedding_length", m_geom.hiddenDim);
        gU64("deepseek2.attention.head_count", m_geom.numHeads);
        gU64("deepseek2.attention.head_count_kv", m_geom.numKVHeads);
        gU64("deepseek2.feed_forward_length", m_geom.intermediateDim);
        gU64("deepseek2.vocab_size", m_geom.vocabSize);
        gU64("deepseek2.context_length", m_geom.maxSeqLen);
        if (auto* s = lookup("deepseek2.rope.freq_base")) {
            try { m_geom.ropeTheta = std::stod(*s); } catch (...) {}
        }
        {
            uint64_t tmp = 0;
            if (gU64("deepseek2.attention.kv_lora_rank", tmp)) m_geom.kvLoraRank = static_cast<uint32_t>(tmp);
            if (gU64("deepseek2.rope.dimension_count", tmp)) m_geom.qkRopeHeadDim = static_cast<uint32_t>(tmp);
            uint64_t keyLen = 0;
            if (gU64("deepseek2.attention.key_length", keyLen))
                m_geom.qkNopeHeadDim = static_cast<uint32_t>(keyLen - m_geom.qkRopeHeadDim);
            if (gU64("deepseek2.attention.value_length", tmp)) m_geom.vHeadDim = static_cast<uint32_t>(tmp);
            if (gU64("deepseek2.expert_count", tmp)) m_geom.nRoutedExperts = static_cast<uint32_t>(tmp);
            if (gU64("deepseek2.expert_shared_count", tmp)) m_geom.nSharedExperts = static_cast<uint32_t>(tmp);
            if (gU64("deepseek2.expert_used_count", tmp)) m_geom.moeTopK = static_cast<uint32_t>(tmp);
        }
        uint64_t leadDense = 0;
        gU64("deepseek2.leading_dense_block_count", leadDense);
        for (uint64_t l = leadDense; l < m_geom.numLayers; ++l)
            m_geom.moeLayerIndex.push_back(static_cast<uint32_t>(l));
    }

    // Vocabulary from tokenizer array length.
    if (auto* s = lookup("tokenizer.ggml.tokens")) {
        try { m_geom.vocabSize = std::stoull(*s); } catch (...) {}
    }

    // Global tensor index: every tensor must have a unique name across shards.
    for (size_t s = 0; s < m_shards.size(); ++s) {
        const ShardManifest& m = m_shards[s];
        for (size_t i = 0; i < m.tensors.size(); ++i) {
            const std::string& name = m.tensors[i].name;
            if (m_nameIndex.emplace(name, std::make_pair(s, i)).second == false) {
                fprintf(stderr, "[ROM] duplicate tensor name '%s' in shard %zu\n",
                        name.c_str(), s);
                return false;
            }
        }
    }

    // Correct dataOffset if KV/tensor-directory parsing drifted from the true
    // payload start (e.g. long KV values mis-parsed). Scans near token_embd's
    // offset for a position where Q3_K_M blocks dequantize to sane values.
    correct_dataOffset(m_shards, *m_shards[0].file);

    // Default pager: a few GiB bounded budget, overridable via env.
    if (!m_pager) {
        const char* env = std::getenv("DEEP2_ROM_CACHE_BYTES");
        uint64_t capacity = env ? static_cast<uint64_t>(std::stoull(env)) : (4ull << 30);
        m_pager = std::make_unique<PageCache>(capacity, 256 * 1024);
        // Reader: pageNo is an absolute file page number (readRange passes
        // offset / pageSize), so the absolute file offset is pageNo * pageSize.
        m_pager->setReader([this](uint32_t shard, uint64_t pageNo, uint8_t* buf, uint64_t size) {
            if (shard >= m_shards.size()) return false;
            const ShardManifest& m = m_shards[shard];
            uint64_t absOffset = pageNo * 256ull * 1024ull;
            return readShardRange(shard, absOffset, buf, size);
        });
    }

    fprintf(stderr, "[ROM] index complete: %zu shard(s), %zu tensor(s), arch=%s geometry: "
                    "hidden=%llu layers=%llu heads=%llu kvHeads=%llu ffn=%llu vocab=%llu "
                    "ctx=%llu theta=%.2f\n",
            m_shards.size(), m_nameIndex.size(),
            m_geom.arch == ModelArch::DeepSeek2 ? "deepseek2" : (m_geom.arch == ModelArch::Phi3 ? "phi3" : "unknown"),
            (unsigned long long)m_geom.hiddenDim, (unsigned long long)m_geom.numLayers,
            (unsigned long long)m_geom.numHeads, (unsigned long long)m_geom.numKVHeads,
            (unsigned long long)m_geom.intermediateDim, (unsigned long long)m_geom.vocabSize,
            (unsigned long long)m_geom.maxSeqLen, m_geom.ropeTheta);
    if (m_geom.arch == ModelArch::DeepSeek2) {
        fprintf(stderr, "[ROM] deepseek2 MLA/MoE: qLora=%u kvLora=%u qkNope=%u qkRope=%u vHead=%u "
                        "experts=%u shared=%u topK=%u firstMoeLayer=%llu moeLayers=%llu hasMla=%d\n",
                m_geom.qLoraRank, m_geom.kvLoraRank, m_geom.qkNopeHeadDim, m_geom.qkRopeHeadDim,
                m_geom.vHeadDim, m_geom.nRoutedExperts, m_geom.nSharedExperts, m_geom.moeTopK,
                m_geom.moeLayerIndex.empty() ? 0 : (unsigned long long)m_geom.moeLayerIndex.front(),
                (unsigned long long)m_geom.moeLayerIndex.size(), m_geom.hasMla ? 1 : 0);
    }
    return true;
}

const TensorEntry* TensorROM::findTensor(const std::string& name) const {
    auto it = m_nameIndex.find(name);
    if (it == m_nameIndex.end()) return nullptr;
    return &m_shards[it->second.first].tensors[it->second.second];
}

bool TensorROM::hasTensor(const std::string& name) const {
    return findTensor(name) != nullptr;
}

uint64_t TensorROM::tensorNumValues(const TensorEntry& e) {
    uint64_t n = 1;
    for (auto d : e.dims) n *= d;
    return n;
}

uint64_t TensorROM::tensorStorageBytes(const TensorEntry& e) {
    return deep2::tensorStorageBytes(tensorNumValues(e), e.type);
}

bool TensorROM::readTensor(const TensorEntry& entry, uint8_t* out) const {
    if (!m_pager) return false;
    const ShardManifest& m = m_shards[entry.shardIndex];
    return m_pager->readRange(static_cast<uint32_t>(entry.shardIndex),
                              m.dataOffset + entry.offset, entry.byteSize(), out);
}

bool TensorROM::readTensorRange(const TensorEntry& entry, uint64_t relOffset,
                                uint64_t size, uint8_t* out) const {
    if (!m_pager) return false;
    const ShardManifest& m = m_shards[entry.shardIndex];
    uint64_t avail = entry.byteSize() - relOffset;
    if (size > avail) size = avail;
    return m_pager->readRange(static_cast<uint32_t>(entry.shardIndex),
                              m.dataOffset + entry.offset + relOffset, size, out);
}

TensorLease TensorROM::leaseTensor(const TensorEntry& entry) const {
    if (!m_pager) return TensorLease(*m_pager, 0, 0, 0); // empty
    const ShardManifest& m = m_shards[entry.shardIndex];
    return TensorLease(*m_pager, static_cast<uint32_t>(entry.shardIndex),
                       m.dataOffset + entry.offset, entry.byteSize());
}

std::vector<TensorROM::ShardStatus> TensorROM::shardStatus() const {
    std::vector<ShardStatus> out;
    out.reserve(m_shards.size());
    for (const auto& m : m_shards) {
        ShardStatus s;
        s.path = m.path;
        s.opened = true;
        s.tensorCount = m.tensorCount;
        s.dataBytes = m.dataSize;
        out.push_back(std::move(s));
    }
    return out;
}

bool TensorROM::readShardRange(size_t shardIndex, uint64_t fileOffset,
                               uint8_t* buf, uint64_t size) const {
    if (shardIndex >= m_shards.size()) return false;
    const ShardManifest& m = m_shards[shardIndex];
    if (fileOffset >= m.dataOffset + m.dataSize) return false;
    uint64_t avail = (m.dataOffset + m.dataSize) - fileOffset;
    if (size > avail) size = avail;
    auto& f = *m.file;
    f.clear();
    f.seekg(static_cast<std::streamoff>(fileOffset), std::ios::beg);
    if (!f) return false;
    f.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(size));
    std::streamsize got = f.gcount();
    if (got < 0) return false;
    if ((uint64_t)got < size) std::memset(buf + got, 0, size - (uint64_t)got);
    return true;
}

} // namespace deep2

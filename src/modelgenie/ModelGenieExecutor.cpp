//=============================================================================
// ModelGenieExecutor - Native Deep2 IR execution engine (runtime library)
// RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001 / PRODUCTION_RUNTIME_001
//
// Extracted verbatim from the standalone rawrxd_modelgenie_ir_executor tool.
// The KERNELS and the 300-operation dispatch loop below are unchanged; only
// the test-only CLI/teacher-forced harness was isolated into
// tools/rawrxd_modelgenie_ir_executor.cpp. RawrXDCore.dll links this file.
//=============================================================================

#include "ModelGenieExecutor.hpp"

#include <algorithm>
#include <array>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <immintrin.h>
#include <limits>
#include <memory>
#include <numeric>
#include <omp.h>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <windows.h>

namespace ModelGenie = ::RawrXD::Deep2::ModelGenie;
namespace Generated = ::RawrXD::Deep2::Generated;

namespace MG = ModelGenie;
namespace GEN = Generated;


// Process-wide differential recorder (declared in ModelGenieExecutor.hpp).
// Disabled by default; enabled only by the standalone verification harness.
DifferentialRecorder g_differential_recorder;

//=============================================================================
// GGUFROM - direct GGUF reader (memory-mapped tensor payloads)
//=============================================================================
// GGUF metadata chatter is useful while debugging a model load, but a DLL must
// not flood its host's stderr. Gate it behind RAWRXD_ROM_TRACE=1.
inline bool MgRomTraceEnabled()
{
    static const bool enabled = [] {
        char buf[8] = {0};
        DWORD n = GetEnvironmentVariableA("RAWRXD_ROM_TRACE", buf, sizeof(buf));
        return n > 0 && (buf[0] == '1' || buf[0] == 't' || buf[0] == 'T' || buf[0] == 'y' || buf[0] == 'Y');
    }();
    return enabled;
}
#define MG_ROM_TRACE(...) do { if (MgRomTraceEnabled()) { std::fprintf(stderr, "[ROM]"); std::fprintf(stderr, __VA_ARGS__); } } while (0)

//=============================================================================
// YaRN attention scaling - reference equivalent (llama.cpp deepseek2.cpp)
// RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001
//
// Mirrors, exactly, the parameters llama.cpp derives for DeepSeek-V2-Lite
// (rope.scaling.type == "yarn", freq_scale 0.025, yarn_ext_factor 1.0):
//
//   cparams.yarn_attn_factor = get_mscale(40, rope_yarn_log_mul)
//                              / get_mscale(40, rope_yarn_log_mul)
//                              * (1 / (1 + 0.1*ln(1/freq_scale)))
//                              * rope_attn_factor
//   attn_factor_org = attn_factor * (1 + 0.1*ln(1/freq_scale))
//   mscale          = attn_factor_org * (1 + 0.1*rope_yarn_log_mul*ln(1/freq_scale))
//   kq_scale        = mscale^2 / sqrt(n_embd_head_k)
//
// The two factors cancel, so attn_factor_org == rope_attn_factor == 1.0 and the
// RoPE mscale becomes 1.0 (i.e. cos/sin are NOT magnitude-scaled). The only
// surviving effects are the frequency interpolation+ramp in the angle and the
// mscale^2 factor folded into the attention score scale.
//=============================================================================
namespace MGRope {

constexpr float kFreqBase    = 10000.0f;
constexpr float kFreqScale   = 0.025f;      // deepseek2.rope.scaling.factor
constexpr float kNCtxOrig    = 4096.0f;     // ...original_context_length
constexpr float kYarnLogMul  = 0.707f;      // yarn_log_multiplier / 0.1
constexpr float kBetaFast    = 32.0f;
constexpr float kBetaSlow    = 1.0f;
constexpr float kNEmbdHeadK  = static_cast<float>(GEN::ModelConfig::kKeyLength);   // 192
constexpr float kNEmbdHeadV  = static_cast<float>(GEN::ModelConfig::kValueLength); // 128
constexpr float kAttnFactor  = 1.0f;        // rope_attn_factor (GGUF default)

// llama.cpp: n_rot * log(n_ctx_orig / (beta * 2 * pi)) / (2 * log(freq_base))
inline float CorrDim(float beta)
{
    return GEN::ModelConfig::kRopeDimensionCount *
           logf(kNCtxOrig / (beta * 2.0f * static_cast<float>(3.14159265358979323846))) /
           (2.0f * logf(kFreqBase));
}

inline float CorrDimLow() { const float v = floorf(CorrDim(kBetaFast)); return v < 0.0f ? 0.0f : v; }
inline float CorrDimHigh()
{
    const float v = ceilf(CorrDim(kBetaSlow));
    const float cap = static_cast<float>(GEN::ModelConfig::kRopeDimensionCount) - 1.0f;
    return v > cap ? cap : v;
}

// llama.cpp rope_yarn_ramp(): ramp = 1 - clamp((k - low) / max(0.001, high - low))
inline float RampMix(float k)
{
    const float span = CorrDimHigh() - CorrDimLow();
    const float denominator = span > 0.001f ? span : 0.001f;
    const float y = (k - CorrDimLow()) / denominator;
    if (y <= 0.0f) return 1.0f;
    if (y >= 1.0f) return 0.0f;
    return 1.0f - y;
}

// Effective rotation angle for RoPE pair k (k = i0/2 in ggml) at token position p.
// theta_extrap = p * base^(-2k/n_rot); theta_interp = freq_scale * theta_extrap.
inline float Alpha(size_t position, size_t k)
{
    const float theta_extrap =
        static_cast<float>(position) * powf(kFreqBase, -2.0f * static_cast<float>(k) /
                                                          static_cast<float>(GEN::ModelConfig::kRopeDimensionCount));
    const float theta_interp = kFreqScale * theta_extrap;
    const float ramp = RampMix(static_cast<float>(k));
    // rope_yarn(): theta = theta_interp * (1 - ramp) + theta_extrap * ramp
    return theta_interp * (1.0f - ramp) + theta_extrap * ramp;
}

// The attention score scale. mscale² replaces the plain 1/sqrt(head_dim).
inline float AttentionScoreScale()
{
    const float attn_factor_org = kAttnFactor * (1.0f + 0.1f * logf(1.0f / kFreqScale));
    const float mscale = attn_factor_org * (1.0f + 0.1f * kYarnLogMul * logf(1.0f / kFreqScale));
    return mscale * mscale / sqrtf(kNEmbdHeadK);
}

} // namespace MGRope
bool GGUFROM::Open(const std::string& path)
        {
            MG_ROM_TRACE("Opening: %s\n", path.c_str()); std::fflush(stderr);
            hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_FLAG_RANDOM_ACCESS, nullptr);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                MG_ROM_TRACE("CreateFile failed: %lu\n", GetLastError()); std::fflush(stderr);
                return false;
            }

            LARGE_INTEGER sz;
            if (!GetFileSizeEx(hFile, &sz))
            {
                MG_ROM_TRACE("GetFileSizeEx failed: %lu\n", GetLastError()); std::fflush(stderr);
                Close();
                return false;
            }
            size = sz.QuadPart;
            MG_ROM_TRACE("File size: %llu\n", (unsigned long long)size); std::fflush(stderr);

            hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (!hMap)
            {
                MG_ROM_TRACE("CreateFileMapping failed: %lu\n", GetLastError()); std::fflush(stderr);
                Close();
                return false;
            }

            base = static_cast<const uint8_t*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
            if (!base)
            {
                MG_ROM_TRACE("MapViewOfFile failed: %lu\n", GetLastError()); std::fflush(stderr);
                Close();
                return false;
            }

            MG_ROM_TRACE("Mapped at base=%p\n", base); std::fflush(stderr);

            if (!ParseGGUFHeader())
            {
                MG_ROM_TRACE("Failed to parse GGUF header\n"); std::fflush(stderr);
                Close();
                return false;
            }

            MG_ROM_TRACE("Mapped %llu bytes\n", (unsigned long long)size); std::fflush(stderr);
            return true;
}

//=============================================================================
// GGUFROM::ParseGGUFHeader - reads GGUF v3 header + tensor info directory
//=============================================================================
bool GGUFROM::ParseGGUFHeader()
{
        MG_ROM_TRACE("ParseGGUFHeader ENTERED: size=%llu\n", (unsigned long long)size); std::fflush(stderr);
        if (size < 24) { MG_ROM_TRACE("size < 24\n"); std::fflush(stderr); return false; }
        
        // GGUF v3 header: magic(4), version(4), tensor_count(8), metadata_kv_count(8)
        uint32_t magic = *reinterpret_cast<const uint32_t*>(base);
        MG_ROM_TRACE("magic=0x%08x\n", magic); std::fflush(stderr);
        if (magic != 0x46554747) // "GGUF"
        {
            MG_ROM_TRACE("Invalid GGUF magic: 0x%08x\n", magic); std::fflush(stderr);
            return false;
        }
        
        uint32_t version = *reinterpret_cast<const uint32_t*>(base + 4);
        MG_ROM_TRACE("version=%u\n", version); std::fflush(stderr);
        if (version != 3)
        {
            MG_ROM_TRACE("Unsupported GGUF version: %u\n", version); std::fflush(stderr);
            return false;
        }
        
        uint64_t tensorCount = *reinterpret_cast<const uint64_t*>(base + 8);
        uint64_t metadataKvCount = *reinterpret_cast<const uint64_t*>(base + 16);
        MG_ROM_TRACE("tensorCount=%llu metadataKvCount=%llu\n", tensorCount, metadataKvCount); std::fflush(stderr);
        
        const uint8_t* ptr = base + 24;
        
        // Skip metadata key-value pairs
        for (uint64_t i = 0; i < metadataKvCount; ++i)
        {
            MG_ROM_TRACE("KV %llu: ptr=%p\n", i, ptr); std::fflush(stderr);
            if (ptr + 8 > base + size) { MG_ROM_TRACE("KV %llu: ptr+8 > size\n", i); std::fflush(stderr); return false; }
            uint64_t keyLen = *reinterpret_cast<const uint64_t*>(ptr);
            MG_ROM_TRACE("KV %llu: keyLen=%llu\n", i, keyLen); std::fflush(stderr);
            ptr += 8;
            // Debug: print first few key bytes
            if (keyLen > 0 && keyLen < 100) {
                MG_ROM_TRACE("KV %llu: key='", i);
                for (uint64_t k = 0; k < keyLen && k < 50; ++k) {
                    char c = ptr[k];
                    if (c >= 32 && c <= 126) MG_ROM_TRACE("%c", c);
                    else MG_ROM_TRACE("\\x%02x", (unsigned char)c);
                }
                MG_ROM_TRACE("'\n");
            }
            if (ptr + keyLen > base + size) { MG_ROM_TRACE("KV %llu: ptr+keyLen > size\n", i); std::fflush(stderr); return false; }
            ptr += keyLen;
            
            if (ptr + 8 > base + size) { MG_ROM_TRACE("KV %llu: ptr+8 > size after key\n", i); std::fflush(stderr); return false; }
            uint32_t valueType = *reinterpret_cast<const uint32_t*>(ptr);
            MG_ROM_TRACE("KV %llu: valueType=%u\n", i, valueType); std::fflush(stderr);
            ptr += 4;
            
            // Skip value based on type (simplified - just advance ptr)
            MG_ROM_TRACE("KV %llu: before value ptr=%p\n", i, ptr); std::fflush(stderr);
            switch (valueType)
            {
                case 0: case 1: ptr += 1; break;   // u8/i8
                case 2: case 3: ptr += 2; break;   // u16/i16
                case 4: case 5: case 6: ptr += 4; break;  // u32/i32/f32
                case 7: ptr += 1; break;   // bool
                case 10: case 11: case 12: ptr += 8; break;  // uint64/int64/f64
                case 8: 
                {
                    MG_ROM_TRACE("KV %llu: string case\n", i); std::fflush(stderr);
                    if (ptr + 8 > base + size) { MG_ROM_TRACE("KV %llu: string ptr+8 > size\n", i); std::fflush(stderr); return false; }
                    uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);
                    MG_ROM_TRACE("KV %llu: strLen=%llu\n", i, strLen); std::fflush(stderr);
                    ptr += 8;
                    if (strLen > static_cast<uint64_t>(base + size - ptr))
                    {
                        MG_ROM_TRACE("KV %llu: strLen > remaining\n", i); std::fflush(stderr);
                        return false;
                    }
                    ptr += strLen;
                    break; // string
                }
                case 9: 
                {
                    MG_ROM_TRACE("KV %llu: array case\n", i); std::fflush(stderr);
                    if (ptr + 4 > base + size) { MG_ROM_TRACE("KV %llu: array ptr+4 > size\n", i); std::fflush(stderr); return false; }
                    uint32_t elemType = *reinterpret_cast<const uint32_t*>(ptr);
                    MG_ROM_TRACE("KV %llu: elemType=%u\n", i, elemType); std::fflush(stderr);
                    ptr += 4;
                    if (ptr + 8 > base + size) { MG_ROM_TRACE("KV %llu: array ptr+8 > size\n", i); std::fflush(stderr); return false; }
                    uint64_t arrLen = *reinterpret_cast<const uint64_t*>(ptr);
                    MG_ROM_TRACE("KV %llu: arrLen=%llu\n", i, arrLen); std::fflush(stderr);
                    ptr += 8;
                    // Array element size lookup (GGUF type -> bytes)
                    uint64_t elemSize = 0;
                    switch (elemType) {
                        case 0: case 1: elemSize = 1; break; // u8/i8
                        case 2: case 3: elemSize = 2; break; // u16/i16
                        case 4: case 5: case 6: elemSize = 4; break; // u32/i32/f32
                        case 7: elemSize = 1; break; // bool
                        case 8: 
                            // STRING array: each element is [uint64_t length][length bytes]
                            for (uint64_t a = 0; a < arrLen; ++a) {
                                if (ptr + 8 > base + size) { MG_ROM_TRACE("KV %llu: nested string ptr+8 > size\n", i); std::fflush(stderr); return false; }
                                uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);
                                ptr += 8;
                                if (strLen > static_cast<uint64_t>(base + size - ptr))
                                {
                                    MG_ROM_TRACE("KV %llu: nested strLen > remaining\n", i); std::fflush(stderr);
                                    return false;
                                }
                                ptr += strLen;
                            }
                            break;
                        case 9: elemSize = 8; break; // array (pointer)
                        case 10: case 11: case 12: elemSize = 8; break; // array/uint64/int64
                        default: { MG_ROM_TRACE("KV %llu: unknown elemType=%u\n", i, elemType); std::fflush(stderr); return false; }
                    }
                    // For string arrays, ptr already advanced in loop. For others, advance by arrLen * elemSize.
                    if (elemType != 8) {
                        if (arrLen > static_cast<uint64_t>(base + size - ptr) / elemSize)
                        {
                            MG_ROM_TRACE("KV %llu: arrLen > remaining\n", i); std::fflush(stderr);
                            return false;
                        }
                        ptr += arrLen * elemSize;
                    }
                    break; // array
                }
                default: return false;
            }
            MG_ROM_TRACE("KV %llu: after value ptr=%p\n", i, ptr); std::fflush(stderr);
        }
        
        // Parse tensor info array
        liveTensors.clear();
        liveTensors.reserve(tensorCount);
        
        for (uint64_t i = 0; i < tensorCount; ++i)
        {
            if (ptr + 8 > base + size) return false;
            uint64_t nameLen = *reinterpret_cast<const uint64_t*>(ptr);
            ptr += 8;
            if (ptr + nameLen > base + size) return false;
            std::string name(reinterpret_cast<const char*>(ptr), nameLen);
            ptr += nameLen;
            
            if (ptr + 4 > base + size) return false;
            uint32_t nDims = *reinterpret_cast<const uint32_t*>(ptr);
            ptr += 4;
            
            std::vector<uint64_t> dims;
            dims.reserve(nDims);
            for (uint32_t d = 0; d < nDims; ++d)
            {
                if (ptr + 8 > base + size) return false;
                dims.push_back(*reinterpret_cast<const uint64_t*>(ptr));
                ptr += 8;
            }
            
            if (ptr + 4 > base + size) return false;
            uint32_t typeId = *reinterpret_cast<const uint32_t*>(ptr);
            ptr += 4;
            
            if (ptr + 8 > base + size) return false;
            uint64_t dataOffset = *reinterpret_cast<const uint64_t*>(ptr);
            ptr += 8;
            
            // Map GGML type ID to ModelGenie::GGMLType (fail-closed: only 5 supported types)
            ModelGenie::GGMLType type;
            switch (typeId)
            {
                case 0:   // GGML_TYPE_F32
                    type = ModelGenie::GGMLType::F32;
                    break;
                case 6:   // GGML_TYPE_Q5_0
                    type = ModelGenie::GGMLType::Q5_0;
                    break;
                case 8:   // GGML_TYPE_Q8_0
                    type = ModelGenie::GGMLType::Q8_0;
                    break;
                case 12:  // GGML_TYPE_Q4_K
                    type = ModelGenie::GGMLType::Q4_K;
                    break;
                case 14:  // GGML_TYPE_Q6_K
                    type = ModelGenie::GGMLType::Q6_K;
                    break;
                default:
                    std::fprintf(stderr,
                        "[GGUF] Unsupported tensor type: tensor=%s raw_type=%u\n",
                        name.c_str(),
                        typeId);
                    return false;
            }
            
            // Calculate encoded bytes from dims and type (fail-closed)
            uint64_t elementCount = 1;
            for (auto d : dims) elementCount *= d;
            
            uint64_t encodedBytes = 0;
            switch (type)
            {
                case ModelGenie::GGMLType::F32:
                    encodedBytes = elementCount * 4;
                    break;
                case ModelGenie::GGMLType::Q5_0:
                    if (elementCount % 32 != 0) return false;
                    encodedBytes = (elementCount / 32) * 22;
                    break;
                case ModelGenie::GGMLType::Q8_0:
                    if (elementCount % 32 != 0) return false;
                    encodedBytes = (elementCount / 32) * 34;
                    break;
                case ModelGenie::GGMLType::Q4_K:
                    if (elementCount % 256 != 0) return false;
                    encodedBytes = (elementCount / 256) * 144;
                    break;
                case ModelGenie::GGMLType::Q6_K:
                    if (elementCount % 256 != 0) return false;
                    encodedBytes = (elementCount / 256) * 210;
                    break;
                default:
                    return false;
            }
            
            liveTensors.push_back({name, type, dataOffset, encodedBytes, dims});
        }
        
        // Calculate data section start (after tensor info, aligned to GGUF alignment)
        uint64_t tensorInfoEnd = static_cast<uint64_t>(ptr - base);
        uint64_t alignment = 32; // from metadata
        uint64_t padding = (alignment - (tensorInfoEnd % alignment)) % alignment;
        ggufDataOffset = tensorInfoEnd + padding;
        
        MG_ROM_TRACE("GGUF parsed: tensors=%zu, tensor_info_end=%llu, data_start=%llu (aligned)\n", 
            liveTensors.size(), (unsigned long long)tensorInfoEnd, (unsigned long long)ggufDataOffset);
        return true;
}

//=============================================================================
// FP16 to Float conversion
//=============================================================================
static float FP16ToFloat(uint16_t h)
{
    const float sign = (h & 0x8000u) ? -1.0f : 1.0f;
    const uint32_t exp = (h >> 10) & 31u, mant = h & 1023u;
    if (!exp) return sign * std::ldexp(static_cast<float>(mant), -24);
    if (exp == 31u) return mant ? std::numeric_limits<float>::quiet_NaN()
                                : sign * std::numeric_limits<float>::infinity();
    return sign * std::ldexp(1.0f + float(mant) / 1024.0f, int(exp) - 15);
}

//=============================================================================
// Dequantizer for GGUF tensor types
//=============================================================================
static void DequantizeTensor(const TensorView& tv, std::vector<float>& out)
{
    ModelGenie::GGMLType effectiveType = tv.type;
    
    out.resize(tv.elementCount);
    switch (effectiveType)
    {
        case ModelGenie::GGMLType::F32:
            memcpy(out.data(), tv.data, tv.bytes);
            break;
        case ModelGenie::GGMLType::Q4_K:
        {
            // Q4_K layout: 256 values per 144-byte block
            //   bytes 0..1 : d      (FP16)
            //   bytes 2..3 : dmin   (FP16)
            //   bytes 4..15: scales[12] (packed 6-bit scale/min per sub-block)
            //   bytes 16..143: qs[128] (256 4-bit values)
            struct Q4KBlock { uint16_t d; uint16_t dmin; uint8_t scales[12]; uint8_t qs[128]; };
            static_assert(sizeof(Q4KBlock) == 144, "Q4_K block must be 144 bytes");
            
            const Q4KBlock* src = reinterpret_cast<const Q4KBlock*>(tv.data);
            size_t blocks = tv.bytes / sizeof(Q4KBlock);
            
            auto get_scale_min_k4 = [](int j, const uint8_t* scales, uint8_t* d, uint8_t* m) {
                if (j < 4) {
                    *d = scales[j] & 63;
                    *m = scales[j + 4] & 63;
                } else {
                    *d = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4);
                    *m = (scales[j + 4] >> 4) | ((scales[j] >> 6) << 4);
                }
            };
            
            for (size_t b = 0; b < blocks; ++b)
            {
                float d = FP16ToFloat(src[b].d);
                float dmin = FP16ToFloat(src[b].dmin);
                
                if (!std::isfinite(d) || !std::isfinite(dmin))
                {
                    // Skip this block to avoid propagating NaN
                    continue;
                }
                
                const uint8_t* q = src[b].qs;
                float* out_ptr = &out[b * 256];
                
                int is = 0;
                for (int j = 0; j < 256; j += 64)
                {
                    uint8_t sc1, m1;
                    uint8_t sc2, m2;
                    
                    get_scale_min_k4(is + 0, src[b].scales, &sc1, &m1);
                    get_scale_min_k4(is + 1, src[b].scales, &sc2, &m2);
                    
                    const float d1 = d * sc1;
                    const float mn1 = dmin * m1;
                    const float d2 = d * sc2;
                    const float mn2 = dmin * m2;
                    
                    // First 32: low nibble
                    for (int l = 0; l < 32; ++l)
                    {
                        out_ptr[j + l] = d1 * float(q[l] & 0x0F) - mn1;
                    }
                    // Next 32: high nibble
                    for (int l = 0; l < 32; ++l)
                    {
                        out_ptr[j + 32 + l] = d2 * float(q[l] >> 4) - mn2;
                    }
                    
                    q += 32;
                    is += 2;
                }
            }
            break;
        }
        case ModelGenie::GGMLType::Q8_0:
        {
            struct Q80Block { uint16_t d; int8_t qs[32]; };
            const Q80Block* src = reinterpret_cast<const Q80Block*>(tv.data);
            size_t blocks = tv.bytes / sizeof(Q80Block);
            for (size_t b = 0; b < blocks; ++b) {
                float scale = FP16ToFloat(src[b].d);
                for (int j = 0; j < 32; j++) {
                    out[b * 32 + j] = scale * src[b].qs[j];
                }
            }
            break;
        }
        case ModelGenie::GGMLType::Q5_0:
        {
            struct Block { uint16_t d; uint8_t qh[4]; uint8_t qs[16]; };
            static_assert(sizeof(Block) == 22, "Q5_0 block size");
            const auto* blocks = reinterpret_cast<const Block*>(tv.data);
            for (size_t b = 0; b < tv.bytes/sizeof(Block); ++b) {
                uint32_t qh = 0;
                std::memcpy(&qh, blocks[b].qh, sizeof(qh));
                const float d = FP16ToFloat(blocks[b].d);
                for (int j = 0; j < 16; ++j) {
                    const int lo = int((blocks[b].qs[j] & 15u) | (((qh >> j) & 1u)<<4)) - 16;
                    const int hi = int((blocks[b].qs[j] >> 4) | (((qh >> (j+16)) & 1u)<<4)) - 16;
                    out[b*32+j] = d*lo;
                    out[b*32+j+16] = d*hi;
                }
            }
            break;
        }
        case ModelGenie::GGMLType::Q6_K:
        {
            struct Block { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d; };
            static_assert(sizeof(Block) == 210, "Q6_K block size");
            const auto* blocks = reinterpret_cast<const Block*>(tv.data);
            for (size_t b = 0; b < tv.bytes/sizeof(Block); ++b) {
                const float d = FP16ToFloat(blocks[b].d);
                for (int half = 0; half < 2; ++half) {
                    const uint8_t* ql = blocks[b].ql + 64*half;
                    const uint8_t* qh = blocks[b].qh + 32*half;
                    const int8_t* sc = blocks[b].scales + 8*half;
                    float* dst = out.data() + 256*b + 128*half;
                    for (int l = 0; l < 32; ++l) {
                        const int g = l/16;
                        dst[l]    = d*sc[g]   * (int((ql[l]&15)    | ((qh[l]&3)<<4))-32);
                        dst[l+32] = d*sc[g+2] * (int((ql[l+32]&15) | (((qh[l]>>2)&3)<<4))-32);
                        dst[l+64] = d*sc[g+4] * (int((ql[l]>>4)    | (((qh[l]>>4)&3)<<4))-32);
                        dst[l+96] = d*sc[g+6] * (int((ql[l+32]>>4) | (((qh[l]>>6)&3)<<4))-32);
                    }
                }
            }
            break;
        }
        default:
            memset(out.data(), 0, out.size() * sizeof(float));
            break;
    }
}

//=============================================================================
// TensorStats for numerical boundary isolation
//=============================================================================
struct TensorStats
{
    size_t count = 0;
    size_t nonfinite = 0;
    size_t firstNonfiniteIndex = 0;
    float min = 0.0f;
    float max = 0.0f;
    float l2 = 0.0f;
};

static TensorStats ComputeTensorStats(const float* data, size_t n)
{
    TensorStats stats;
    stats.count = n;
    if (n == 0) return stats;
    
    stats.min = data[0];
    stats.max = data[0];
    stats.l2 = 0.0f;
    
    for (size_t i = 0; i < n; ++i)
    {
        float v = data[i];
        if (!std::isfinite(v))
        {
            stats.nonfinite++;
            if (stats.firstNonfiniteIndex == 0) stats.firstNonfiniteIndex = i;
        }
        else
        {
            if (i == 0) { stats.min = data[i]; stats.max = data[i]; }
            else { stats.min = (std::min)(stats.min, v); stats.max = (std::max)(stats.max, v); }
            stats.l2 += v * v;
        }
    }
    stats.l2 = std::sqrt(stats.l2);
    return stats;
}

static void EmitTensorStats(const char* blockLabel, const char* stage, const TensorStats& stats)
{
    std::fprintf(stderr, "TENSOR_STATS BLOCK=%s STAGE=%s COUNT=%zu NONFINITE=%zu FIRST_NF_IDX=%zu MIN=%.6f MAX=%.6f L2=%.6f\n",
                 blockLabel, stage, stats.count, stats.nonfinite, stats.firstNonfiniteIndex,
                 stats.min, stats.max, stats.l2);
    fflush(stderr);
}

//=============================================================================
// Kernel Primitives
//=============================================================================
static void RMSNorm(float* out, const float* in, const float* w, int n, float eps)
{
    if (!out || !in || !w || n <= 0) return;
    double ss = 0.0;
    for (int i=0;i<n;++i) ss += double(in[i])*in[i];
    const float scale = 1.0f/std::sqrt(float(ss/n)+eps);
    for (int i=0;i<n;++i) out[i] = in[i]*w[i]*scale;
}

static void Softmax(float* x, int n)
{
    if (!x || n<=0) return;
    float m = x[0];
    for (int i=1;i<n;++i) m=(std::max)(m,x[i]);
    double sum=0.0;
    for (int i=0;i<n;++i) {x[i]=std::exp(x[i]-m);sum+=x[i];}
    if (sum>0) for (int i=0;i<n;++i) x[i] = float(x[i]/sum);
}

static void MatMul(const float* A, const float* B, float* C, int M, int K, int N)
{
    // GGUF 2D tensors: dim[0] contiguous.  B element (row k, col j) = B[k + j*K].
    #pragma omp parallel for schedule(static)
    for (int i=0;i<M;++i)
        for (int j=0;j<N;++j) {
            double sum=0.0;
            for (int k=0;k<K;++k) sum+=double(A[i*K+k])*B[k+j*K];
            C[i*N+j]=float(sum);
        }
}

static void VecAdd(float* out, const float* a, const float* b, int n)
{
    int i = 0;
    for (; i + 15 < n; i += 16)
        _mm512_storeu_ps(out + i, _mm512_add_ps(_mm512_loadu_ps(a + i), _mm512_loadu_ps(b + i)));
    for (; i < n; i++) out[i] = a[i] + b[i];
}

static void Silu(float* x, int n)
{
    for (int i = 0; i < n; ++i) {
        float x_val = x[i];
        float sig = 1.0f / (1.0f + expf(-x_val));
        x[i] = x_val * sig;
    }
}

static void RoPE(float* q, float* k, int pos, int headDim, int numHeads)
{
    // Simplified RoPE implementation
    (void)pos; (void)headDim; (void)numHeads;
    (void)q; (void)k;
}


//=============================================================================
// RoPE (Rotary Positional Embedding)
//=============================================================================
static void ApplyRoPE(float* q, float* k, int pos, int head_dim, int num_heads, uint64_t rope_freq_base)
{
    if (!q || !k) return;
    const float base = static_cast<float>(rope_freq_base);
    for (int h = 0; h < num_heads; ++h) {
        for (int i = 0; i < head_dim; i += 2) {
            float theta = powf(base, -static_cast<float>(i) / head_dim);
            float alpha = pos * theta;
            float ca = cosf(alpha), sa = sinf(alpha);
            float* qp = q + h * head_dim + i;
            float q0 = qp[0], q1 = qp[1];
            qp[0] = q0 * ca - q1 * sa;
            qp[1] = q0 * sa + q1 * ca;
            float* kp = k + h * head_dim + i;
            float k0 = kp[0], k1 = kp[1];
            kp[0] = k0 * ca - k1 * sa;
            kp[1] = k0 * sa + k1 * ca;
        }
    }
}



//=============================================================================
// Operand Accessor Helpers (valid C++ - no undefined pointer arithmetic)
//=============================================================================
static MG::OperandRef GenInput(const GEN::OperationIR& op, uint32_t i) {
    switch (i) {
        case 0: return op.input0; case 1: return op.input1; case 2: return op.input2;
        case 3: return op.input3; case 4: return op.input4; case 5: return op.input5;
        case 6: return op.input6; case 7: return op.input7; default: return MG::OperandRef{};
    }
}

static MG::OperandRef GenWeight(const GEN::OperationIR& op, uint32_t i) {
    switch (i) {
        case 0: return op.weight0; case 1: return op.weight1; case 2: return op.weight2;
        case 3: return op.weight3; case 4: return op.weight4; case 5: return op.weight5;
        case 6: return op.weight6; case 7: return op.weight7; default: return MG::OperandRef{};
    }
}

static const float* ResolveInput(const GEN::OperationIR& op, uint32_t idx, ActivationArena& arena, uint32_t tokenId) {
    MG::OperandRef ref = GenInput(op, idx);
    if (ref.domain == MG::OperandDomain::Activation) {
        return arena.Get(ref.id);
    } else if (ref.domain == MG::OperandDomain::RuntimeScalar) {
        // Use the provided tokenId (set by executor)
        static thread_local float tokenStorage = 0.0f;
        tokenStorage = static_cast<float>(tokenId);
        return &tokenStorage;
    }
    return nullptr;
}

static const float* ResolveWeight(const GEN::OperationIR& op, uint32_t idx, const ROMResolver& romResolver) {
    MG::OperandRef ref = GenWeight(op, idx);
    if (ref.domain == MG::OperandDomain::RomTensor) {
        return romResolver.GetDequantizedWeight(ref.id);
    }
    return nullptr;
}

static float* ResolveOutput(const GEN::OperationIR& op, ActivationArena& arena,
                            const ROMResolver& rom)
{
    if (op.output.domain != MG::OperandDomain::Activation) return nullptr;
    size_t count = 0;
    switch (op.requiredPrimitive) {
        case MG::Primitive::MlaDecompressFwd:
            count = GEN::ModelConfig::kHeadCount *
                    (GEN::ModelConfig::kKeyLength + GEN::ModelConfig::kValueLength);
            break;
        case MG::Primitive::AttentionFwd:
        case MG::Primitive::MoEExecuteFwd:
            count = GEN::ModelConfig::kEmbeddingLength;
            break;
        case MG::Primitive::TopKFwd:
            count = 2 * GEN::ModelConfig::kExpertUsedCount;
            break;
        case MG::Primitive::ResidualAddFwd:
            count = arena.Size(GenInput(op, 0).id);
            break;
        case MG::Primitive::RmsNormFwd:
        case MG::Primitive::LinearFwd:
        case MG::Primitive::RouterFwd:
        case MG::Primitive::LMHeadFwd: {
            if (!op.weightCount) break;
            const auto ref = GenWeight(op, 0);
            const TensorView* view = ref.domain == MG::OperandDomain::RomTensor ?
                                     rom.Resolve(ref.id) : nullptr;
            if (!view) break;
            if (op.requiredPrimitive == MG::Primitive::RmsNormFwd && view->rank == 1)
                count = view->dims[0];
            else if (view->rank == 2)
                count = GenInput(op, 0).domain == MG::OperandDomain::RuntimeScalar ?
                        view->dims[0] : view->dims[1];
            break;
        }
        default: break;
    }
    return count ? arena.GetOrCreate(op.output.id, count) : nullptr;
}

//=============================================================================
// Primitive Dispatcher
//=============================================================================
class PrimitiveDispatcher
{
public:
    // Returns true if operation executed successfully, false if skipped/failed
    static bool Dispatch(const Generated::OperationIR& op, 
                         ActivationArena& arena,
                         const ROMResolver& romResolver,
                         uint32_t tokenId,
                         MlaKVCache* kvCache = nullptr,
                         size_t position = 0)
    {
        using Primitive = ModelGenie::Primitive;
        
        // Helper to get operand pointers using global helper functions
        auto getInput = [&](const GEN::OperationIR& op, uint32_t idx) -> const float* {
            return ResolveInput(op, idx, arena, tokenId);
        };
        
        auto getWeight = [&](const GEN::OperationIR& op, uint32_t idx) -> const float* {
            return ResolveWeight(op, idx, romResolver);
        };
        
auto getOutput = [&](const GEN::OperationIR& op) -> float* {
            return ResolveOutput(op, arena, romResolver);
        };
        
        // Compute layer index from blockIndex for MLA operations
        // Layer 0: blockIndex = UINT32_MAX (special)
        // Layer 1+: blockIndex = layerIdx (1, 2, 3... 26)
        size_t layerIdx = 0;
        if (op.requiredPrimitive == Primitive::MlaDecompressFwd || 
            op.requiredPrimitive == Primitive::AttentionFwd) {
if (op.blockIndex == UINT32_MAX) {
                layerIdx = 0;
            } else if (op.blockIndex >= 1) {
                layerIdx = op.blockIndex;
            }
        }
        
        switch (op.requiredPrimitive) {
            case Primitive::RmsNormFwd: {
                const float* x=getInput(op,0), *w=getWeight(op,0);
                float* y=getOutput(op);
                const auto wr=GenWeight(op,0), xr=GenInput(op,0);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id) : nullptr;
                if (!x||!w||!y||!v||v->rank!=1 || xr.domain!=MG::OperandDomain::Activation ||
                    arena.Size(xr.id)!=v->dims[0] || arena.Size(op.output.id)!=v->dims[0]) return false;
                RmsNormFwd(x,w,y,op);
                return true;
            }
            case Primitive::LinearFwd: {
                const float* x=getInput(op,0), *w=getWeight(op,0);
                float* y=getOutput(op);
                const auto wr=GenWeight(op,0), xr=GenInput(op,0);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id):nullptr;
                const float* second=op.inputCount>1 ? getInput(op,1) : nullptr;
                if (op.inputCount>1 && (!second || arena.Size(GenInput(op,1).id)!=arena.Size(xr.id)))
                    return false;
                return LinearFwd(x,w,y,v,xr,arena.Size(xr.id),arena.Size(op.output.id),second);
            }
            case Primitive::MatMulFwd: {
                return false;
            }
            case Primitive::AttentionFwd: {
                const auto qr=GenInput(op,0), kr=GenInput(op,1);
                const float* q=getInput(op,0), *kv=getInput(op,1);
                float* output=getOutput(op);
                return AttentionFwd(q,kv,output,arena.Size(qr.id),arena.Size(kr.id),
                                    arena.Size(op.output.id), kvCache, layerIdx, position, op.opId);
            }
            case Primitive::MlaDecompressFwd: {
                const auto xr=GenInput(op,0), n=GenWeight(op,0), a=GenWeight(op,1),b=GenWeight(op,2);
                const float* input=getInput(op,0), *wn=getWeight(op,0);
                const float* wa=getWeight(op,1), *wb=getWeight(op,2);
                float* output=getOutput(op);
                if (n.domain!=MG::OperandDomain::RomTensor || a.domain!=MG::OperandDomain::RomTensor ||
                    b.domain!=MG::OperandDomain::RomTensor) return false;
                return MlaDecompressFwd(input,wn,wa,wb,output,romResolver.Resolve(n.id),
                                         romResolver.Resolve(a.id),romResolver.Resolve(b.id),
                                         arena.Size(xr.id),arena.Size(op.output.id), kvCache, layerIdx, position);
            }
            case Primitive::RouterFwd: {
                const auto xr=GenInput(op,0), wr=GenWeight(op,0);
                const float* input=getInput(op,0), *weight=getWeight(op,0);
                float* output=getOutput(op);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id):nullptr;
                return LinearFwd(input,weight,output,v,xr,arena.Size(xr.id),arena.Size(op.output.id));
            }
            case Primitive::TopKFwd: {
                const auto r = GenInput(op, 0);
                // getOutput() allocates the activation. Function arguments have
                // unspecified evaluation order, so never query Size() in the same call.
                const float* input = getInput(op, 0);
                float* output = getOutput(op);
                const size_t inputN = arena.Size(r.id);
                const size_t outputN = arena.Size(op.output.id);
                if (!input || !output || inputN != GEN::ModelConfig::kExpertCount ||
                    outputN != 2u * GEN::ModelConfig::kExpertUsedCount) {
                    std::fprintf(stderr,
                        "[IR] TOPK_BIND_FAIL op=%u inputN=%zu outputN=%zu input=%d output=%d\n",
                        op.opId, inputN, outputN, input != nullptr, output != nullptr);
                    return false;
                }
                return TopKFwd(input, output, inputN, outputN);
            }
            case Primitive::MoEExecuteFwd: {
                const auto a = GenInput(op, 0), b = GenInput(op, 1);
                const float* input = getInput(op, 0);
                const float* choices = getInput(op, 1);
                // ResolveOutput must run before any output Size query.
                float* output = getOutput(op);
                const size_t inputN = arena.Size(a.id);
                const size_t choicesN = arena.Size(b.id);
                const size_t outputN = arena.Size(op.output.id);
                if (!input || !choices || !output ||
                    inputN != GEN::ModelConfig::kEmbeddingLength ||
                    choicesN != 2u * GEN::ModelConfig::kExpertUsedCount ||
                    outputN != GEN::ModelConfig::kEmbeddingLength) {
                    std::fprintf(stderr,
                        "[IR] MOE_BIND_FAIL op=%u inputN=%zu choicesN=%zu outputN=%zu "
                        "input=%d choices=%d output=%d\n",
                        op.opId, inputN, choicesN, outputN,
                        input != nullptr, choices != nullptr, output != nullptr);
                    return false;
                }
                return MoEExecuteFwd(input, choices, output, op, romResolver,
                                     inputN, choicesN, outputN);
            }
            case Primitive::ResidualAddFwd: {
                const auto ar=GenInput(op,0), br=GenInput(op,1);
                const size_t n=arena.Size(ar.id);
                const float* a=getInput(op,0),*b=getInput(op,1);
                float* out=getOutput(op);
                if (!n || n!=arena.Size(br.id) || n!=arena.Size(op.output.id) || !a || !b || !out)
                    return false;
                for (size_t j=0;j<n;++j) out[j]=a[j]+b[j];
                return true;
            }
            case Primitive::LMHeadFwd: {
                const auto xr=GenInput(op,0),wr=GenWeight(op,0);
                const float* input=getInput(op,0), *weight=getWeight(op,0);
                float* output=getOutput(op);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id):nullptr;
                
                // Diagnostic: LM-head write boundary
                const size_t outputCount = arena.Size(op.output.id);
                std::fprintf(stderr, "[LMHEAD_WRITE] op=%u output_id=%u ptr=%p elements=%zu\n",
                             op.opId, op.output.id, static_cast<const void*>(output), outputCount);
                fflush(stderr);
                
                bool result = LinearFwd(input,weight,output,v,xr,arena.Size(xr.id),arena.Size(op.output.id));
                
                // Verify output after write
                if (result && output && outputCount == 102400) {
                    bool finite = true;
                    uint32_t argmaxIdx = 0;
                    float argmaxVal = output[0];
                    for (size_t i = 0; i < 102400; ++i) {
                        if (!std::isfinite(output[i])) { finite = false; break; }
                        if (output[i] > argmaxVal) { argmaxVal = output[i]; argmaxIdx = static_cast<uint32_t>(i); }
                    }
                    std::fprintf(stderr, "[LMHEAD_WRITE] finite=%d argmax=%u max_val=%.6f\n", finite ? 1 : 0, argmaxIdx, argmaxVal);
                    fflush(stderr);
                }
                return result;
            }
            default:
                std::fprintf(stderr, "[IR] Unsupported primitive: %u\n", static_cast<uint32_t>(op.requiredPrimitive));
                return false;
        }
    }

private:
    // RMSNorm forward pass
    static void RmsNormFwd(const float* input, const float* weight, float* output, const GEN::OperationIR& op) {
        // Get dimensions from weight tensor (should be 1D: hidden_size)
        // For now assume 2048 hidden size
        const uint32_t hiddenSize = 2048;
        const float eps = 1e-6f;
        
        // Compute RMS
        float sumSq = 0.0f;
        for (uint32_t i = 0; i < hiddenSize; ++i) {
            float v = input[i];
            sumSq += v * v;
        }
        float rms = sqrtf(sumSq / hiddenSize + eps);
        
        // Normalize and scale
        for (uint32_t i = 0; i < hiddenSize; ++i) {
            output[i] = (input[i] / rms) * weight[i];
        }
    }
    
    // All GGUF 2D tensors are stored with dim[0] contiguous (GGML convention).
    // Element (row j=input, column i=output) is at offset j + i * in.
    static bool LinearFwd(const float* input, const float* weight, float* output,
                           const TensorView* view, const MG::OperandRef& inputRef,
                           size_t inputN, size_t outputN, const float* gate = nullptr)
    {
        if (!view || view->rank != 2 || !input || !weight || !output) return false;
        const size_t in = view->dims[0], out = view->dims[1];
        if (inputRef.domain == MG::OperandDomain::RuntimeScalar) {
            // Embedding lookup: token ID indexes dim[1] (vocab).
            // Row t starts at weight + t * in (GGML: dim[0] contiguous).
            // output = column `token` of weight, length = in (hidden)
            const uint32_t token = static_cast<uint32_t>(input[0]);
            if (token >= out || outputN != in) return false;
            for (size_t j = 0; j < in; ++j)
                output[j] = weight[j + token * in];
            return true;
        }
        if (inputN != in || outputN != out) return false;
        std::vector<float> gated;
        if (gate) {
            gated.resize(in);
            for (size_t j = 0; j < in; ++j)
                gated[j] = (input[j] / (1.0f + std::exp(-input[j]))) * gate[j];
            input = gated.data();
        }
        return DotRows(weight, input, output, in, out);
    }

    // All GGUF 2D tensors are stored with dim[0] contiguous (GGML convention).
    // Element (row j=input, column i=output) is at offset j + i * in.
    // Computes: output[i] = sum_j input[j] * weight[j + i * in]
    static bool DotRows(const float* weight, const float* input, float* output,
                        size_t in, size_t out)
    {
        if (!weight || !input || !output || !in || !out) return false;
        #pragma omp parallel for schedule(static) if(out >= 128)
        for (int64_t i = 0; i < static_cast<int64_t>(out); ++i) {
            double sum = 0.0;
            for (size_t j = 0; j < in; ++j) {
                sum += double(input[j]) * double(weight[j + i * in]);
            }
            output[i] = float(sum);
        }
        return true;
    }


// For position 0 with a single causal token, attention softmax contains one
// element and is exactly 1.0: the output is V regardless of Q/K scores.
// This is ONLY a token-zero kernel, not an autoregressive KV-cache kernel.
// Full causal attention with KV cache:
// q: [heads, key] - current query (content key + positional key with RoPE at current position)
// KV cache contains expanded K/V for all positions up to current (keys already have RoPE at their write position)
    static bool AttentionFwd(const float* q, const float* kv, float* output,
                             size_t qN, size_t kvN, size_t outputN,
                             const MlaKVCache* kvCache = nullptr, size_t layerIdx = 0, size_t position = 0,
                             uint32_t opId = 0)
    {
        const size_t heads = GEN::ModelConfig::kHeadCount;
        const size_t key = GEN::ModelConfig::kKeyLength;
        const size_t value = GEN::ModelConfig::kValueLength;
        const size_t rope = GEN::ModelConfig::kRopeDimensionCount;
        const size_t noRope = key - rope;
        const size_t kSize = heads * key;
        const size_t vSize = heads * value;
        const size_t kv_size = heads * (key + value); // 5120
        
        if (!q || !output || qN != kSize || outputN != vSize) return false;
        
        // If no KV cache or position 0, use simple path (kv contains current K/V)
        if (!kvCache || position == 0) {
            if (!kv || kvN != kSize + vSize) return false;
            std::memcpy(output, kv + kSize, vSize * sizeof(float));
            return true;
        }
        
        // Causal attention with KV cache
        // q: [heads, key] - current query (positional component NOT yet RoPE'd)
        // KV cache contains expanded K/V for all positions 0..position (keys already RoPE'd at their positions)
        const size_t seq_len = position + 1; // including current
        if (layerIdx >= kvCache->layers.size() || kvCache->layers[layerIdx].Size() != seq_len) {
            std::fprintf(stderr, "[KV] Invalid layer or prefix at position %zu, layer %zu\n", position, layerIdx);
            return false;
        }
        const float* all_kv_latent = kvCache->layers[layerIdx].ReadAllKvLatent();
        const float* all_k_rope_raw = kvCache->layers[layerIdx].ReadAllKRopeRaw();
        if (!all_kv_latent || !all_k_rope_raw) return false;
        
        // Apply RoPE to query's positional component at current position
        std::vector<float> q_rope(heads * key);
        for (size_t head = 0; head < heads; ++head) {
            const float* q_head = q + head * key;
            float* q_rope_head = q_rope.data() + head * key;
            // Content key (noRope) unchanged
            std::memcpy(q_rope_head, q_head, noRope * sizeof(float));
            // Positional key (rope) - apply YaRN-interpolated RoPE at current position
            for (size_t i = 0; i < rope; i += 2) {
                const float alpha = MGRope::Alpha(position, i / 2);
                const float ca = cosf(alpha), sa = sinf(alpha);
                float p0 = q_head[noRope + i];
                float p1 = q_head[noRope + i + 1];
                q_rope_head[noRope + i] = p0 * ca - p1 * sa;
                q_rope_head[noRope + i + 1] = p0 * sa + p1 * ca;
            }
        }
        
        // llama.cpp deepseek2: kq_scale = mscale^2 / sqrt(n_embd_head_k)
        const float scale = MGRope::AttentionScoreScale();
        const bool capture_scores = g_differential_recorder.ShouldRecord(position);
        std::vector<float> captured_scores, captured_weights;
        if (capture_scores) {
            captured_scores.resize(heads * seq_len);
            captured_weights.resize(heads * seq_len);
        }
        
        // DIFF: Record query after RoPE
        DIFF_RECORD("Attention_Q_RoPE", opId, layerIdx, position, "q_rope", q_rope.data(), {(int64_t)heads * key});
        
        // DIFF: Test capture at start of AttentionFwd
        DIFF_RECORD("AttentionFwd_Entry", opId, layerIdx, position, "entry_test", q_rope.data(), {(int64_t)heads * key});
        
        // For each head, compute attention over all cached positions
        for (size_t head = 0; head < heads; ++head) {
            // Query for this head (with RoPE applied): q_rope[head * key ... (head+1)*key - 1]
            const float* q_head = q_rope.data() + head * key;
            
            // Split query into q_nope (128) and q_pe (64)
            const float* q_nope = q_head;
            const float* q_pe = q_head + 128;
            
            // Accumulator for output values - use vector to avoid stack overflow
            std::vector<float> out_acc(value, 0.0f);
            float denom = 0.0f;
            
            // Find max score for numerical stability
            float max_score = -INFINITY;
            for (size_t pos = 0; pos < seq_len; ++pos) {
                const float* kv_latent_pos = kvCache->layers[layerIdx].ReadKvLatent(pos);
                const float* k_rope_raw_pos = kvCache->layers[layerIdx].ReadKRopeRaw(pos);
                if (!kv_latent_pos || !k_rope_raw_pos) return false;
                
                // Reconstruct K for this position and head:
                // K = [kv_latent (512) per pos] + [k_rope (64) with RoPE at pos]
                // Per head: K_nope (128) from kv_latent + K_pe (64) from k_rope_raw with RoPE at pos
                
                // K_nope for this head: 128 elements from kv_latent
                const float* k_nope = kv_latent_pos + head * 128;
                
                // K_pe: apply YaRN-interpolated RoPE to k_rope_raw at this position
                float k_pe[64];
                const float* k_rope_raw = all_k_rope_raw + pos * 64;
                for (size_t i = 0; i < 64; i += 2) {
                    const float alpha = MGRope::Alpha(pos, i / 2);
                    const float ca = cosf(alpha), sa = sinf(alpha);
                    float p0 = k_rope_raw[i];
                    float p1 = k_rope_raw[i + 1];
                    k_pe[i] = p0 * ca - p1 * sa;
                    k_pe[i + 1] = p0 * sa + p1 * ca;
                }
                
                // Compute dot product qÂ·k (both have RoPE at their respective positions)
                float score = 0.0f;
                // q_nope (128) dot k_nope (128)
                for (size_t i = 0; i < 128; ++i) {
                    score += q_nope[i] * k_nope[i];
                }
                // q_pe (64) dot k_pe (64) - both have RoPE at their positions
                for (size_t i = 0; i < 64; ++i) {
                    score += q_head[128 + i] * k_pe[i];
                }
                score *= scale;
                if (capture_scores) captured_scores[head * seq_len + pos] = score;
                
                if (score > max_score) max_score = score;
            }
            
            // Compute softmax and weighted sum
            for (size_t pos = 0; pos < seq_len; ++pos) {
                const float* kv_latent_pos = kvCache->layers[layerIdx].ReadKvLatent(pos);
                const float* k_rope_raw_pos = kvCache->layers[layerIdx].ReadKRopeRaw(pos);
                if (!kv_latent_pos || !k_rope_raw_pos) return false;
                
                const float* k_nope = kv_latent_pos + head * 128;
                const float* k_rope_raw = all_k_rope_raw + pos * 64;
                float k_pe[64];
                for (size_t i = 0; i < 64; i += 2) {
                    const float alpha = MGRope::Alpha(pos, i / 2);
                    const float ca = cosf(alpha), sa = sinf(alpha);
                    float p0 = k_rope_raw[i];
                    float p1 = k_rope_raw[i + 1];
                    k_pe[i] = p0 * ca - p1 * sa;
                    k_pe[i + 1] = p0 * sa + p1 * ca;
                }
                
                float score = 0.0f;
                for (size_t i = 0; i < 128; ++i) {
                    score += q_nope[i] * k_nope[i];
                }
                for (size_t i = 0; i < 64; ++i) {
                    score += q_head[128 + i] * k_pe[i];
                }
                score *= scale;
                
                float exp_score = expf(score - max_score);
                if (capture_scores) captured_weights[head * seq_len + pos] = exp_score;
                denom += exp_score;
                
                // V is the value from expanded KV at this position
                // kv passed to this function contains [K (3072), V (2048)] for current position
                const float* v_head = kv + 3072 + head * 128;
                
                // DIFF: Capture reconstructed V for this head at this position
                DIFF_RECORD("MLA_V_RECONSTRUCTED", opId, layerIdx, position, 
                            "v_reconstructed", v_head, {(int64_t)value});
                
                for (size_t i = 0; i < 128; ++i) {
                    out_acc[i] += exp_score * v_head[i];
                }
            }
            
            // Normalize and write output
            float* out_head = output + head * value;
            for (size_t i = 0; i < value; ++i) {
                out_head[i] = out_acc[i] / denom;
            }
            if (capture_scores)
                for (size_t pos = 0; pos < seq_len; ++pos)
                    captured_weights[head * seq_len + pos] /= denom;
        }
        if (capture_scores) {
            DIFF_RECORD("Attention_Scores", opId, layerIdx, position, "scaled_scores",
                        captured_scores.data(), (std::vector<int64_t>{static_cast<int64_t>(heads), static_cast<int64_t>(seq_len)}));
            DIFF_RECORD("Attention_Weights", opId, layerIdx, position, "softmax",
                        captured_weights.data(), (std::vector<int64_t>{static_cast<int64_t>(heads), static_cast<int64_t>(seq_len)}));
        }
        
        // DIFF: Record pre-wo concatenated head outputs (MLA_PRE_WO)
        DIFF_RECORD("MLA_PRE_WO", opId, layerIdx, position, "pre_wo", output, {(int64_t)heads * value});
        
        // DIFF: Test capture right before Attention_Output
        DIFF_RECORD("Test_Before_Attention_Output", opId, layerIdx, position, "test_before_output", output, {(int64_t)heads * value});
        
        // DIFF: Record attention output
        DIFF_RECORD("Attention_Output", opId, layerIdx, position, "output", output, {(int64_t)heads * value});
        
        return true;
    }

// Input x[2048] -> A projection [576] -> RMSNorm latent [512] ->
    // RoPE key component [64] -> B projection [4096] -> [16*128 key_nope, 16*128 value] = 4096 floats.
    // With KV cache: writes latent [512] and k_rope_raw [64] to cache at current position.
    // Returns expanded K/V for current position: [16*128 key_nope, 16*64 key_pe, 16*128 value] = 5120 floats.
    // Applies RoPE to key positional component at write position.
    static bool MlaDecompressFwd(const float* input, const float* norm,
                                 const float* kvA, const float* kvB, float* output,
                                 const TensorView* normView, const TensorView* aView,
                                 const TensorView* bView, size_t inputN, size_t outputN,
                                 MlaKVCache* kvCache = nullptr, size_t layerIdx = 0, size_t position = 0)
    {
        const size_t hidden = GEN::ModelConfig::kEmbeddingLength;
        const size_t rank = GEN::ModelConfig::kKvLoraRank;          // 512
        const size_t rope = GEN::ModelConfig::kRopeDimensionCount;  // 64
        const size_t heads = GEN::ModelConfig::kHeadCount;          // 16
        const size_t key = GEN::ModelConfig::kKeyLength;            // 192
        const size_t value = GEN::ModelConfig::kValueLength;        // 128
        const size_t noRope = key - rope;                           // 128
        if (!input || !norm || !kvA || !kvB || !output ||
            !normView || !aView || !bView ||
            rank + rope != 576 || noRope != value ||
            normView->rank != 1 || normView->dims[0] != rank ||
            aView->rank != 2 || aView->dims[0] != hidden || aView->dims[1] != rank + rope ||
            bView->rank != 2 || bView->dims[0] != rank || bView->dims[1] != heads * (noRope + value) ||
            inputN != hidden || outputN != heads * (key + value)) return false;
        
        // Latent decomposition: [512 kv_latent | 64 k_rope_raw]
        std::vector<float> latent(rank + rope);
        if (!DotRows(kvA, input, latent.data(), hidden, rank + rope)) return false;
        
        // RMSNorm on kv_latent only (first 512 elements)
        double ss = 0;
        for (size_t j = 0; j < rank; ++j) ss += double(latent[j]) * latent[j];
        const float factor = 1.0f / std::sqrt(float(ss / rank) + float(GEN::ModelConfig::kRmsEps));
        for (size_t j = 0; j < rank; ++j) latent[j] *= factor * norm[j];
        
        // Separate kv_latent (512) and k_rope_raw (64)
        const float* kv_latent = latent.data();          // [512]
        const float* k_rope_raw = latent.data() + rank;  // [64]
        
        // B projection: [512] -> [4096] = 16 * (128 key_nope + 128 value)
        std::vector<float> expanded(heads * (noRope + value));
        if (!DotRows(kvB, kv_latent, expanded.data(), rank, expanded.size())) return false;
        const size_t kSize = heads * key;  // 3072
        
        // Prepare positional key component with RoPE for this position
        // Apply RoPE to k_rope_raw at write position
        std::vector<float> k_rope(rope);
        if (position == 0) {
            // Position 0: RoPE is identity
            std::memcpy(k_rope.data(), k_rope_raw, rope * sizeof(float));
        } else {
            const float base = static_cast<float>(GEN::ModelConfig::kRopeFreqBase);
            for (size_t i = 0; i < rope; i += 2) {
                float theta = powf(base, -static_cast<float>(i) / static_cast<float>(rope));
                float alpha = static_cast<float>(position) * theta;
                float ca = cosf(alpha), sa = sinf(alpha);
                float p0 = k_rope_raw[i];
                float p1 = k_rope_raw[i + 1];
                k_rope[i] = p0 * ca - p1 * sa;
                k_rope[i + 1] = p0 * sa + p1 * ca;
            }
        }
        
        // DIFF: Capture MLA components
        if (g_differential_recorder.ShouldRecord(position)) {
            DIFF_RECORD("MLA_kv_latent", 0, layerIdx, position, "kv_latent", kv_latent, {(int64_t)rank});
            DIFF_RECORD("MLA_k_rope_raw", 0, layerIdx, position, "k_rope_raw", k_rope_raw, {(int64_t)rope});
            DIFF_RECORD("MLA_k_rope", 0, layerIdx, position, "k_rope", k_rope.data(), {(int64_t)rope});
            DIFF_RECORD("MLA_expanded", 0, layerIdx, position, "expanded_KV", expanded.data(), {(int64_t)heads * (noRope + value)});
        }
        
        // Build output: [16*192 K (128 nope + 64 pe), 16*128 V]
        for (size_t head = 0; head < heads; ++head) {
            const size_t src = head * (noRope + value);  // 256 per head
            const size_t dst = head * key;               // 192 per head
            // K_nope from expanded
            std::memcpy(output + dst, expanded.data() + src, noRope * sizeof(float));
            // K_pe from k_rope (shared across heads)
            std::memcpy(output + dst + noRope, k_rope.data(), rope * sizeof(float));
            // V from expanded
            std::memcpy(output + kSize + head * value, expanded.data() + src + noRope, value * sizeof(float));
        }
        
        // Write kv_latent (512) and k_rope_raw (64) to KV cache if provided
        if (kvCache) {
            if (layerIdx >= kvCache->layers.size() ||
                kvCache->layers[layerIdx].Size() != position) {
                std::fprintf(stderr, "[KV] Duplicate/gap write at position %zu layer %zu\n", position, layerIdx);
                return false;
            }
            // Store kv_latent (512) and k_rope_raw (64) in cache
            if (!kvCache->layers[layerIdx].WriteLatentKv(kv_latent, k_rope_raw)) return false;
        }
        
        return true;
    }

    // Encode selected expert indices and unnormalized routing probabilities.
    // With norm_topk_prob=false (DeepSeek-V2-Lite-Chat default), probabilities
    // are preserved unnormalized: each output prob[i] = softmax(input)[ids[i]].
    // MoEExecuteFwd applies the score as a linear weight in the weighted sum.
    static bool TopKFwd(const float* input, float* output, size_t inputN, size_t outputN)
    {
        constexpr uint32_t total = GEN::ModelConfig::kExpertCount;
        constexpr uint32_t k = GEN::ModelConfig::kExpertUsedCount;
        if (!input || !output || inputN != total || outputN != 2*k) return false;
        double maxV = -std::numeric_limits<double>::infinity();
        for (size_t i=0;i<total;++i) {
            if (!std::isfinite(input[i])) return false;
            maxV = (std::max)(maxV, double(input[i]));
        }
        std::array<double, total> prob{};
        double sum = 0.0;
        for (size_t i=0;i<total;++i) { prob[i] = std::exp(double(input[i])-maxV); sum += prob[i]; }
        if (!(sum > 0.0)) return false;
        std::array<uint32_t,total> ids{};
        std::iota(ids.begin(), ids.end(), 0u);
        std::stable_sort(ids.begin(), ids.end(), [&](uint32_t a, uint32_t b) { return prob[a] > prob[b]; });
        for (uint32_t i=0;i<k;++i) {
            output[i] = float(ids[i]);
            output[k+i] = float(prob[ids[i]] / sum);
        }
        return true;
    }

    static bool MoEExecuteFwd(const float* input, const float* choices, float* output,
                              const GEN::OperationIR& op, const ROMResolver& rom,
                              size_t inputN, size_t choicesN, size_t outputN)
    {
        constexpr uint32_t experts = GEN::ModelConfig::kExpertCount;
        constexpr uint32_t selected = GEN::ModelConfig::kExpertUsedCount;
        constexpr size_t hidden = GEN::ModelConfig::kEmbeddingLength;
        constexpr size_t ffn = GEN::ModelConfig::kExpertFfnLength;
        if (!input || !choices || !output || inputN != hidden ||
            choicesN != 2*selected || outputN != hidden || op.blockIndex == 0 ||
            op.blockIndex >= GEN::ModelConfig::kBlockCount || op.weightCount < 3)
            return false;
        const auto gateId = GenWeight(op,0), downId = GenWeight(op,1), upId = GenWeight(op,2);
        if (gateId.domain != MG::OperandDomain::RomTensor ||
            downId.domain != MG::OperandDomain::RomTensor ||
            upId.domain != MG::OperandDomain::RomTensor) return false;
        const auto& b = GEN::kBlockGenomeTable[op.blockIndex];
        if (!b.ffnGateShExp || !b.ffnUpShExp || !b.ffnDownShExp) return false;
        std::fill(output, output+outputN, 0.0f);
        std::vector<float> gateW, upW, downW;
        std::vector<float> g(ffn), u(ffn), tmp(hidden);
        for (uint32_t i=0;i<selected;++i) {
            const float idF = choices[i], score = choices[selected+i];
            if (!std::isfinite(idF) || !std::isfinite(score) ||
                idF < 0 || idF >= experts || float(uint32_t(idF)) != idF) return false;
            const uint32_t id = uint32_t(idF);
            if (!rom.GetExpertSlice(gateId.id,id,gateW) ||
                !rom.GetExpertSlice(upId.id,id,upW) ||
                !rom.GetExpertSlice(downId.id,id,downW) ||
                gateW.size() != ffn*hidden || upW.size() != ffn*hidden ||
                downW.size() != hidden*ffn) return false;
            if (!DotRows(gateW.data(),input,g.data(),hidden,ffn) ||
                !DotRows(upW.data(),input,u.data(),hidden,ffn)) return false;
            for (size_t j=0;j<ffn;++j)
                g[j] = (g[j] / (1.0f + std::exp(-g[j]))) * u[j];
            if (!DotRows(downW.data(),g.data(),tmp.data(),ffn,hidden)) return false;
            for (size_t j=0;j<hidden;++j) output[j] += score*tmp[j];
        }
        // Two always-active shared experts are concatenated into a single FFN.
        const auto* gateView = rom.Resolve(*b.ffnGateShExp);
        const auto* upView = rom.Resolve(*b.ffnUpShExp);
        const auto* downView = rom.Resolve(*b.ffnDownShExp);
        const float* sharedGate = rom.GetDequantizedWeight(*b.ffnGateShExp);
        const float* sharedUp = rom.GetDequantizedWeight(*b.ffnUpShExp);
        const float* sharedDown = rom.GetDequantizedWeight(*b.ffnDownShExp);
        const size_t shared = ffn*GEN::ModelConfig::kExpertSharedCount;
        if (!gateView || !upView || !downView || !sharedGate || !sharedUp || !sharedDown ||
            gateView->rank!=2 || gateView->dims[0]!=hidden || gateView->dims[1]!=shared ||
            upView->rank!=2 || upView->dims[0]!=hidden || upView->dims[1]!=shared ||
            downView->rank!=2 || downView->dims[0]!=shared || downView->dims[1]!=hidden)
            return false;
        g.resize(shared);u.resize(shared);
        if (!DotRows(sharedGate,input,g.data(),hidden,shared) ||
            !DotRows(sharedUp,input,u.data(),hidden,shared)) return false;
        for (size_t j=0;j<shared;++j) g[j] = (g[j]/(1.0f+std::exp(-g[j])))*u[j];
        if (!DotRows(sharedDown,g.data(),tmp.data(),shared,hidden)) return false;
        for (size_t j=0;j<hidden;++j) output[j] += tmp[j];
        return true;
    }

    // ResidualAdd forward pass
    static void ResidualAddFwd(const float* input0, const float* input1, float* output, const GEN::OperationIR& op) {
        const uint32_t hiddenSize = 2048;
        for (uint32_t i = 0; i < hiddenSize; ++i) {
            output[i] = input0[i] + input1[i];
        }
    }
};

//=============================================================================
// IR Executor - Walks kExecutionIRTable and dispatches primitives
// The declaration lives in ModelGenieExecutor.hpp so the standalone tool and
// RawrXDCore.dll share exactly one implementation.
//=============================================================================
IRExecutor::IRExecutor(const std::string& ggufPath, uint32_t tokenId)
        : romResolver_(ggufPath), tokenId_(tokenId)
    {
        if (!romResolver_.IsValid()) {
            std::fprintf(stderr, "[IR] Failed to initialize ROM resolver\n");
        }
        // Initialize KV cache for testing (use smaller max_seq_len to avoid OOM)
        // Full context is 163840 but we only need a few tokens for testing
        kvCache_.Init(1024);
}

bool IRExecutor::Execute()
{
        std::fprintf(stderr, "[IR] Starting execution of %u operations\n", GEN::kExecutionOpCount);
        fflush(stderr);
        
        if (!romResolver_.IsValid()) {
            std::fprintf(stderr, "[IR] ROM resolver invalid\n");
            return false;
        }
        
        // Bind RuntimeScalar 0 to tokenId
        tokenStorage_ = static_cast<float>(tokenId_);
        
        uint32_t opsDispatched = 0;
        uint32_t opsVisited = 0;
        uint32_t opsSkipped = 0;
        visited_ = dispatched_ = skipped_ = 0;
        logits_.clear();
        
        for (uint32_t i = 0; i < GEN::kExecutionOpCount; ++i)
        {
            const auto& op = GEN::kExecutionIRTable[i];
            opsVisited++;
            
            // DIFF: Record input before execution
            if (g_differential_recorder.enabled && op.requiredPrimitive == ModelGenie::Primitive::MlaDecompressFwd) {
                const float* input = ResolveInput(op, 0, arena_, tokenId_);
                if (input) {
                    DIFF_RECORD("MlaDecompress_Input", op.opId, op.blockIndex, position_, "input", 
                               ResolveInput(op, 0, arena_, tokenId_), {(int64_t)GEN::ModelConfig::kEmbeddingLength});
                }
            }
            
            // Dispatch primitive - let dispatcher decide if supported
            bool executed = PrimitiveDispatcher::Dispatch(op, arena_, romResolver_, tokenId_, &kvCache_, position_);
if (executed && op.output.domain == MG::OperandDomain::Activation) {
                RawrXD_IR_Trace::save(op.opId, arena_.Get(op.output.id),
                                     arena_.Size(op.output.id));
            }
            
            // Capture the persistent prefix (including all earlier positions) after
            // the current position has been written into the layer's cache.
            if (executed && op.requiredPrimitive == MG::Primitive::MlaDecompressFwd &&
                g_differential_recorder.ShouldRecord(position_)) {
                const size_t layer = op.blockIndex == UINT32_MAX ? 0 : op.blockIndex;
                if (layer < kvCache_.layers.size()) {
                    const auto& cache = kvCache_.layers[layer];
                    const size_t count = cache.Size() * 512;  // kv_latent size
                    if (count && count <= 200000u) {
                        // Read all kv_latent and k_rope_raw for captured positions
                        std::vector<float> all_latent(count);
                        std::vector<float> all_rope(cache.Size() * 64);
                        for (size_t pos = 0; pos < cache.Size(); ++pos) {
                            const float* src_latent = cache.ReadKvLatent(pos);
                            const float* src_rope = cache.ReadKRopeRaw(pos);
                            if (src_latent && src_rope) {
                                std::memcpy(all_latent.data() + pos * 512, src_latent, 512 * sizeof(float));
                                std::memcpy(all_rope.data() + pos * 64, src_rope, 64 * sizeof(float));
                            }
                        }
                        DIFF_RECORD("MLA_CacheKV_Prefix", op.opId, static_cast<uint32_t>(layer),
                                    position_, "kv_latent", all_latent.data(), (std::vector<int64_t>{static_cast<int64_t>(cache.Size()), 512}));
                        DIFF_RECORD("MLA_CacheKV_Prefix", op.opId, static_cast<uint32_t>(layer),
                                    position_, "k_rope_raw", all_rope.data(), (std::vector<int64_t>{static_cast<int64_t>(cache.Size()), 64}));
                    }
                }
            }

            // DIFF: Record key intermediate activations
            if (g_differential_recorder.enabled && executed) {
                const float* result = arena_.Get(op.output.id);
                const size_t n = arena_.Size(op.output.id);
                if (result && n > 0) {
                    std::string tensor_type;
                    if (op.requiredPrimitive == ModelGenie::Primitive::MlaDecompressFwd) {
                        tensor_type = "MlaDecompress_Output";
                    } else if (op.requiredPrimitive == ModelGenie::Primitive::AttentionFwd) {
                        tensor_type = "Attention_Output";
                    } else if (op.requiredPrimitive == ModelGenie::Primitive::MoEExecuteFwd) {
                        tensor_type = "MoE_Output";
                    } else if (op.requiredPrimitive == ModelGenie::Primitive::TopKFwd) {
                        tensor_type = "MoE_TopK";
                    } else if (op.requiredPrimitive == ModelGenie::Primitive::RmsNormFwd) {
                        tensor_type = "RMSNorm_Output";
                    } else if (op.requiredPrimitive == ModelGenie::Primitive::LinearFwd) {
                        tensor_type = "Linear_Output";
                    } else {
                        tensor_type = "Output";
                    }
                    DIFF_RECORD(tensor_type.c_str(), op.opId, op.blockIndex, position_, "output", result, {(int64_t)n});
                }
            }
            
            if (executed && op.output.domain == MG::OperandDomain::Activation) {
                const float* result = arena_.Get(op.output.id);
                const size_t n = arena_.Size(op.output.id);
                if (!result || !n) executed = false;
                else for (size_t j=0;j<n;++j)
                    if (!std::isfinite(result[j])) {
                        std::fprintf(stderr,"[IR] NONFINITE op=%u offset=%zu\n",op.opId,j);
                        executed = false;
                        break;
                    }
            }
            if (executed) {
                opsDispatched++;
            } else {
                opsSkipped++;
                std::fprintf(stderr, "[IR] Op %u: primitive %u skipped/failed\n", 
                             op.opId, static_cast<uint32_t>(op.requiredPrimitive));
            }
            
            if ((opsVisited % 50) == 0)
            {
                std::fprintf(stderr, "[IR] Progress: %u/%u ops visited, %u dispatched, %u skipped\n",
                             opsVisited, GEN::kExecutionOpCount, opsDispatched, opsSkipped);
                fflush(stderr);
            }
        }
        
        std::fprintf(stderr, "[IR] Execution complete: visited=%u dispatched=%u skipped=%u\n",
                     opsVisited, opsDispatched, opsSkipped);
        
        visited_ = opsVisited;
        dispatched_ = opsDispatched;
        skipped_ = opsSkipped;
        constexpr uint32_t kLmHeadOpId = 299;
        constexpr size_t kExpectedVocab = 102400;
        
        const auto& lmHeadOp = GEN::kExecutionIRTable[kLmHeadOpId];
        const uint32_t logitsActivationId = lmHeadOp.output.id;
        
        // Diagnostic: trace both candidate activation IDs
        const float* logitsPtr299 = arena_.Get(299);
        const size_t count299 = arena_.Size(299);
        const float* logitsPtr14000 = arena_.Get(14000);
        const size_t count14000 = arena_.Size(14000);
        
        std::fprintf(stderr, "[LMHEAD_READ] requested=299 ptr=%p elements=%zu\n",
                     static_cast<const void*>(logitsPtr299), count299);
        std::fprintf(stderr, "[LMHEAD_READ] requested=14000 ptr=%p elements=%zu\n",
                     static_cast<const void*>(logitsPtr14000), count14000);
        std::fprintf(stderr, "[LMHEAD_AUTHORITY] op=%u output_id=%u ptr=%p elements=%zu\n",
                     kLmHeadOpId, logitsActivationId, 
                     static_cast<const void*>(arena_.Get(logitsActivationId)), 
                     arena_.Size(logitsActivationId));
        fflush(stderr);
        
        // Use the IR-declared output activation
        const float* logitsPtr = arena_.Get(logitsActivationId);
        const size_t logitsCount = arena_.Size(logitsActivationId);
        
        // Fail-closed: require valid, correctly sized, finite logits
        if (!logitsPtr || logitsCount != kExpectedVocab) {
            std::fprintf(stderr, "[LMHEAD_AUTHORITY] FAIL: missing or incorrectly sized output (ptr=%p count=%zu expected=%zu)\n",
                         static_cast<const void*>(logitsPtr), logitsCount, kExpectedVocab);
            fflush(stderr);
            return false;
        }
        
        // Verify all logits are finite
        bool allFinite = true;
        uint32_t argmaxIdx = 0;
        float argmaxVal = logitsPtr[0];
        for (size_t i = 0; i < kExpectedVocab; ++i) {
            if (!std::isfinite(logitsPtr[i])) {
                allFinite = false;
                std::fprintf(stderr, "[LMHEAD_AUTHORITY] FAIL: nonfinite logit at index %zu\n", i);
                fflush(stderr);
                break;
            }
            if (logitsPtr[i] > argmaxVal) {
                argmaxVal = logitsPtr[i];
                argmaxIdx = static_cast<uint32_t>(i);
            }
        }
        
        if (!allFinite) {
            return false;
        }
        
        std::fprintf(stderr, "[LMHEAD_AUTHORITY] PASS: argmax=%u max_val=%.6f\n", argmaxIdx, argmaxVal);
        fflush(stderr);

        // Capture the authoritative logits snapshot (same buffer used for sampling)
        logits_.assign(logitsPtr, logitsPtr + kExpectedVocab);

        return opsSkipped == 0;
}

uint32_t IRExecutor::SampleToken() const
{
    if (logits_.empty()) return 0;
    
    uint32_t bestIdx = 0;
    float bestVal = logits_[0];
    for (uint32_t i = 1; i < logits_.size(); ++i) {
        if (logits_[i] > bestVal) {
            bestVal = logits_[i];
            bestIdx = i;
        }
    }
    return bestIdx;
}


//=============================================================================
// IRExecutor::Prefill - decode a token sequence into the persistent KV cache.
// Arena activations are cleared between tokens; only the KV cache survives,
// which is exactly the state the IR attention kernels read back.
//=============================================================================
bool IRExecutor::Prefill(const std::vector<uint32_t>& tokens)
{
    if (tokens.empty()) return false;
    if (!romResolver_.IsValid()) return false;

    for (size_t i = 0; i < tokens.size(); ++i) {
        SetTokenId(tokens[i]);
        ClearArena();
        if (!Execute()) return false;
        AdvancePosition();
    }
    return Skipped() == 0;
}

//=============================================================================
// IRExecutor::Generate - greedy autoregressive decode.
// Each generated token becomes the next input; the KV cache persists, so no
// re-prefill of the prompt is performed.
//=============================================================================
std::vector<uint32_t> IRExecutor::Generate(const std::vector<uint32_t>& prompt, uint32_t maxTokens)
{
    std::vector<uint32_t> out;
    if (maxTokens == 0) return out;
    if (!romResolver_.IsValid()) return out;

    uint32_t next = 0;
    if (!prompt.empty()) {
        if (!Prefill(prompt)) return out;
        next = SampleToken();
    } else {
        next = tokenId_;
    }

    for (uint32_t i = 0; i < maxTokens; ++i) {
        if (i > 0 || prompt.empty()) {
            SetTokenId(next);
            ClearArena();
            if (!Execute()) break;
            AdvancePosition();
        }
        out.push_back(next);
        next = SampleToken();
    }
    return out;
}

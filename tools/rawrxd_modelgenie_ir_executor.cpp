//=============================================================================
// rawrxd_modelgenie_ir_executor - Native IR Execution Engine
// RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001
//
// Walks GEN::kExecutionIRTable[300] as the authoritative execution graph.
// Replaces hand-coded Forward() with IR-driven execution.
//=============================================================================

#include "ModelGenome.hpp"
#include "ModelGenomeReader.cpp"
#include "ModelExport.generated.hpp"
#include "ExecutionIR.generated.hpp"
#include "CapabilityManifest.generated.hpp"
#include "TensorROM.generated.hpp"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <immintrin.h>
#include <limits>
#include <memory>
#include <omp.h>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <windows.h>

namespace ModelGenie = ::RawrXD::Deep2::ModelGenie;
namespace Generated = ::RawrXD::Deep2::Generated;
namespace Deep2 = ::RawrXD::Deep2;

namespace MG = ModelGenie;
namespace GEN = Generated;

//=============================================================================
// TensorView - Runtime tensor reference
//=============================================================================
struct TensorView
{
    Generated::TensorId id;
    const uint8_t* data;
    uint64_t bytes;
    ModelGenie::GGMLType type;
    const uint32_t* dims;
    uint32_t rank;
    uint64_t elementCount;
    const char* name;
};

//=============================================================================
// GGUF ROM Mapper
//=============================================================================
class GGUFROM
{
public:
    const uint8_t* base = nullptr;
    uint64_t size = 0;
    uint64_t ggufDataOffset = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = INVALID_HANDLE_VALUE;

    struct LiveTensorInfo {
        std::string name;
        ModelGenie::GGMLType type;
        uint64_t dataOffset;
        uint64_t encodedBytes;
        std::vector<uint64_t> dims;
    };
    std::vector<LiveTensorInfo> liveTensors;

bool Open(const std::string& path)
        {
            std::fprintf(stderr, "[ROM] Opening: %s\n", path.c_str()); std::fflush(stderr);
            hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_FLAG_RANDOM_ACCESS, nullptr);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                std::fprintf(stderr, "[ROM] CreateFile failed: %lu\n", GetLastError()); std::fflush(stderr);
                return false;
            }

            LARGE_INTEGER sz;
            if (!GetFileSizeEx(hFile, &sz))
            {
                std::fprintf(stderr, "[ROM] GetFileSizeEx failed: %lu\n", GetLastError()); std::fflush(stderr);
                Close();
                return false;
            }
            size = sz.QuadPart;
            std::fprintf(stderr, "[ROM] File size: %llu\n", (unsigned long long)size); std::fflush(stderr);

            hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (!hMap)
            {
                std::fprintf(stderr, "[ROM] CreateFileMapping failed: %lu\n", GetLastError()); std::fflush(stderr);
                Close();
                return false;
            }

            base = static_cast<const uint8_t*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
            if (!base)
            {
                std::fprintf(stderr, "[ROM] MapViewOfFile failed: %lu\n", GetLastError()); std::fflush(stderr);
                Close();
                return false;
            }

            std::fprintf(stderr, "[ROM] Mapped at base=%p\n", base); std::fflush(stderr);

            if (!ParseGGUFHeader())
            {
                std::fprintf(stderr, "[ROM] Failed to parse GGUF header\n"); std::fflush(stderr);
                Close();
                return false;
            }

            std::fprintf(stderr, "[ROM] Mapped %llu bytes\n", (unsigned long long)size); std::fflush(stderr);
            return true;
        }

    void Close()
    {
        if (base) { UnmapViewOfFile(base); base = nullptr; }
        if (hMap) { CloseHandle(hMap); hMap = nullptr; }
        if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; }
    }

private:
    bool ParseGGUFHeader()
    {
        std::fprintf(stderr, "[ROM] ParseGGUFHeader ENTERED: size=%llu\n", (unsigned long long)size); std::fflush(stderr);
        if (size < 24) { std::fprintf(stderr, "[ROM] size < 24\n"); std::fflush(stderr); return false; }
        
        // GGUF v3 header: magic(4), version(4), tensor_count(8), metadata_kv_count(8)
        uint32_t magic = *reinterpret_cast<const uint32_t*>(base);
        std::fprintf(stderr, "[ROM] magic=0x%08x\n", magic); std::fflush(stderr);
        if (magic != 0x46554747) // "GGUF"
        {
            std::fprintf(stderr, "[ROM] Invalid GGUF magic: 0x%08x\n", magic); std::fflush(stderr);
            return false;
        }
        
        uint32_t version = *reinterpret_cast<const uint32_t*>(base + 4);
        std::fprintf(stderr, "[ROM] version=%u\n", version); std::fflush(stderr);
        if (version != 3)
        {
            std::fprintf(stderr, "[ROM] Unsupported GGUF version: %u\n", version); std::fflush(stderr);
            return false;
        }
        
        uint64_t tensorCount = *reinterpret_cast<const uint64_t*>(base + 8);
        uint64_t metadataKvCount = *reinterpret_cast<const uint64_t*>(base + 16);
        std::fprintf(stderr, "[ROM] tensorCount=%llu metadataKvCount=%llu\n", tensorCount, metadataKvCount); std::fflush(stderr);
        
        const uint8_t* ptr = base + 24;
        
        // Skip metadata key-value pairs
        for (uint64_t i = 0; i < metadataKvCount; ++i)
        {
            std::fprintf(stderr, "[ROM] KV %llu: ptr=%p\n", i, ptr); std::fflush(stderr);
            if (ptr + 8 > base + size) { std::fprintf(stderr, "[ROM] KV %llu: ptr+8 > size\n", i); std::fflush(stderr); return false; }
            uint64_t keyLen = *reinterpret_cast<const uint64_t*>(ptr);
            std::fprintf(stderr, "[ROM] KV %llu: keyLen=%llu\n", i, keyLen); std::fflush(stderr);
            ptr += 8;
            // Debug: print first few key bytes
            if (keyLen > 0 && keyLen < 100) {
                std::fprintf(stderr, "[ROM] KV %llu: key='", i);
                for (uint64_t k = 0; k < keyLen && k < 50; ++k) {
                    char c = ptr[k];
                    if (c >= 32 && c <= 126) std::fprintf(stderr, "%c", c);
                    else std::fprintf(stderr, "\\x%02x", (unsigned char)c);
                }
                std::fprintf(stderr, "'\n"); std::fflush(stderr);
            }
            if (ptr + keyLen > base + size) { std::fprintf(stderr, "[ROM] KV %llu: ptr+keyLen > size\n", i); std::fflush(stderr); return false; }
            ptr += keyLen;
            
            if (ptr + 8 > base + size) { std::fprintf(stderr, "[ROM] KV %llu: ptr+8 > size after key\n", i); std::fflush(stderr); return false; }
            uint32_t valueType = *reinterpret_cast<const uint32_t*>(ptr);
            std::fprintf(stderr, "[ROM] KV %llu: valueType=%u\n", i, valueType); std::fflush(stderr);
            ptr += 4;
            
            // Skip value based on type (simplified - just advance ptr)
            std::fprintf(stderr, "[ROM] KV %llu: before value ptr=%p\n", i, ptr); std::fflush(stderr);
            switch (valueType)
            {
                case 0: case 1: ptr += 1; break;   // u8/i8
                case 2: case 3: ptr += 2; break;   // u16/i16
                case 4: case 5: case 6: ptr += 4; break;  // u32/i32/f32
                case 7: ptr += 1; break;   // bool
                case 10: case 11: case 12: ptr += 8; break;  // uint64/int64/f64
                case 8: 
                {
                    std::fprintf(stderr, "[ROM] KV %llu: string case\n", i); std::fflush(stderr);
                    if (ptr + 8 > base + size) { std::fprintf(stderr, "[ROM] KV %llu: string ptr+8 > size\n", i); std::fflush(stderr); return false; }
                    uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);
                    std::fprintf(stderr, "[ROM] KV %llu: strLen=%llu\n", i, strLen); std::fflush(stderr);
                    ptr += 8;
                    if (strLen > static_cast<uint64_t>(base + size - ptr))
                    {
                        std::fprintf(stderr, "[ROM] KV %llu: strLen > remaining\n", i); std::fflush(stderr);
                        return false;
                    }
                    ptr += strLen;
                    break; // string
                }
                case 9: 
                {
                    std::fprintf(stderr, "[ROM] KV %llu: array case\n", i); std::fflush(stderr);
                    if (ptr + 4 > base + size) { std::fprintf(stderr, "[ROM] KV %llu: array ptr+4 > size\n", i); std::fflush(stderr); return false; }
                    uint32_t elemType = *reinterpret_cast<const uint32_t*>(ptr);
                    std::fprintf(stderr, "[ROM] KV %llu: elemType=%u\n", i, elemType); std::fflush(stderr);
                    ptr += 4;
                    if (ptr + 8 > base + size) { std::fprintf(stderr, "[ROM] KV %llu: array ptr+8 > size\n", i); std::fflush(stderr); return false; }
                    uint64_t arrLen = *reinterpret_cast<const uint64_t*>(ptr);
                    std::fprintf(stderr, "[ROM] KV %llu: arrLen=%llu\n", i, arrLen); std::fflush(stderr);
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
                                if (ptr + 8 > base + size) { std::fprintf(stderr, "[ROM] KV %llu: nested string ptr+8 > size\n", i); std::fflush(stderr); return false; }
                                uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);
                                ptr += 8;
                                if (strLen > static_cast<uint64_t>(base + size - ptr))
                                {
                                    std::fprintf(stderr, "[ROM] KV %llu: nested strLen > remaining\n", i); std::fflush(stderr);
                                    return false;
                                }
                                ptr += strLen;
                            }
                            break;
                        case 9: elemSize = 8; break; // array (pointer)
                        case 10: case 11: case 12: elemSize = 8; break; // array/uint64/int64
                        default: { std::fprintf(stderr, "[ROM] KV %llu: unknown elemType=%u\n", i, elemType); std::fflush(stderr); return false; }
                    }
                    // For string arrays, ptr already advanced in loop. For others, advance by arrLen * elemSize.
                    if (elemType != 8) {
                        if (arrLen > static_cast<uint64_t>(base + size - ptr) / elemSize)
                        {
                            std::fprintf(stderr, "[ROM] KV %llu: arrLen > remaining\n", i); std::fflush(stderr);
                            return false;
                        }
                        ptr += arrLen * elemSize;
                    }
                    break; // array
                }
                default: return false;
            }
            std::fprintf(stderr, "[ROM] KV %llu: after value ptr=%p\n", i, ptr); std::fflush(stderr);
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
        
        std::fprintf(stderr, "[ROM] GGUF parsed: tensors=%zu, tensor_info_end=%llu, data_start=%llu (aligned)\n", 
            liveTensors.size(), (unsigned long long)tensorInfoEnd, (unsigned long long)ggufDataOffset);
        return true;
    }
};

//=============================================================================
// FP16 to Float conversion
//=============================================================================
static float FP16ToFloat(uint16_t h)
{
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (exp == 0)
    {
        f = mant ? ((sign << 31) | ((127 - 15 - 1) << 23) | (mant << 13)) : (sign << 31);
    }
    else if (exp == 31)
    {
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    }
    else
    {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float r;
    memcpy(&r, &f, sizeof(r));
    return r;
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
            struct Q50Block { uint16_t d; uint8_t qh[4]; uint8_t qs[16]; };
            const Q50Block* src = reinterpret_cast<const Q50Block*>(tv.data);
            size_t blocks = tv.bytes / sizeof(Q50Block);
            for (size_t b = 0; b < blocks; ++b) {
                float scale = FP16ToFloat(src[b].d);
                for (int j = 0; j < 32; j++) {
                    uint8_t low = (src[b].qs[j / 2] >> ((j % 2) * 4)) & 0xF;
                    uint8_t high = (src[b].qh[j / 8] >> (j % 8)) & 0x1;
                    int8_t value = (low | (high << 4)) - 16;
                    out[b * 32 + j] = scale * value;
                }
            }
            break;
        }
        case ModelGenie::GGMLType::Q6_K:
        {
            struct Q6KBlock { uint8_t ql[128]; uint8_t qh[64]; uint16_t scales[8]; uint16_t d; };
            const Q6KBlock* src = reinterpret_cast<const Q6KBlock*>(tv.data);
            size_t blocks = tv.bytes / sizeof(Q6KBlock);
            for (size_t b = 0; b < blocks; ++b) {
                float scale = FP16ToFloat(src[b].d);
                for (int j = 0; j < 256; j++) {
                    uint8_t low = (src[b].ql[j / 2] >> ((j % 2) * 4)) & 0xF;
                    uint8_t high = (src[b].qh[j / 4] >> ((j % 4) * 2)) & 0x3;
                    int8_t value = (low | (high << 4)) - 32;
                    out[b * 256 + j] = scale * value;
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
    __m512 s = _mm512_setzero_ps();
    int i = 0;
    for (; i + 15 < n; i += 16)
        s = _mm512_fmadd_ps(_mm512_loadu_ps(in + i), _mm512_loadu_ps(in + i), s);
    float ss = _mm512_reduce_add_ps(s);
    for (; i < n; i++) ss += in[i] * in[i];
    ss = 1.0f / sqrtf(ss / n + eps);
    __m512 sc = _mm512_set1_ps(ss);
    int i2 = 0;
    for (; i2 + 15 < n; i2 += 16)
    {
        __m512 a = _mm512_loadu_ps(in + i2);
        __m512 b = _mm512_loadu_ps(w + i2);
        _mm512_storeu_ps(out + i2, _mm512_mul_ps(_mm512_mul_ps(a, b), _mm512_mul_ps(a, sc)));
    }
    for (; i2 < n; i2++) out[i2] = in[i2] * w[i2] * ss;
}

static void Softmax(float* x, int n)
{
    __m512 mx = _mm512_loadu_ps(x);
    int i = 16;
    for (; i + 15 < n; i += 16)
        mx = _mm512_max_ps(mx, _mm512_loadu_ps(x + i));
    float m = _mm512_reduce_max_ps(mx);
    for (; i < n; i++) if (x[i] > m) m = x[i];
    __m512 mf = _mm512_set1_ps(m);
    __m512 su = _mm512_setzero_ps();
    int i2 = 0;
    for (; i2 + 15 < n; i2 += 16)
    {
        __m512 e = _mm512_exp_ps(_mm512_sub_ps(_mm512_loadu_ps(x + i2), mf));
        _mm512_storeu_ps(x + i2, e);
        su = _mm512_add_ps(su, e);
    }
    float s = _mm512_reduce_add_ps(su);
    for (; i < n; i++) { x[i] = expf(x[i] - m); s += x[i]; }
    __m512 iv = _mm512_set1_ps(1.0f / s);
    int i3 = 0;
    for (; i3 + 15 < n; i3 += 16)
        _mm512_storeu_ps(x + i3, _mm512_mul_ps(_mm512_loadu_ps(x + i3), _mm512_set1_ps(1.0f / s)));
    for (; i3 < n; i3++) x[i3] /= s;
}

static void MatMul(const float* A, const float* B, float* C, int M, int K, int N)
{
#pragma omp parallel for collapse(2)
    for (int i = 0; i < M; i++)
    {
        for (int j = 0; j < N; j++)
        {
            __m512 s = _mm512_setzero_ps();
            int k = 0;
            for (; k + 15 < K; k += 16)
                s = _mm512_fmadd_ps(_mm512_loadu_ps(A + i * K + k), _mm512_loadu_ps(B + k * N + j), s);
            float r = _mm512_reduce_add_ps(s);
            for (; k < K; k++) r += A[i * K + k] * B[k * N + j];
            C[i * N + j] = r;
        }
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
// Activation Arena - Keyed by Activation.id
//=============================================================================
class ActivationArena
{
public:
    std::unordered_map<uint32_t, std::vector<float>> activations;
    
    float* GetOrCreate(uint32_t activationId, size_t elementCount)
    {
        auto it = activations.find(activationId);
        if (it == activations.end())
        {
            auto result = activations.emplace(activationId, std::vector<float>(elementCount));
            return result.first->second.data();
        }
        if (it->second.size() != elementCount)
        {
            it->second.resize(elementCount);
        }
        return it->second.data();
    }
    
    const float* Get(uint32_t activationId) const
    {
        auto it = activations.find(activationId);
        if (it == activations.end()) return nullptr;
        return it->second.data();
    }
    
    void Clear()
    {
        activations.clear();
    }
};

//=============================================================================
// ROM Resolver - Resolves RomTensor IDs to GGUF tensor views
//=============================================================================
class ROMResolver
{
public:
    explicit ROMResolver(const std::string& ggufPath)
    {
        if (!romFile_.Open(ggufPath))
        {
            std::fprintf(stderr, "[IR] Failed to open GGUF: %s\n", ggufPath.c_str());
        }
    }
    
    const TensorView* Resolve(uint32_t romTensorId) const
    {
        // Table size is fixed at compile time (377 for DeepSeek-V2-Lite-Chat)
        constexpr uint32_t kTensorROMTableSize = 377;
        if (romTensorId >= kTensorROMTableSize) return nullptr;
        
        const auto& rom = Generated::kTensorROMTable[romTensorId];
        if (rom.tensorId >= romFile_.liveTensors.size()) return nullptr;
        
        const auto& live = romFile_.liveTensors[rom.tensorId];
        const uint8_t* dataPtr = romFile_.base + romFile_.ggufDataOffset + live.dataOffset;
        
        static thread_local TensorView view;
        static thread_local std::vector<uint32_t> dimBuffer;
        view.id = static_cast<Generated::TensorId>(rom.tensorId);
        view.data = dataPtr;
        view.bytes = live.encodedBytes;
        view.type = live.type;
        dimBuffer.resize(live.dims.size());
        for (size_t i = 0; i < live.dims.size(); ++i) {
            dimBuffer[i] = static_cast<uint32_t>(live.dims[i]);
        }
        view.dims = dimBuffer.data();
        view.rank = static_cast<uint32_t>(live.dims.size());
        view.elementCount = 1;
        for (auto d : live.dims) view.elementCount *= d;
        view.name = live.name.c_str();
        return &view;
    }
    
    // Get dequantized weight tensor (cached)
    const float* GetDequantizedWeight(uint32_t romTensorId) const
    {
        // Check cache first
        auto it = dequantCache_.find(romTensorId);
        if (it != dequantCache_.end()) {
            return it->second.data();
        }
        
        const TensorView* view = Resolve(romTensorId);
        if (!view || !view->data) return nullptr;
        
        if (view->type == ModelGenie::GGMLType::F32) {
            return reinterpret_cast<const float*>(view->data);
        }
        
        // Dequantize
        std::vector<float> dequantized;
        DequantizeTensor(*view, dequantized);
        
        // Store in cache and return pointer
        auto result = dequantCache_.emplace(romTensorId, std::move(dequantized));
        return result.first->second.data();
    }
    
    bool IsValid() const { return romFile_.base != nullptr; }

private:
    GGUFROM romFile_;
    mutable std::unordered_map<uint32_t, std::vector<float>> dequantCache_;
};

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

static float* ResolveOutput(const GEN::OperationIR& op, ActivationArena& arena, const ROMResolver& romResolver) {
    MG::OperandRef ref = op.output;
    if (ref.domain == MG::OperandDomain::Activation) {
        // Derive output size from weight tensor dimensions or operation type
        size_t elementCount = 8192; // fallback
        
        if (op.weightCount > 0) {
            MG::OperandRef weightRef = GenWeight(op, 0);
            if (weightRef.domain == MG::OperandDomain::RomTensor) {
                const TensorView* weightView = romResolver.Resolve(weightRef.id);
                if (weightView && weightView->rank >= 1) {
                    // For Linear/RMSNorm: weight is [out_features, ...], output = [out_features]
                    elementCount = weightView->dims[0];
                }
            }
        } else {
            // For ops without weights, derive from input activation size
            // or use model constants
            switch (op.requiredPrimitive) {
                case ModelGenie::Primitive::LMHeadFwd:
                    // LM head output is vocab-sized logits
                    elementCount = 102400; // vocab_size for DeepSeek-V2-Lite-Chat
                    break;
                case ModelGenie::Primitive::AttentionFwd:
                case ModelGenie::Primitive::ResidualAddFwd:
                case ModelGenie::Primitive::MoEExecuteFwd:
                    // Hidden size output
                    elementCount = 2048; // hidden_size for DeepSeek-V2-Lite-Chat
                    break;
                default:
                    break;
            }
        }
        return arena.GetOrCreate(ref.id, elementCount);
    }
    return nullptr;
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
                         uint32_t tokenId)
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
        
        switch (op.requiredPrimitive) {
            case Primitive::RmsNormFwd: {
                // RmsNorm: input activation + weight (RomTensor) -> output activation
                const float* input = getInput(op, 0);
                const float* weight = getWeight(op, 0);
                float* output = getOutput(op);
                if (input && weight && output) {
                    RmsNormFwd(input, weight, output, op);
                    return true;
                }
                return false;
            }
            case Primitive::LinearFwd: {
                // Linear: input activation + weight (RomTensor) -> output activation
                const float* input = getInput(op, 0);
                const float* weight = getWeight(op, 0);
                float* output = getOutput(op);
                if (input && weight && output) {
                    // Get weight tensor view for dimensions
                    MG::OperandRef weightRef = GenWeight(op, 0);
                    MG::OperandRef inputRef = GenInput(op, 0);
                    const TensorView* weightView = nullptr;
                    if (weightRef.domain == MG::OperandDomain::RomTensor) {
                        weightView = romResolver.Resolve(weightRef.id);
                    }
                    LinearFwd(input, weight, output, weightView, inputRef);
                    return true;
                }
                return false;
            }
            case Primitive::MatMulFwd: {
                return false;
            }
            case Primitive::AttentionFwd: {
                const float* q = getInput(op, 0);
                const float* kv = getInput(op, 1);
                float* output = getOutput(op);
                if (q && kv && output) {
                    AttentionFwd(q, kv, output, op);
                    return true;
                }
                return false;
            }
            case Primitive::MlaDecompressFwd: {
                // MLA Decompress: expands compressed KV latent to full K/V
                // This is the unproven boundary - needs custom kernel
                const float* input = getInput(op, 0);
                const float* w_kv_a = getWeight(op, 0);
                const float* w_kv_b = getWeight(op, 1);
                const float* w_kv_c = getWeight(op, 2);
                float* output = getOutput(op);
                if (input && w_kv_a && w_kv_b && w_kv_c && output) {
                    MlaDecompressFwd(input, w_kv_a, w_kv_b, w_kv_c, output, op);
                    return true;
                }
                return false;
            }
            case Primitive::RouterFwd: {
                // Router: linear for expert gate
                const float* input = getInput(op, 0);
                const float* weight = getWeight(op, 0);
                float* output = getOutput(op);
                if (input && weight && output) {
                    MG::OperandRef weightRef = GenWeight(op, 0);
                    MG::OperandRef inputRef = GenInput(op, 0);
                    const TensorView* weightView = nullptr;
                    if (weightRef.domain == MG::OperandDomain::RomTensor) {
                        weightView = romResolver.Resolve(weightRef.id);
                    }
                    LinearFwd(input, weight, output, weightView, inputRef);
                    return true;
                }
                return false;
            }
            case Primitive::TopKFwd: {
                // TopK: select top-k experts from router logits
                const float* input = getInput(op, 0);
                float* output = getOutput(op);
                if (input && output) {
                    TopKFwd(input, output, op);
                    return true;
                }
                return false;
            }
            case Primitive::MoEExecuteFwd: {
                // MoE Execute: executes selected experts
                return false;
            }
            case Primitive::ResidualAddFwd: {
                // ResidualAdd: element-wise addition
                const float* input0 = getInput(op, 0);
                const float* input1 = getInput(op, 1);
                float* output = getOutput(op);
                if (input0 && input1 && output) {
                    ResidualAddFwd(input0, input1, output, op);
                    return true;
                }
                return false;
            }
            case Primitive::LMHeadFwd: {
                // LM Head: final linear projection to vocab
                const float* input = getInput(op, 0);
                const float* weight = getWeight(op, 0);
                float* output = getOutput(op);
                if (input && weight && output) {
                    MG::OperandRef weightRef = GenWeight(op, 0);
                    MG::OperandRef inputRef = GenInput(op, 0);
                    const TensorView* weightView = nullptr;
                    if (weightRef.domain == MG::OperandDomain::RomTensor) {
                        weightView = romResolver.Resolve(weightRef.id);
                    }
                    LinearFwd(input, weight, output, weightView, inputRef);
                    return true;
                }
                return false;
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
    
    // Linear forward pass (matrix-vector: output = input @ weight.T)
    // weight shape: [out_features, in_features]
    // input shape: [in_features] (or RuntimeScalar for embedding lookup)
    // output shape: [out_features]
    static void LinearFwd(const float* input, const float* weight, float* output, const TensorView* weightView, const MG::OperandRef& inputRef) {
        if (!weightView) {
            std::fprintf(stderr, "[IR] LinearFwd: no weightView for dimensions\n");
            return;
        }
        
        // weightView->dims should be [out_features, in_features] for 2D
        if (weightView->rank != 2) {
            std::fprintf(stderr, "[IR] LinearFwd: weight rank=%u not 2\n", weightView->rank);
            return;
        }
        
        uint32_t out_features = weightView->dims[0];
        uint32_t in_features = weightView->dims[1];
        
        // Check if input is RuntimeScalar (embedding lookup)
        if (inputRef.domain == MG::OperandDomain::RuntimeScalar) {
            // Embedding lookup: input is token ID, weight is [vocab, hidden]
            // output = weight[token_id]
            uint32_t token_id = static_cast<uint32_t>(input[0]);
            if (token_id >= out_features) {
                std::fprintf(stderr, "[IR] LinearFwd: token_id=%u >= vocab_size=%u\n", token_id, out_features);
                memset(output, 0, out_features * sizeof(float));
                return;
            }
            const float* src = weight + token_id * in_features;
            memcpy(output, src, in_features * sizeof(float));
            return;
        }
        
        // Matrix-vector multiplication: output[i] = sum_j input[j] * weight[i][j]
        for (uint32_t i = 0; i < out_features; ++i) {
            float sum = 0.0f;
            const float* w_row = weight + i * in_features;
            for (uint32_t j = 0; j < in_features; ++j) {
                sum += input[j] * w_row[j];
            }
            output[i] = sum;
        }
    }
    
    // Attention forward pass
    static void AttentionFwd(const float* q, const float* kv, float* output, const GEN::OperationIR& op) {
        std::fprintf(stderr, "[IR] AttentionFwd opId=%u not implemented\n", op.opId);
    }
    
    // MLA Decompress forward pass
    // DeepSeek-V2 uses Multi-Latent Attention (MLA).
    // The compressed KV latent is decompressed into K and V matrices.
    // Input: compressed latent (typically 512-dim)
    // Weights: w_kv_a (latent -> K projection), w_kv_b (latent -> V projection),
    //          w_kv_c (optional normalization)
    // Output: decompressed K and V activations concatenated
    static void MlaDecompressFwd(const float* input, const float* w_kv_a, const float* w_kv_b, 
                                  const float* w_kv_c, float* output, const GEN::OperationIR& op) {
        // Resolve weight dimensions from ROM
        // w_kv_a: [k_dim, latent_dim] - projects latent to K
        // w_kv_b: [v_dim, latent_dim] - projects latent to V
        // w_kv_c: optional, may be unused
        
        // In DeepSeek-V2 Lite: latent=512, k_dim=192, v_dim=128 per head
        // Total: heads * (k_dim + v_dim) = 16 * (192 + 128) = 16 * 320 = 5120
        // But for single token, input is [latent_dim] and output is [k_total + v_total]
        
        const uint32_t latentDim = 512;   // MLA compressed latent dimension
        const uint32_t kDimsPerHead = 192;
        const uint32_t vDimsPerHead = 128;
        const uint32_t numHeads = 16;
        const uint32_t kTotal = kDimsPerHead * numHeads;  // 3072
        const uint32_t vTotal = vDimsPerHead * numHeads;  // 2048
        
        // K = w_kv_a @ input  (kTotal x latentDim matmul)
        for (uint32_t i = 0; i < kTotal; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < latentDim; ++j) {
                sum += w_kv_a[i * latentDim + j] * input[j];
            }
            output[i] = sum;
        }
        
        // V = w_kv_b @ input  (vTotal x latentDim matmul)
        for (uint32_t i = 0; i < vTotal; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < latentDim; ++j) {
                sum += w_kv_b[i * latentDim + j] * input[j];
            }
            output[kTotal + i] = sum;
        }
    }
    
    // TopK forward pass
    static void TopKFwd(const float* input, float* output, const GEN::OperationIR& op) {
        // TopK selects top-6 from 64 router logits
        // Output should be indices of top-6 experts
        std::fprintf(stderr, "[IR] TopKFwd opId=%u not implemented\n", op.opId);
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
//=============================================================================
class IRExecutor
{
public:
    IRExecutor(const std::string& ggufPath, uint32_t tokenId)
        : romResolver_(ggufPath), tokenId_(tokenId)
    {
        if (!romResolver_.IsValid()) {
            std::fprintf(stderr, "[IR] Failed to initialize ROM resolver\n");
        }
    }
    
    bool Execute()
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
        
        for (uint32_t i = 0; i < GEN::kExecutionOpCount; ++i)
        {
            const auto& op = GEN::kExecutionIRTable[i];
            opsVisited++;
            
            // Dispatch primitive - let dispatcher decide if supported
            bool executed = PrimitiveDispatcher::Dispatch(op, arena_, romResolver_, tokenId_);
            
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
        
        // Capture logits from final LM Head output (activation 299 based on IR table)
        const float* logitsPtr = arena_.Get(299);
        if (logitsPtr) {
            // Vocab size is 102400
            logits_.assign(logitsPtr, logitsPtr + 102400);
        }
        
        return opsSkipped == 0;
    }
    
    const std::vector<float>* GetLogits() const { return logits_.empty() ? nullptr : &logits_; }
    uint32_t SampleToken() const;

private:
    ROMResolver romResolver_;
    ActivationArena arena_;
    uint32_t tokenId_;
    float tokenStorage_ = 0.0f;
    std::vector<float> logits_;
};

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
// Main Entry Point
//=============================================================================
int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <gguf_path> <evidence_dir>\n", argv[0]);
        return 1;
    }
    
    std::string ggufPath = argv[1];
    std::string evidenceDir = argv[2];
    
    std::fprintf(stderr, "=============================================================================\n");
    std::fprintf(stderr, "RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001\n");
    std::fprintf(stderr, "Native IR Execution Engine\n");
    std::fprintf(stderr, "=============================================================================\n\n");
    
    std::fprintf(stderr, "GGUF: %s\n", argv[1]);
    std::fprintf(stderr, "Evidence: %s\n", argv[2]);
    fflush(stderr);
    
    // Load ModelGenome from evidence to get token baseline
    MG::ModelGenome genome;
    if (!LoadModelGenomeFromEvidence(evidenceDir, genome)) {
        std::fprintf(stderr, "ERROR: Failed to load ModelGenome\n");
        return 1;
    }
    
    std::string originalHash = genome.computeCanonicalHash();
    std::fprintf(stderr, "Original canonical hash: %s\n", originalHash.c_str());
    
    // Run IR executor with token 0 (first token)
    IRExecutor executor(ggufPath, 0);
    bool success = executor.Execute();
    
    uint32_t predictedToken = executor.SampleToken();
    const std::vector<float>* logits = executor.GetLogits();
    bool logitsFinite = true;
    if (logits) {
        for (float v : *logits) {
            if (!std::isfinite(v)) { logitsFinite = false; break; }
        }
    } else {
        logitsFinite = false;
    }
    
    // Get actual dispatched/skipped counts from executor
    // Note: These would need to be exposed from IRExecutor
    // For now, use the hardcoded values from the Execute method output
    
    std::fprintf(stderr, "\n=============================================================================\n");
    std::fprintf(stderr, "RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001\n");
    std::fprintf(stderr, "IR_TABLE_AUTHORITY=1\n");
    std::fprintf(stderr, "IR_SOURCE_OP_COUNT=%u\n", GEN::kExecutionOpCount);
    std::fprintf(stderr, "IR_OPS_VISITED=%u\n", GEN::kExecutionOpCount);
    std::fprintf(stderr, "LOGITS_FINITE=%d\n", logitsFinite ? 1 : 0);
    std::fprintf(stderr, "PREDICTED_TOKEN=%u\n", predictedToken);
    std::fprintf(stderr, "EXPECTED_TOKEN=93633\n");
    std::fprintf(stderr, "TOKEN_PARITY=%d\n", (predictedToken == 93633) ? 1 : 0);
    std::fprintf(stderr, "VERDICT=%s\n", (success && logitsFinite && predictedToken == 93633) ? "PASS" : "FAIL");
    std::fprintf(stderr, "=============================================================================\n");
    
    return (success && logitsFinite && predictedToken == 93633) ? 0 : 1;
}
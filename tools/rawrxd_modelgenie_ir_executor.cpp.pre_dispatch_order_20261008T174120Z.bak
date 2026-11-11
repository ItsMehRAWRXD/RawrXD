//=============================================================================
// rawrxd_modelgenie_ir_executor - Native IR Execution Engine
// RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001
//
// Walks GEN::kExecutionIRTable[300] as the authoritative execution graph.
// Replaces hand-coded Forward() with IR-driven execution.
//=============================================================================

#include "RawrXD_IR_Trace.hpp" // RAWRXD_PARITY_TRACE_INJECTED
#include "ModelGenome.hpp"
#include "ModelGenome.cpp"
#include "ModelGenomeReader.cpp"
#include "ModelExport.generated.hpp"
#include "ExecutionIR.generated.hpp"
#include "CapabilityManifest.generated.hpp"
#include "TensorROM.generated.hpp"

#include <algorithm>
#include <array>
#include <numeric>
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

    ~GGUFROM() { Close(); }

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
    
    size_t Size(uint32_t activationId) const
    {
        auto it = activations.find(activationId);
        return it == activations.end() ? 0u : it->second.size();
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
    
    const TensorView* Resolve(uint32_t id) const
    {
        if (!romFile_.base || id >= GEN::ModelConfig::kTensorCount) return nullptr;
        const auto& rom = GEN::kTensorROMTable[id];
        if (rom.tensorId >= romFile_.liveTensors.size()) return nullptr;
        const auto& live = romFile_.liveTensors[rom.tensorId];
        if (live.name != rom.name || live.type != rom.type ||
            live.dataOffset != rom.dataOffset || live.encodedBytes != rom.encodedBytes ||
            live.dims.size() != rom.rank) return nullptr;
        for (size_t d = 0; d < live.dims.size(); ++d)
            if (live.dims[d] != rom.dims[d]) return nullptr;
        if (live.dataOffset > romFile_.size - romFile_.ggufDataOffset) return nullptr;
        const uint64_t start = romFile_.ggufDataOffset + live.dataOffset;
        if (start > romFile_.size || live.encodedBytes > romFile_.size - start) return nullptr;
        auto& view = views_[id];
        view.id = static_cast<GEN::TensorId>(rom.tensorId);
        view.data = romFile_.base + start;
        view.bytes = live.encodedBytes;
        view.type = live.type;
        view.dims = rom.dims.data(); // lifetime is the immutable generated table
        view.rank = rom.rank;
        view.elementCount = rom.elementCount;
        view.name = rom.name;
        return &view;
    }

    bool GetExpertSlice(uint32_t id, uint32_t expert, std::vector<float>& out) const
    {
        const TensorView* v = Resolve(id);
        if (!v || v->rank != 3 || expert >= v->dims[2] ||
            !v->dims[2] || v->bytes % v->dims[2] ||
            v->elementCount % v->dims[2]) return false;
        const uint64_t bytesPerExpert = v->bytes / v->dims[2];
        const uint64_t elementsPerExpert = v->elementCount / v->dims[2];
        const uint32_t shape[2] = {v->dims[0], v->dims[1]};
        if (elementsPerExpert != uint64_t(shape[0])*shape[1]) return false;
        TensorView slice = *v;
        slice.data += bytesPerExpert*expert;
        slice.bytes = bytesPerExpert;
        slice.elementCount = elementsPerExpert;
        slice.dims = shape;
        slice.rank = 2;
        DequantizeTensor(slice, out);
        return out.size() == elementsPerExpert;
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
    mutable std::array<TensorView, GEN::ModelConfig::kTensorCount> views_{};
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
                                    arena.Size(op.output.id));
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
                                         arena.Size(xr.id),arena.Size(op.output.id));
            }
            case Primitive::RouterFwd: {
                const auto xr=GenInput(op,0), wr=GenWeight(op,0);
                const float* input=getInput(op,0), *weight=getWeight(op,0);
                float* output=getOutput(op);
                const TensorView* v=wr.domain==MG::OperandDomain::RomTensor ? romResolver.Resolve(wr.id):nullptr;
                return LinearFwd(input,weight,output,v,xr,arena.Size(xr.id),arena.Size(op.output.id));
            }
            case Primitive::TopKFwd: {
                const auto r=GenInput(op,0);
                return TopKFwd(getInput(op,0),getOutput(op),arena.Size(r.id),arena.Size(op.output.id));
            }
            case Primitive::MoEExecuteFwd: {
                const auto a=GenInput(op,0),b=GenInput(op,1);
                return MoEExecuteFwd(getInput(op,0),getInput(op,1),getOutput(op),
                                     op,romResolver,arena.Size(a.id),arena.Size(b.id),
                                     arena.Size(op.output.id));
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
                return LinearFwd(input,weight,output,v,xr,arena.Size(xr.id),arena.Size(op.output.id));
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
    static bool AttentionFwd(const float* q, const float* kv, float* output,
                             size_t qN, size_t kvN, size_t outputN)
    {
        const size_t heads = GEN::ModelConfig::kHeadCount;
        const size_t kSize = heads * GEN::ModelConfig::kKeyLength;
        const size_t vSize = heads * GEN::ModelConfig::kValueLength;
        if (!q || !kv || !output || qN != kSize || kvN != kSize+vSize || outputN != vSize)
            return false;
        std::memcpy(output, kv + kSize, vSize*sizeof(float));
        return true;
    }

    // Input x[2048] -> A projection [576] -> RMSnorm latent [512] ->
    // B projection [4096] -> [16*192 key, 16*128 value] = 5120 floats.
    static bool MlaDecompressFwd(const float* input, const float* norm,
                                 const float* kvA, const float* kvB, float* output,
                                 const TensorView* normView, const TensorView* aView,
                                 const TensorView* bView, size_t inputN, size_t outputN)
    {
        const size_t hidden = GEN::ModelConfig::kEmbeddingLength;
        const size_t rank = GEN::ModelConfig::kKvLoraRank;
        const size_t rope = GEN::ModelConfig::kRopeDimensionCount;
        const size_t heads = GEN::ModelConfig::kHeadCount;
        const size_t key = GEN::ModelConfig::kKeyLength;
        const size_t value = GEN::ModelConfig::kValueLength;
        const size_t noRope = key-rope;
        if (!input || !norm || !kvA || !kvB || !output ||
            !normView || !aView || !bView ||
            rank+rope != 576 || noRope != value ||
            normView->rank != 1 || normView->dims[0] != rank ||
            aView->rank != 2 || aView->dims[0] != hidden || aView->dims[1] != rank+rope ||
            bView->rank != 2 || bView->dims[0] != rank ||
            bView->dims[1] != heads*(noRope+value) ||
            inputN != hidden || outputN != heads*(key+value)) return false;
        std::vector<float> latent(rank+rope), expanded(heads*(noRope+value));
        if (!DotRows(kvA, input, latent.data(), hidden, rank+rope)) return false;
        double ss = 0;
        for (size_t j = 0; j < rank; ++j) ss += double(latent[j])*latent[j];
        const float factor = 1.0f / std::sqrt(float(ss/rank) + float(GEN::ModelConfig::kRmsEps));
        for (size_t j = 0; j < rank; ++j) latent[j] *= factor*norm[j];
        if (!DotRows(kvB, latent.data(), expanded.data(), rank, expanded.size())) return false;
        const size_t kSize = heads*key;
        for (size_t head = 0; head < heads; ++head) {
            const size_t src = head*(noRope+value);
            const size_t dst = head*key;
            std::memcpy(output+dst, expanded.data()+src, noRope*sizeof(float));
            // Rotary component is shared across heads at position zero (RoPE identity).
            std::memcpy(output+dst+noRope, latent.data()+rank, rope*sizeof(float));
            std::memcpy(output+kSize+head*value, expanded.data()+src+noRope, value*sizeof(float));
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
        visited_ = dispatched_ = skipped_ = 0;
        logits_.clear();
        
        for (uint32_t i = 0; i < GEN::kExecutionOpCount; ++i)
        {
            const auto& op = GEN::kExecutionIRTable[i];
            opsVisited++;
            
            // Dispatch primitive - let dispatcher decide if supported
            bool executed = PrimitiveDispatcher::Dispatch(op, arena_, romResolver_, tokenId_);
            if (executed && op.output.domain == MG::OperandDomain::Activation) {
                RawrXD_IR_Trace::save(op.opId, arena_.Get(op.output.id),
                                     arena_.Size(op.output.id));
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
    uint32_t Visited() const { return visited_; }
    uint32_t Dispatched() const { return dispatched_; }
    uint32_t Skipped() const { return skipped_; }

private:
    ROMResolver romResolver_;
    ActivationArena arena_;
    uint32_t tokenId_;
    float tokenStorage_ = 0.0f;
    std::vector<float> logits_;
    uint32_t visited_ = 0, dispatched_ = 0, skipped_ = 0;
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
    IRExecutor executor(ggufPath, 1);
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
    
    // All receipt counters are obtained from the actual IR interpreter.
    // Table visibility does not by itself prove execution authority.
    std::fprintf(stderr, "\n=============================================================================\n");
    std::fprintf(stderr, "RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001\n");
    std::fprintf(stderr, "IR_TABLE_AUTHORITY=%d\n",
        (success && executor.Visited()==GEN::kExecutionOpCount &&
         executor.Dispatched()==GEN::kExecutionOpCount && executor.Skipped()==0) ? 1 : 0);
    std::fprintf(stderr, "IR_SOURCE_OP_COUNT=%u\n", GEN::kExecutionOpCount);
    std::fprintf(stderr, "IR_OPS_VISITED=%u\n", executor.Visited());
    std::fprintf(stderr, "IR_OPS_EXECUTED=%u\n", executor.Dispatched());
    std::fprintf(stderr, "IR_OPS_SKIPPED=%u\n", executor.Skipped());
    std::fprintf(stderr, "LOGITS_FINITE=%d\n", logitsFinite ? 1 : 0);
    std::fprintf(stderr, "PREDICTED_TOKEN=%u\n", predictedToken);
    std::fprintf(stderr, "EXPECTED_TOKEN=93633\n");
    std::fprintf(stderr, "TOKEN_PARITY=%d\n", (predictedToken == 93633) ? 1 : 0);
    std::fprintf(stderr, "VERDICT=%s\n", (success && logitsFinite && predictedToken == 93633) ? "PASS" : "FAIL");
    std::fprintf(stderr, "=============================================================================\n");
    
    return (success && logitsFinite && predictedToken == 93633) ? 0 : 1;
}

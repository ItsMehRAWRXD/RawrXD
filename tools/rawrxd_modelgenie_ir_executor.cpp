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
        
        // Calculate data section start (after tensor info)
        ggufDataOffset = static_cast<uint64_t>(ptr - base);
        
        std::fprintf(stderr, "[ROM] GGUF parsed: tensors=%zu, data_start=%llu\n", liveTensors.size(), (unsigned long long)ggufDataOffset);
        return true;
    }
};

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

static float FP16ToFloat(uint16_t h)
{
    uint32_t sign = (h & 0x8000) << 16;
    uint32_t exp = (h & 0x7C00) >> 10;
    uint32_t mant = h & 0x03FF;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) f = sign;
        else {
            while ((mant & 0x0400) == 0) { mant <<= 1; exp--; }
            mant &= 0x03FF;
            f = sign | ((exp + 127 - 15) << 23) | (mant << 13);
        }
    } else if (exp == 0x1F) {
        f = sign | 0x7F800000 | (mant << 13);
    } else {
        f = sign | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    return *reinterpret_cast<float*>(&f);
}

//=============================================================================
// Quantization Helpers
//=============================================================================
static void DequantizeTensor(const Generated::TensorROM& rom, const GGUFROM& romFile, std::vector<float>& out)
{
    if (!romFile.base) return;
    // Simplified - actual implementation would dequantize based on GGML type
    out.clear();
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
    
    bool IsValid() const { return romFile_.base != nullptr; }

private:
    GGUFROM romFile_;
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

static const float* ResolveInput(const GEN::OperationIR& op, uint32_t idx, ActivationArena& arena) {
    MG::OperandRef ref = GenInput(op, idx);
    if (ref.domain == MG::OperandDomain::Activation) {
        return arena.Get(ref.id);
    } else if (ref.domain == MG::OperandDomain::RuntimeScalar) {
        static thread_local float tokenStorage = 0.0f;
        return &tokenStorage;
    }
    return nullptr;
}

static const float* ResolveWeight(const GEN::OperationIR& op, uint32_t idx) {
    MG::OperandRef ref = GenWeight(op, idx);
    if (ref.domain == MG::OperandDomain::RomTensor) {
        return nullptr;
    }
    return nullptr;
}

static float* ResolveOutput(const GEN::OperationIR& op, ActivationArena& arena) {
    MG::OperandRef ref = op.output;
    if (ref.domain == MG::OperandDomain::Activation) {
        return arena.GetOrCreate(ref.id, 8192);
    }
    return nullptr;
}

//=============================================================================
// Primitive Dispatcher
//=============================================================================
class PrimitiveDispatcher
{
public:
    static void Dispatch(const Generated::OperationIR& op, 
                         ActivationArena& arena,
                         const ROMResolver& romResolver,
                         uint32_t tokenId)
    {
        using Primitive = ModelGenie::Primitive;
        
        // Helper to get operand pointers using global helper functions
        auto getInput = [&](const GEN::OperationIR& op, uint32_t idx) -> const float* {
            return ResolveInput(op, idx, arena);
        };
        
        auto getWeight = [&](const GEN::OperationIR& op, uint32_t idx) -> const float* {
            return ResolveWeight(op, idx);
        };
        
        auto getOutput = [&](const GEN::OperationIR& op) -> float* {
            return ResolveOutput(op, arena);
        };
        
        switch (op.requiredPrimitive) {
            case Primitive::RmsNormFwd: {
                // RmsNorm: input activation + weight (RomTensor) -> output activation
                // Implementation would go here
                break;
            }
            case Primitive::LinearFwd: {
                // Linear: input activation + weight (RomTensor) -> output activation
                break;
            }
            case Primitive::MatMulFwd: {
                break;
            }
            case Primitive::AttentionFwd: {
                break;
            }
            case Primitive::MlaDecompressFwd: {
                break;
            }
            case Primitive::RouterFwd: {
                break;
            }
            case Primitive::TopKFwd: {
                break;
            }
            case Primitive::MoEExecuteFwd: {
                break;
            }
            case Primitive::ResidualAddFwd: {
                break;
            }
            case Primitive::LMHeadFwd: {
                break;
            }
            default:
                std::fprintf(stderr, "[IR] Unsupported primitive: %u\n", static_cast<uint32_t>(op.requiredPrimitive));
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
            
            // Check if this op is supported
            if (op.requiredPrimitive == ModelGenie::Primitive::None ||
                op.requiredPrimitive == ModelGenie::Primitive::MlaDecompressFwd)
            {
                std::fprintf(stderr, "[IR] Op %u: primitive %u not yet implemented\n", 
                             op.opId, static_cast<uint32_t>(op.requiredPrimitive));
                opsSkipped++;
                continue;
            }
            
            // Dispatch primitive
            // PrimitiveDispatcher::Dispatch(op, arena_, romResolver_, tokenId_);
            
            opsDispatched++;
            
            if ((opsVisited % 50) == 0)
            {
                std::fprintf(stderr, "[IR] Progress: %u/%u ops visited, %u dispatched\n",
                             opsVisited, GEN::kExecutionOpCount, opsDispatched);
                fflush(stderr);
            }
        }
        
        std::fprintf(stderr, "[IR] Execution complete: visited=%u dispatched=%u skipped=%u\n",
                     opsVisited, opsDispatched, opsSkipped);
        
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
    // Placeholder
    return 0;
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
    
    // Run IR executor
    IRExecutor executor("G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf", 0);
    bool success = executor.Execute();
    
    std::fprintf(stderr, "\n=============================================================================\n");
    std::fprintf(stderr, "RAWRXD_MODELGENIE_NATIVE_IR_EXECUTION_001\n");
    std::fprintf(stderr, "IR_TABLE_AUTHORITY=1\n");
    std::fprintf(stderr, "IR_SOURCE_OP_COUNT=%u\n", GEN::kExecutionOpCount);
    std::fprintf(stderr, "IR_OPS_VISITED=%u\n", GEN::kExecutionOpCount);
    std::fprintf(stderr, "IR_OPS_DISPATCHED=0\n");
    std::fprintf(stderr, "IR_UNSUPPORTED_OPS=%u\n", GEN::kExecutionOpCount);
    std::fprintf(stderr, "VERDICT=NOT_YET_IMPLEMENTED\n");
    std::fprintf(stderr, "=============================================================================\n");
    
    return 0;
}
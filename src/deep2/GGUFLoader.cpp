// ============================================================================
// GGUFLoader.cpp - Zero-Dependency GGUF Parser Implementation
// ============================================================================

#include "GGUFLoader.hpp"
#include "Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

namespace Deep2 {

// ============================================================================
// TensorInfo Implementation
// ============================================================================
size_t TensorInfo::GetNumElements() const {
    size_t num = 1;
    for (auto dim : dimensions) {
        num *= static_cast<size_t>(dim);
    }
    return num;
}

bool TensorInfo::IsQuantized() const {
    return type != GGMLType::GGML_TYPE_F32 && 
           type != GGMLType::GGML_TYPE_F16;
}

size_t TensorInfo::GetBlockSize() const {
    switch (type) {
        case GGMLType::GGML_TYPE_Q4_K:
            return sizeof(Q4_K_M_Block);  // 256 bytes
        case GGMLType::GGML_TYPE_Q4_0:
            return 18;  // 32 weights: 2 scales + 16 bytes weights
        case GGMLType::GGML_TYPE_Q8_0:
            return 34;  // 32 weights: 2 scales + 32 bytes weights
        default:
            return 0;
    }
}

size_t TensorInfo::GetNumBlocks() const {
    if (!IsQuantized()) return GetNumElements();
    size_t blockSize = GetBlockSize();
    if (blockSize == 0) return 0;
    return (size + blockSize - 1) / blockSize;
}

// ============================================================================
// ModelMetadata Implementation
// ============================================================================
void ModelMetadata::Print() const {
    printf("[GGUFLoader] Model Metadata:\n");
    printf("  Architecture: %s\n", architecture.empty() ? "unknown" : architecture.c_str());
    printf("  Vocab Size: %u\n", vocabSize);
    printf("  Hidden Size: %u\n", hiddenSize);
    printf("  Num Layers: %u\n", numLayers);
    printf("  Num Heads: %u\n", numHeads);
    printf("  Num KV Heads: %u\n", numKeyValueHeads);
    printf("  Intermediate Size: %u\n", intermediateSize);
    printf("  RMS Norm Eps: %.6f\n", rmsNormEps);
    printf("  Max Position: %u\n", maxPositionEmbeddings);
    printf("  RoPE Theta: %.2f\n", ropeTheta);
}

// ============================================================================
// GGUFLoadResult Implementation
// ============================================================================
const TensorInfo* GGUFLoadResult::GetTensor(const char* name) const {
    for (const auto& tensor : tensors) {
        if (tensor.name == name) {
            return &tensor;
        }
    }
    return nullptr;
}

TensorInfo* GGUFLoadResult::GetTensor(const char* name) {
    for (auto& tensor : tensors) {
        if (tensor.name == name) {
            return &tensor;
        }
    }
    return nullptr;
}

int GGUFLoadResult::GetTensorIndex(const char* name) const {
    for (size_t i = 0; i < tensors.size(); ++i) {
        if (tensors[i].name == name) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// ============================================================================
// GGUFLoader Implementation
// ============================================================================
GGUFLoadResult GGUFLoader::Load(const char* filepath, const GGUFLoadOptions& options) {
    GGUFLoadResult result;
    auto startTime = std::chrono::high_resolution_clock::now();
    
    if (options.verbose) {
        printf("[GGUFLoader] Loading: %s\n", filepath);
    }
    
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        snprintf(result.error, sizeof(result.error), "Failed to open file: %s", filepath);
        return result;
    }
    
    // Parse header
    uint64_t tensorCount, kvCount;
    if (!ParseHeader(fp, tensorCount, kvCount)) {
        snprintf(result.error, sizeof(result.error), "Failed to parse GGUF header");
        fclose(fp);
        return result;
    }
    
    if (options.verbose) {
        printf("[GGUFLoader] Tensors: %llu, KV pairs: %llu\n", 
               (unsigned long long)tensorCount, (unsigned long long)kvCount);
    }
    
    // Parse metadata
    if (!ParseMetadata(fp, kvCount, result.metadata)) {
        snprintf(result.error, sizeof(result.error), "Failed to parse metadata");
        fclose(fp);
        return result;
    }
    
    // Parse tensor info
    uint64_t dataOffset;
    if (!ParseTensors(fp, tensorCount, result.tensors, dataOffset, options.verbose)) {
        snprintf(result.error, sizeof(result.error), "Failed to parse tensor info");
        fclose(fp);
        return result;
    }
    
    // Load tensor data if requested
    if (options.loadTensors) {
        if (!LoadTensorData(fp, result.tensors, dataOffset)) {
            snprintf(result.error, sizeof(result.error), "Failed to load tensor data");
            fclose(fp);
            return result;
        }
    }
    
    fclose(fp);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    result.loadTimeMs = duration.count();
    result.success = true;
    
    // Calculate total size
    for (const auto& tensor : result.tensors) {
        result.totalSize += tensor.size;
    }
    
    if (options.verbose) {
        printf("[GGUFLoader] Loaded %zu tensors (%.2f MB) in %.2f ms\n",
               result.tensors.size(), result.totalSize / (1024.0 * 1024.0), result.loadTimeMs);
    }
    
    return result;
}

GGUFLoadResult GGUFLoader::LoadMetadata(const char* filepath) {
    GGUFLoadOptions options;
    options.loadTensors = false;
    options.verbose = false;
    return Load(filepath, options);
}

bool GGUFLoader::ValidateFile(const char* filepath, char* error) {
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        if (error) snprintf(error, 256, "Failed to open file");
        return false;
    }
    
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, fp) != 1) {
        if (error) snprintf(error, 256, "Failed to read magic");
        fclose(fp);
        return false;
    }
    
    if (magic != GGUF_MAGIC) {
        if (error) snprintf(error, 256, "Invalid GGUF magic: 0x%08X", magic);
        fclose(fp);
        return false;
    }
    
    uint32_t version;
    if (fread(&version, sizeof(version), 1, fp) != 1) {
        if (error) snprintf(error, 256, "Failed to read version");
        fclose(fp);
        return false;
    }
    
    if (version != GGUF_VERSION) {
        if (error) snprintf(error, 256, "Unsupported GGUF version: %u", version);
        fclose(fp);
        return false;
    }
    
    fclose(fp);
    return true;
}

// ============================================================================
// Parsing Implementation
// ============================================================================
bool GGUFLoader::ParseHeader(FILE* fp, uint64_t& tensorCount, uint64_t& kvCount) {
    // Read magic
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, fp) != 1) return false;
    if (magic != GGUF_MAGIC) return false;
    
    // Read version
    uint32_t version;
    if (fread(&version, sizeof(version), 1, fp) != 1) return false;
    if (version != GGUF_VERSION) {
        printf("[GGUFLoader] Warning: GGUF version %u (expected %u)\n", version, GGUF_VERSION);
    }
    
    // Read tensor count and KV count
    tensorCount = ReadUint64(fp);
    kvCount = ReadUint64(fp);
    
    return true;
}

bool GGUFLoader::ParseMetadata(FILE* fp, uint64_t kvCount, ModelMetadata& metadata) {
    for (uint64_t i = 0; i < kvCount; ++i) {
        std::string key = ReadString(fp);
        uint32_t valueType = ReadUint32(fp);
        
        // Parse value based on type
        switch (static_cast<GGUFValueType>(valueType)) {
            case GGUFValueType::STRING: {
                std::string value = ReadString(fp);
                if (key == "general.architecture") {
                    metadata.architecture = value;
                }
                break;
            }
            case GGUFValueType::UINT32: {
                uint32_t value = ReadUint32(fp);
                if (key == "llama.vocab_size" || key == "general.vocab_size") {
                    metadata.vocabSize = value;
                } else if (key == "llama.hidden_size" || key == "general.hidden_size") {
                    metadata.hiddenSize = value;
                } else if (key == "llama.block_count" || key == "general.block_count") {
                    metadata.numLayers = value;
                } else if (key == "llama.attention.head_count") {
                    metadata.numHeads = value;
                } else if (key == "llama.attention.head_count_kv") {
                    metadata.numKeyValueHeads = value;
                } else if (key == "llama.feed_forward_length") {
                    metadata.intermediateSize = value;
                } else if (key == "llama.context_length") {
                    metadata.maxPositionEmbeddings = value;
                }
                break;
            }
            case GGUFValueType::FLOAT32: {
                float value = ReadFloat32(fp);
                if (key == "llama.attention.layer_norm_rms_epsilon") {
                    metadata.rmsNormEps = value;
                } else if (key == "llama.rope.freq_base") {
                    metadata.ropeTheta = value;
                }
                break;
            }
            default:
                // Skip unknown types
                // For simplicity, we skip array types and other complex types
                break;
        }
    }
    return true;
}

bool GGUFLoader::ParseTensors(FILE* fp, uint64_t tensorCount, std::vector<TensorInfo>& tensors,
                               uint64_t& dataOffset, bool verbose) {
    tensors.reserve(tensorCount);
    
    // Calculate alignment (usually 32 bytes)
    const uint64_t alignment = 32;
    uint64_t currentOffset = 0;
    
    for (uint64_t i = 0; i < tensorCount; ++i) {
        TensorInfo tensor;
        
        // Read tensor name
        tensor.name = ReadString(fp);
        
        // Read dimensions
        uint32_t nDims = ReadUint32(fp);
        tensor.dimensions.reserve(nDims);
        for (uint32_t d = 0; d < nDims; ++d) {
            tensor.dimensions.push_back(ReadUint64(fp));
        }
        
        // Read type
        tensor.type = static_cast<GGMLType>(ReadUint32(fp));
        
        // Read offset (this is where the data starts, relative to tensor data section)
        tensor.offset = ReadUint64(fp);
        
        // Calculate size
        tensor.size = CalculateTensorSize(tensor);
        
        tensors.push_back(tensor);
        
        if (verbose) {
            printf("  Tensor[%llu]: %s, type=%s, dims=%zu, size=%llu\n",
                   (unsigned long long)i, tensor.name.c_str(), GetTypeName(tensor.type),
                   tensor.dimensions.size(), (unsigned long long)tensor.size);
        }
    }
    
    // Calculate data section offset (after padding to alignment)
    long currentPos = ftell(fp);
    dataOffset = ((currentPos + alignment - 1) / alignment) * alignment;
    
    return true;
}

bool GGUFLoader::LoadTensorData(FILE* fp, std::vector<TensorInfo>& tensors, uint64_t dataOffset) {
    for (auto& tensor : tensors) {
        // Allocate memory for tensor data
        tensor.data = _aligned_malloc(tensor.size, 32);
        if (!tensor.data) {
            printf("[GGUFLoader] ERROR: Failed to allocate %llu bytes for %s\n",
                   (unsigned long long)tensor.size, tensor.name.c_str());
            return false;
        }
        
        // Seek to tensor data
        uint64_t tensorFileOffset = dataOffset + tensor.offset;
        if (fseek(fp, static_cast<long>(tensorFileOffset), SEEK_SET) != 0) {
            printf("[GGUFLoader] ERROR: Failed to seek to tensor data\n");
            return false;
        }
        
        // Read tensor data
        if (fread(tensor.data, 1, tensor.size, fp) != tensor.size) {
            printf("[GGUFLoader] ERROR: Failed to read tensor data\n");
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// Helper Functions
// ============================================================================
std::string GGUFLoader::ReadString(FILE* fp) {
    uint64_t len = ReadUint64(fp);
    std::string str;
    str.resize(len);
    if (len > 0) {
        fread(&str[0], 1, len, fp);
    }
    return str;
}

uint64_t GGUFLoader::ReadUint64(FILE* fp) {
    uint64_t value;
    fread(&value, sizeof(value), 1, fp);
    return value;
}

uint32_t GGUFLoader::ReadUint32(FILE* fp) {
    uint32_t value;
    fread(&value, sizeof(value), 1, fp);
    return value;
}

int32_t GGUFLoader::ReadInt32(FILE* fp) {
    int32_t value;
    fread(&value, sizeof(value), 1, fp);
    return value;
}

float GGUFLoader::ReadFloat32(FILE* fp) {
    float value;
    fread(&value, sizeof(value), 1, fp);
    return value;
}

size_t GGUFLoader::CalculateTensorSize(const TensorInfo& tensor) {
    size_t numElements = tensor.GetNumElements();
    
    switch (tensor.type) {
        case GGMLType::GGML_TYPE_F32:
            return numElements * sizeof(float);
        case GGMLType::GGML_TYPE_F16:
            return numElements * sizeof(uint16_t);
        case GGMLType::GGML_TYPE_Q4_K:
            // Q4_K_M: 256 weights per 256-byte block
            return ((numElements + 255) / 256) * sizeof(Q4_K_M_Block);
        case GGMLType::GGML_TYPE_Q4_0:
            // Q4_0: 32 weights per 18-byte block
            return ((numElements + 31) / 32) * 18;
        case GGMLType::GGML_TYPE_Q8_0:
            // Q8_0: 32 weights per 34-byte block
            return ((numElements + 31) / 32) * 34;
        default:
            printf("[GGUFLoader] Warning: Unknown type %d, assuming FP32\n", 
                   static_cast<int>(tensor.type));
            return numElements * sizeof(float);
    }
}

int GGUFLoader::ConvertType(GGMLType ggmlType) {
    switch (ggmlType) {
        case GGMLType::GGML_TYPE_F32:  return 0;   // WEIGHT_FP32
        case GGMLType::GGML_TYPE_F16:  return 1;   // WEIGHT_FP16
        case GGMLType::GGML_TYPE_Q4_0:  return 2;   // WEIGHT_Q4_0
        case GGMLType::GGML_TYPE_Q4_1:  return 3;   // WEIGHT_Q4_1
        case GGMLType::GGML_TYPE_Q8_0:  return 8;   // WEIGHT_Q8_0
        case GGMLType::GGML_TYPE_Q4_K:  return 12;  // WEIGHT_Q4_K
        case GGMLType::GGML_TYPE_Q5_K:  return 13;  // WEIGHT_Q5_K
        case GGMLType::GGML_TYPE_Q6_K:  return 14;  // WEIGHT_Q6_K
        default: return 0;  // Default to FP32
    }
}

const char* GGUFLoader::GetTypeName(GGMLType type) {
    switch (type) {
        case GGMLType::GGML_TYPE_F32:  return "F32";
        case GGMLType::GGML_TYPE_F16:  return "F16";
        case GGMLType::GGML_TYPE_Q4_0:  return "Q4_0";
        case GGMLType::GGML_TYPE_Q4_1:  return "Q4_1";
        case GGMLType::GGML_TYPE_Q5_0:  return "Q5_0";
        case GGMLType::GGML_TYPE_Q5_1:  return "Q5_1";
        case GGMLType::GGML_TYPE_Q8_0:  return "Q8_0";
        case GGMLType::GGML_TYPE_Q8_K:  return "Q8_K";
        case GGMLType::GGML_TYPE_Q2_K:  return "Q2_K";
        case GGMLType::GGML_TYPE_Q3_K:  return "Q3_K";
        case GGMLType::GGML_TYPE_Q4_K:  return "Q4_K_M";
        case GGMLType::GGML_TYPE_Q5_K:  return "Q5_K";
        case GGMLType::GGML_TYPE_Q6_K:  return "Q6_K";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Integration Helpers
// ============================================================================
int LoadGGUFIntoEngine(const char* filepath, Deep2Engine& engine, bool verbose) {
    GGUFLoadOptions options;
    options.loadTensors = true;
    options.verbose = verbose;
    
    GGUFLoadResult result = GGUFLoader::Load(filepath, options);
    if (!result.success) {
        printf("[LoadGGUFIntoEngine] Failed: %s\n", result.error);
        return -1;
    }
    
    if (verbose) {
        result.metadata.Print();
    }
    
    int registeredCount = 0;
    for (auto& tensor : result.tensors) {
        if (!tensor.data) continue;
        
        // Calculate dimensions
        size_t rows = 1, cols = 1;
        if (tensor.dimensions.size() >= 1) rows = tensor.dimensions[0];
        if (tensor.dimensions.size() >= 2) cols = tensor.dimensions[1];
        
        // Convert GGML type to Deep2 WeightType
        int weightType = GGUFLoader::ConvertType(tensor.type);
        
        // Register with engine
        int idx = engine.registerWeightTensor(tensor.data, weightType, rows, cols);
        if (idx >= 0) {
            registeredCount++;
            if (verbose) {
                printf("  Registered: %s (type=%s, dims=%zux%zu)\n",
                       tensor.name.c_str(), GGUFLoader::GetTypeName(tensor.type), rows, cols);
            }
        }
    }
    
    if (verbose) {
        printf("[LoadGGUFIntoEngine] Registered %d/%zu tensors\n", 
               registeredCount, result.tensors.size());
    }
    
    return registeredCount;
}

int LoadGGUFTensor(const char* filepath, const char* tensorName, Deep2Engine& engine) {
    GGUFLoadResult result = GGUFLoader::LoadMetadata(filepath);
    if (!result.success) {
        return -1;
    }
    
    const TensorInfo* tensor = result.GetTensor(tensorName);
    if (!tensor) {
        printf("[LoadGGUFTensor] Tensor '%s' not found\n", tensorName);
        return -1;
    }
    
    // Load just this tensor's data
    FILE* fp = fopen(filepath, "rb");
    if (!fp) return -1;
    
    // Calculate data offset (simplified - would need proper parsing)
    // For now, return error
    fclose(fp);
    
    printf("[LoadGGUFTensor] Single tensor loading not yet implemented\n");
    return -1;
}

} // namespace Deep2

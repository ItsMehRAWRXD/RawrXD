// ============================================================================
// DeepSeekMoELoader.cpp - Streaming MoE Loader Implementation
// ============================================================================

#include "DeepSeekMoELoader.hpp"
#include "MoERouter.hpp"
#include "Deep2Engine.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <regex>
#include <cmath>
#include <unordered_set>
#include <fcntl.h>

#ifdef _WIN32
    #include <psapi.h>
#include "gguf_loader.h"
    #pragma comment(lib, "psapi.lib")
    // Undefine GetFileSize macro from windows.h to avoid collision
    #ifdef GetFileSize
        #undef GetFileSize
    #endif
#endif

namespace Deep2 {

// ============================================================================
// GGUF Constants
// ============================================================================
// GGUF_MAGIC and GGUF_VERSION are provided by GGUFLoader.hpp
static constexpr uint32_t GGUF_VERSION_3 = 3;

// GGUF value types - constants only, no enum to avoid collision with
// the strongly-typed GGUFValueType defined in GGUFLoader.hpp.
static constexpr uint32_t GGUF_TYPE_UINT8   = 0;
static constexpr uint32_t GGUF_TYPE_INT8    = 1;
static constexpr uint32_t GGUF_TYPE_UINT16  = 2;
static constexpr uint32_t GGUF_TYPE_INT16   = 3;
static constexpr uint32_t GGUF_TYPE_UINT32  = 4;
static constexpr uint32_t GGUF_TYPE_INT32   = 5;
static constexpr uint32_t GGUF_TYPE_FLOAT32 = 6;
static constexpr uint32_t GGUF_TYPE_BOOL    = 7;
static constexpr uint32_t GGUF_TYPE_STRING  = 8;
static constexpr uint32_t GGUF_TYPE_ARRAY   = 9;
static constexpr uint32_t GGUF_TYPE_UINT64  = 10;
static constexpr uint32_t GGUF_TYPE_INT64   = 11;
static constexpr uint32_t GGUF_TYPE_FLOAT64 = 12;

// ============================================================================
// GGML Type Size Helpers
// ============================================================================
static size_t GGMLTypeSize(GGMLType type) {
    switch (type) {
        case GGMLType::GGML_TYPE_F32:     return 4;
        case GGMLType::GGML_TYPE_F16:     return 2;
        case GGMLType::GGML_TYPE_Q4_0:    return sizeof(block_q4_0);
        case GGMLType::GGML_TYPE_Q4_1:    return sizeof(block_q4_1);
        case GGMLType::GGML_TYPE_Q5_0:    return sizeof(block_q5_0);
        case GGMLType::GGML_TYPE_Q5_1:    return sizeof(block_q5_1);
        case GGMLType::GGML_TYPE_Q8_0:    return sizeof(block_q8_0);
        case GGMLType::GGML_TYPE_Q8_K:    return sizeof(block_q8_K);
        case GGMLType::GGML_TYPE_Q2_K:    return sizeof(block_q2_K);
        case GGMLType::GGML_TYPE_Q3_K:    return sizeof(block_q3_K);
        case GGMLType::GGML_TYPE_Q4_K:    return sizeof(block_q4_K);
        case GGMLType::GGML_TYPE_Q5_K:    return sizeof(block_q5_K);
        case GGMLType::GGML_TYPE_Q6_K:    return sizeof(block_q6_K);
        case GGMLType::GGML_TYPE_IQ2_XXS: return sizeof(block_iq2_xxs);
        case GGMLType::GGML_TYPE_IQ2_XS:  return sizeof(block_iq2_xs);
        case GGMLType::GGML_TYPE_IQ3_XXS: return sizeof(block_iq3_xxs);
        case GGMLType::GGML_TYPE_IQ1_S:   return sizeof(block_iq1_s);
        case GGMLType::GGML_TYPE_IQ4_NL:  return sizeof(block_iq4_nl);
        case GGMLType::GGML_TYPE_IQ3_S:   return sizeof(block_iq3_s);
        case GGMLType::GGML_TYPE_IQ2_S:   return sizeof(block_iq2_s);
        case GGMLType::GGML_TYPE_IQ4_XS:  return sizeof(block_iq4_xs);
        case GGMLType::GGML_TYPE_I8:      return 1;
        case GGMLType::GGML_TYPE_I16:     return 2;
        case GGMLType::GGML_TYPE_I32:     return 4;
        case GGMLType::GGML_TYPE_I64:     return 8;
        case GGMLType::GGML_TYPE_F64:     return 8;
        default:                return 4;
    }
}

static size_t GGMLTypeBlockSize(GGMLType type) {
    switch (type) {
        case GGMLType::GGML_TYPE_F32:     return 1;
        case GGMLType::GGML_TYPE_F16:     return 1;
        case GGMLType::GGML_TYPE_Q4_0:    return QK4_0;
        case GGMLType::GGML_TYPE_Q4_1:    return QK4_1;
        case GGMLType::GGML_TYPE_Q5_0:    return QK5_0;
        case GGMLType::GGML_TYPE_Q5_1:    return QK5_1;
        case GGMLType::GGML_TYPE_Q8_0:    return QK8_0;
        case GGMLType::GGML_TYPE_Q8_K:    return QK_K;
        case GGMLType::GGML_TYPE_Q2_K:    return QK_K;
        case GGMLType::GGML_TYPE_Q3_K:    return QK_K;
        case GGMLType::GGML_TYPE_Q4_K:    return QK_K;
        case GGMLType::GGML_TYPE_Q5_K:    return QK_K;
        case GGMLType::GGML_TYPE_Q6_K:    return QK_K;
        case GGMLType::GGML_TYPE_IQ2_XXS: return QK_K;
        case GGMLType::GGML_TYPE_IQ2_XS:  return QK_K;
        case GGMLType::GGML_TYPE_IQ3_XXS: return QK_K;
        case GGMLType::GGML_TYPE_IQ1_S:   return QK_K;
        case GGMLType::GGML_TYPE_IQ4_NL:  return QK4_NL;
        case GGMLType::GGML_TYPE_IQ3_S:   return QK_K;
        case GGMLType::GGML_TYPE_IQ2_S:   return QK_K;
        case GGMLType::GGML_TYPE_IQ4_XS:  return QK_K;
        case GGMLType::GGML_TYPE_I8:      return 1;
        case GGMLType::GGML_TYPE_I16:     return 1;
        case GGMLType::GGML_TYPE_I32:     return 1;
        case GGMLType::GGML_TYPE_I64:     return 1;
        case GGMLType::GGML_TYPE_F64:     return 1;
        default:                return 1;
    }
}

static size_t CalculateTensorBytes(const TensorInfo& t) {
    if (t.dimensions.empty()) return 0;
    size_t elements = 1;
    for (auto d : t.dimensions) elements *= (size_t)d;
    size_t blockSize = GGMLTypeBlockSize(t.type);
    size_t typeSize = GGMLTypeSize(t.type);
    return (elements / blockSize) * typeSize + (elements % blockSize ? typeSize : 0);
}

// ============================================================================
// DeepSeekMoELoader Implementation
// ============================================================================
DeepSeekMoELoader::DeepSeekMoELoader()
#ifdef _WIN32
    : fileHandle_(nullptr)
    , fileMapping_(nullptr)
#else
    : fileHandle_(-1)
#endif
    , mappedBase_(nullptr)
    , fileSize_(0)
    , dataOffset_(0)
    , maxCacheBytes_(4ULL * 1024 * 1024 * 1024)
    , currentCacheBytes_(0)
    , isLoaded_(false)
{
}

DeepSeekMoELoader::~DeepSeekMoELoader() {
    Close();
}

bool DeepSeekMoELoader::Open(const char* ggufPath, size_t cacheSizeMB) {
    Close();
    
    maxCacheBytes_ = cacheSizeMB * 1024ULL * 1024ULL;
    currentCacheBytes_ = 0;
    
    if (!OpenFile(ggufPath)) {
        return false;
    }
    
    if (!ParseIndex()) {
        CloseFile();
        return false;
    }
    
    DiscoverExpertTensors();
    
    return true;
}

void DeepSeekMoELoader::Close() {
    // Free cache
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        for (auto& pair : cache_) {
            if (pair.second.weights) {
                _aligned_free(pair.second.weights);
            }
        }
        cache_.clear();
        currentCacheBytes_ = 0;
    }
    
    CloseFile();
}

bool DeepSeekMoELoader::OpenFile(const char* path) {
#ifdef _WIN32
    fileHandle_ = CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr
    );
    if (fileHandle_ == INVALID_HANDLE_VALUE) {
        printf("[DeepSeekMoELoader] Failed to open: %s (error %lu)\n", 
               path, GetLastError());
        return false;
    }
    
    LARGE_INTEGER size;
    if (!GetFileSizeEx(fileHandle_, &size)) {
        CloseHandle(fileHandle_);
        fileHandle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    fileSize_ = (uint64_t)size.QuadPart;
    
    // Create file mapping for fast random access
    fileMapping_ = CreateFileMappingA(fileHandle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (fileMapping_) {
        mappedBase_ = MapViewOfFile(fileMapping_, FILE_MAP_READ, 0, 0, 0);
        if (!mappedBase_) {
            printf("[DeepSeekMoELoader] Failed to map view (error %lu)\n", GetLastError());
        }
    } else {
        printf("[DeepSeekMoELoader] No file mapping (error %lu), using ReadFile\n", GetLastError());
    }
#else
    fileHandle_ = open(path, O_RDONLY);
    if (fileHandle_ < 0) return false;
    
    struct stat st;
    if (fstat(fileHandle_, &st) != 0) {
        close(fileHandle_);
        fileHandle_ = -1;
        return false;
    }
    fileSize_ = (uint64_t)st.st_size;
    
    mappedBase_ = mmap(nullptr, fileSize_, PROT_READ, MAP_PRIVATE, fileHandle_, 0);
    if (mappedBase_ == MAP_FAILED) {
        mappedBase_ = nullptr;
    }
#endif
    
    printf("[DeepSeekMoELoader] Opened %.2f GB file\n", 
           fileSize_ / (1024.0 * 1024.0 * 1024.0));
    return true;
}

void DeepSeekMoELoader::CloseFile() {
#ifdef _WIN32
    if (mappedBase_) {
        UnmapViewOfFile(mappedBase_);
        mappedBase_ = nullptr;
    }
    if (fileMapping_) {
        CloseHandle(fileMapping_);
        fileMapping_ = nullptr;
    }
    if (fileHandle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(fileHandle_);
        fileHandle_ = INVALID_HANDLE_VALUE;
    }
#else
    if (mappedBase_) {
        munmap(mappedBase_, fileSize_);
        mappedBase_ = nullptr;
    }
    if (fileHandle_ >= 0) {
        close(fileHandle_);
        fileHandle_ = -1;
    }
#endif
    fileSize_ = 0;
}

bool DeepSeekMoELoader::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!buffer || size == 0) return false;
    if (offset + size > fileSize_) return false;
    
#ifdef _WIN32
    if (mappedBase_) {
        memcpy(buffer, (uint8_t*)mappedBase_ + offset, size);
        return true;
    }
    
    OVERLAPPED overlapped = {};
    overlapped.Offset = (DWORD)(offset & 0xFFFFFFFF);
    overlapped.OffsetHigh = (DWORD)(offset >> 32);
    
    DWORD bytesRead = 0;
    if (!ReadFile(fileHandle_, buffer, (DWORD)size, &bytesRead, &overlapped)) {
        return false;
    }
    return bytesRead == size;
#else
    if (mappedBase_) {
        memcpy(buffer, (uint8_t*)mappedBase_ + offset, size);
        return true;
    }
    
    if (lseek(fileHandle_, (off_t)offset, SEEK_SET) < 0) return false;
    ssize_t n = read(fileHandle_, buffer, size);
    return n == (ssize_t)size;
#endif
}

// ============================================================================
// Architecture Detection and Dispatch
// ============================================================================
void DeepSeekMoELoader::DetectArchitecture() {
    // First, check if we have architecture info in raw metadata
    auto it = rawMetadata_.find("general.architecture");
    if (it != rawMetadata_.end()) {
        config_.architectureName = it->second;
        
        // Map architecture string to enum
        if (config_.architectureName == "deepseek2" || config_.architectureName == "deepseek_v2") {
            config_.architecture = MoEArchitecture::DeepSeekV2;
        } else if (config_.architectureName == "deepseek3" || config_.architectureName == "deepseek_v3") {
            config_.architecture = MoEArchitecture::DeepSeekV3;
        } else if (config_.architectureName.find("mixtral") != std::string::npos) {
            config_.architecture = MoEArchitecture::Mixtral;
        } else if (config_.architectureName.find("qwen3") != std::string::npos || 
                   config_.architectureName.find("qwen") != std::string::npos) {
            config_.architecture = MoEArchitecture::Qwen3MoE;
        } else if (config_.architectureName.find("phi") != std::string::npos) {
            config_.architecture = MoEArchitecture::Phi3MoE;
        } else {
            // Try to detect from tensor naming patterns
            config_.architecture = MoEArchitecture::GenericMoE;
        }
    } else {
        // No architecture declared - try to infer from tensor names
        config_.architecture = MoEArchitecture::GenericMoE;
    }
    
    printf("[DeepSeekMoELoader] Detected architecture: %s (enum: %d)\n", 
           config_.architectureName.c_str(), static_cast<int>(config_.architecture));
}

bool DeepSeekMoELoader::ParseArchitectureMetadata() {
    // Dispatch to appropriate parser based on detected architecture
    switch (config_.architecture) {
        case MoEArchitecture::DeepSeekV2:
        case MoEArchitecture::DeepSeekV3:
            return ParseDeepSeekMetadata();
        case MoEArchitecture::Mixtral:
            return ParseMixtralMetadata();
        case MoEArchitecture::Qwen3MoE:
            return ParseQwen3MoEMetadata();
        case MoEArchitecture::GenericMoE:
        case MoEArchitecture::Unknown:
        default:
            return ParseGenericMoEMetadata();
    }
}

// ============================================================================
// DeepSeek V2/V3 Metadata Parser
// ============================================================================
bool DeepSeekMoELoader::ParseDeepSeekMetadata() {
    printf("[DeepSeekMoELoader] Parsing DeepSeek metadata...\n");
    
    // DeepSeek uses specific metadata keys
    // Try architecture-prefixed keys first, then fall back to generic
    std::string prefix = config_.architectureName + ".";
    
    // Core dimensions
    config_.hiddenSize = GetMetadata<size_t>(prefix + "embedding_length", 0);
    if (config_.hiddenSize == 0) {
        config_.hiddenSize = GetMetadata<size_t>("model.hidden_size", 7168);
    }
    
    config_.numHiddenLayers = GetMetadata<size_t>(prefix + "block_count", 0);
    if (config_.numHiddenLayers == 0) {
        config_.numHiddenLayers = GetMetadata<size_t>("model.num_hidden_layers", 61);
    }
    
    config_.numAttentionHeads = GetMetadata<size_t>(prefix + "attention.head_count", 0);
    if (config_.numAttentionHeads == 0) {
        config_.numAttentionHeads = GetMetadata<size_t>("model.num_attention_heads", 128);
    }
    
    config_.numKeyValueHeads = GetMetadata<size_t>(prefix + "attention.head_count_kv", 0);
    if (config_.numKeyValueHeads == 0) {
        config_.numKeyValueHeads = GetMetadata<size_t>("model.num_key_value_heads", 128);
    }
    
    // MoE specific
    config_.numExperts = GetMetadata<size_t>(prefix + "expert_count", 0);
    if (config_.numExperts == 0) {
        config_.numExperts = GetMetadata<size_t>("moe.num_experts", 256);
    }
    
    config_.numExpertsPerToken = GetMetadata<size_t>(prefix + "expert_used_count", 0);
    if (config_.numExpertsPerToken == 0) {
        config_.numExpertsPerToken = GetMetadata<size_t>("moe.num_experts_per_token", 8);
    }
    
    config_.numSharedExperts = GetMetadata<size_t>(prefix + "expert_shared_count", 0);
    if (config_.numSharedExperts == 0) {
        config_.numSharedExperts = GetMetadata<size_t>("moe.num_shared_experts", 1);
    }
    
    // Intermediate sizes
    config_.intermediateSize = GetMetadata<size_t>(prefix + "feed_forward_length", 0);
    if (config_.intermediateSize == 0) {
        config_.intermediateSize = GetMetadata<size_t>("model.intermediate_size", 18432);
    }
    
    config_.moeIntermediateSize = GetMetadata<size_t>(prefix + "ffn_dim", 0);
    if (config_.moeIntermediateSize == 0) {
        config_.moeIntermediateSize = GetMetadata<size_t>("model.moe_intermediate_size", 2048);
    }
    
    // Vocabulary and context
    config_.vocabSize = GetMetadata<size_t>(prefix + "vocab_size", 0);
    if (config_.vocabSize == 0) {
        config_.vocabSize = GetMetadata<size_t>("model.vocab_size", 129280);
    }
    
    config_.maxPositionEmbeddings = GetMetadata<size_t>(prefix + "context_length", 0);
    if (config_.maxPositionEmbeddings == 0) {
        config_.maxPositionEmbeddings = GetMetadata<size_t>("model.max_position_embeddings", 163840);
    }
    
    // RoPE parameters
    config_.ropeTheta = GetMetadata<float>(prefix + "rope.freq_base", 10000.0f);
    config_.ropeScaling = GetMetadata<float>(prefix + "rope.scale_linear", 1.0f);
    
    return true;
}

// ============================================================================
// Mixtral Metadata Parser
// ============================================================================
bool DeepSeekMoELoader::ParseMixtralMetadata() {
    printf("[DeepSeekMoELoader] Parsing Mixtral metadata...\n");
    
    // Mixtral uses different key conventions
    std::string prefix = "mixtral.";
    if (rawMetadata_.find("general.architecture") != rawMetadata_.end()) {
        prefix = rawMetadata_["general.architecture"] + ".";
    }
    
    config_.hiddenSize = GetMetadata<size_t>(prefix + "embedding_length", 4096);
    config_.numHiddenLayers = GetMetadata<size_t>(prefix + "block_count", 32);
    config_.numAttentionHeads = GetMetadata<size_t>(prefix + "attention.head_count", 32);
    config_.numKeyValueHeads = GetMetadata<size_t>(prefix + "attention.head_count_kv", 8);
    config_.numExperts = GetMetadata<size_t>(prefix + "expert_count", 8);
    config_.numExpertsPerToken = GetMetadata<size_t>(prefix + "expert_used_count", 2);
    config_.numSharedExperts = 0;  // Mixtral doesn't use shared experts
    config_.intermediateSize = GetMetadata<size_t>(prefix + "feed_forward_length", 14336);
    config_.moeIntermediateSize = config_.intermediateSize;
    config_.vocabSize = GetMetadata<size_t>(prefix + "vocab_size", 32000);
    config_.maxPositionEmbeddings = GetMetadata<size_t>(prefix + "context_length", 32768);
    
    return true;
}

// ============================================================================
// Qwen3 MoE Metadata Parser
// ============================================================================
bool DeepSeekMoELoader::ParseQwen3MoEMetadata() {
    printf("[DeepSeekMoELoader] Parsing Qwen3 MoE metadata...\n");
    
    std::string prefix = "qwen3.";
    if (rawMetadata_.find("general.architecture") != rawMetadata_.end()) {
        prefix = rawMetadata_["general.architecture"] + ".";
    }
    
    // Qwen3 MoE has different defaults
    config_.hiddenSize = GetMetadata<size_t>(prefix + "embedding_length", 4096);
    config_.numHiddenLayers = GetMetadata<size_t>(prefix + "block_count", 48);
    config_.numAttentionHeads = GetMetadata<size_t>(prefix + "attention.head_count", 32);
    config_.numKeyValueHeads = GetMetadata<size_t>(prefix + "attention.head_count_kv", 8);
    config_.numExperts = GetMetadata<size_t>(prefix + "expert_count", 128);
    config_.numExpertsPerToken = GetMetadata<size_t>(prefix + "expert_used_count", 8);
    config_.numSharedExperts = GetMetadata<size_t>(prefix + "expert_shared_count", 0);
    config_.intermediateSize = GetMetadata<size_t>(prefix + "feed_forward_length", 0);
    config_.moeIntermediateSize = GetMetadata<size_t>(prefix + "moe_intermediate_size", 0);
    config_.vocabSize = GetMetadata<size_t>(prefix + "vocab_size", 151936);
    config_.maxPositionEmbeddings = GetMetadata<size_t>(prefix + "context_length", 131072);
    
    return true;
}

// ============================================================================
// Generic MoE Metadata Parser (fallback)
// ============================================================================
bool DeepSeekMoELoader::ParseGenericMoEMetadata() {
    printf("[DeepSeekMoELoader] Parsing generic MoE metadata...\n");
    
    // Try to extract whatever we can find using common key patterns
    config_.hiddenSize = GetMetadata<size_t>("model.hidden_size", 0);
    config_.numHiddenLayers = GetMetadata<size_t>("model.num_hidden_layers", 0);
    config_.numAttentionHeads = GetMetadata<size_t>("model.num_attention_heads", 0);
    config_.numKeyValueHeads = GetMetadata<size_t>("model.num_key_value_heads", config_.numAttentionHeads);
    config_.numExperts = GetMetadata<size_t>("moe.num_experts", 0);
    config_.numExpertsPerToken = GetMetadata<size_t>("moe.num_experts_per_token", 0);
    config_.numSharedExperts = GetMetadata<size_t>("moe.num_shared_experts", 0);
    config_.intermediateSize = GetMetadata<size_t>("model.intermediate_size", 0);
    config_.moeIntermediateSize = GetMetadata<size_t>("model.moe_intermediate_size", config_.intermediateSize);
    config_.vocabSize = GetMetadata<size_t>("model.vocab_size", 0);
    config_.maxPositionEmbeddings = GetMetadata<size_t>("model.max_position_embeddings", 0);
    
    return true;
}

// ============================================================================
// Validation
// ============================================================================
bool MoEModelConfig::Validate() const {
    validationError.clear();
    
    // Check required fields
    if (hiddenSize == 0) {
        validationError = "hiddenSize is zero";
        return false;
    }
    if (numHiddenLayers == 0) {
        validationError = "numHiddenLayers is zero";
        return false;
    }
    if (numExperts == 0) {
        validationError = "numExperts is zero";
        return false;
    }
    if (numExpertsPerToken == 0) {
        validationError = "numExpertsPerToken is zero";
        return false;
    }
    if (numExpertsPerToken > numExperts) {
        validationError = "numExpertsPerToken exceeds numExperts";
        return false;
    }
    if (vocabSize == 0) {
        validationError = "vocabSize is zero";
        return false;
    }
    if (numAttentionHeads == 0) {
        validationError = "numAttentionHeads is zero";
        return false;
    }
    if (numKeyValueHeads == 0) {
        validationError = "numKeyValueHeads is zero";
        return false;
    }
    
    // Validate dimensions are reasonable
    if (hiddenSize > 100000 || numExperts > 10000) {
        validationError = "dimensions unreasonably large (possible corruption)";
        return false;
    }
    
    isValidated = true;
    return true;
}

bool DeepSeekMoELoader::ValidateAgainstTensors() {
    if (!config_.isValidated) {
        printf("[DeepSeekMoELoader] ERROR: Config not validated before tensor check\n");
        return false;
    }
    
    // Count actual expert tensors found
    size_t actualExpertTensors = expertTensors_.size();
    size_t expectedExpertTensors = config_.numHiddenLayers * 3;  // gate, up, down per layer
    
    printf("[DeepSeekMoELoader] Validating: found %zu expert tensors, expected ~%zu\n",
           actualExpertTensors, expectedExpertTensors);
    
    // Allow some flexibility (not all layers may have experts in file)
    if (actualExpertTensors == 0) {
        printf("[DeepSeekMoELoader] ERROR: No expert tensors found in file\n");
        return false;
    }
    
    // Validate router tensors exist
    int routerCount = 0;
    for (const auto& tensor : allTensors_) {
        if (tensor.name.find("ffn_gate_inp") != std::string::npos ||
            tensor.name.find("router") != std::string::npos) {
            routerCount++;
        }
    }
    
    if (routerCount == 0) {
        printf("[DeepSeekMoELoader] WARNING: No router tensors found\n");
    } else {
        printf("[DeepSeekMoELoader] Found %d router tensors\n", routerCount);
    }
    
    return true;
}

// ============================================================================
// Metadata Helpers
// ============================================================================
template<typename T>
T DeepSeekMoELoader::GetMetadata(const std::string& key, T defaultValue) const {
    auto it = rawMetadata_.find(key);
    if (it == rawMetadata_.end()) {
        return defaultValue;
    }
    
    // Parse value from string
    try {
        if constexpr (std::is_same_v<T, size_t>) {
            return static_cast<size_t>(std::stoull(it->second));
        } else if constexpr (std::is_same_v<T, int>) {
            return std::stoi(it->second);
        } else if constexpr (std::is_same_v<T, float>) {
            return std::stof(it->second);
        } else if constexpr (std::is_same_v<T, double>) {
            return std::stod(it->second);
        } else if constexpr (std::is_same_v<T, bool>) {
            return it->second == "true" || it->second == "1";
        } else {
            return defaultValue;
        }
    } catch (...) {
        return defaultValue;
    }
}

// Explicit instantiations
template size_t DeepSeekMoELoader::GetMetadata<size_t>(const std::string&, size_t) const;
template int DeepSeekMoELoader::GetMetadata<int>(const std::string&, int) const;
template float DeepSeekMoELoader::GetMetadata<float>(const std::string&, float) const;
template double DeepSeekMoELoader::GetMetadata<double>(const std::string&, double) const;
template bool DeepSeekMoELoader::GetMetadata<bool>(const std::string&, bool) const;

// Legacy helpers (kept for compatibility)
void DeepSeekMoELoader::ParseConfigValue(const std::string& key, uint64_t value) {
    rawMetadata_[key] = std::to_string(value);
}

void DeepSeekMoELoader::ParseConfigValue(const std::string& key, int64_t value) {
    rawMetadata_[key] = std::to_string(value);
}

void DeepSeekMoELoader::ParseConfigString(const std::string& key, const std::string& value) {
    rawMetadata_[key] = value;
    
    if (key == "general.architecture") {
        printf("[DeepSeekMoELoader] Model architecture: %s\n", value.c_str());
    } else if (key == "general.name") {
        printf("[DeepSeekMoELoader] Model name: %s\n", value.c_str());
        config_.modelName = value;
    }
}

bool DeepSeekMoELoader::ParseIndex() {
    progress_.Reset();
    auto start = std::chrono::high_resolution_clock::now();
    
    // Read GGUF header directly from mapped memory or file
    // GGUF format: magic(4) + version(4) + tensorCount(8) + kvCount(8) + metadata... + tensorInfos... + padding + data
    
    uint64_t cursor = 0;
    
    // Read magic
    uint32_t magic = 0;
    if (!ReadAt(cursor, &magic, sizeof(magic))) return false;
    cursor += sizeof(magic);
    if (magic != GGUF_MAGIC) {
        printf("[DeepSeekMoELoader] Invalid GGUF magic: 0x%08X\n", magic);
        return false;
    }
    
    // Read version
    uint32_t version = 0;
    if (!ReadAt(cursor, &version, sizeof(version))) return false;
    cursor += sizeof(version);
    if (version < 2 || version > 3) {
        printf("[DeepSeekMoELoader] Unsupported GGUF version: %u\n", version);
        return false;
    }
    
    // Read tensor count and KV count
    uint64_t tensorCount = 0, kvCount = 0;
    if (!ReadAt(cursor, &tensorCount, sizeof(tensorCount))) return false;
    cursor += sizeof(tensorCount);
    if (!ReadAt(cursor, &kvCount, sizeof(kvCount))) return false;
    cursor += sizeof(kvCount);
    
    // Parse metadata KV pairs and extract model configuration
    for (uint64_t i = 0; i < kvCount; ++i) {
        // Read key length + key
        uint64_t keyLen = 0;
        if (!ReadAt(cursor, &keyLen, sizeof(keyLen))) return false;
        cursor += sizeof(keyLen);
        
        std::vector<char> keyBuf(static_cast<size_t>(keyLen) + 1);
        if (!ReadAt(cursor, keyBuf.data(), static_cast<size_t>(keyLen))) return false;
        keyBuf[keyLen] = '\0';
        std::string key(keyBuf.data());
        cursor += keyLen;
        
        // Read value type
        uint32_t valueType = 0;
        if (!ReadAt(cursor, &valueType, sizeof(valueType))) return false;
        cursor += sizeof(valueType);
        
        // Parse value based on type, extracting config values
        switch (valueType) {
            case GGUF_TYPE_UINT8: {
                uint8_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                ParseConfigValue(key, static_cast<uint64_t>(val));
                break;
            }
            case GGUF_TYPE_INT8: {
                int8_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                break;
            }
            case GGUF_TYPE_UINT16: {
                uint16_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                ParseConfigValue(key, static_cast<uint64_t>(val));
                break;
            }
            case GGUF_TYPE_INT16: {
                int16_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                break;
            }
            case GGUF_TYPE_UINT32: {
                uint32_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                ParseConfigValue(key, static_cast<uint64_t>(val));
                break;
            }
            case GGUF_TYPE_INT32: {
                int32_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                ParseConfigValue(key, static_cast<int64_t>(val));
                break;
            }
            case GGUF_TYPE_FLOAT32: {
                float val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                break;
            }
            case GGUF_TYPE_BOOL: {
                uint8_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                break;
            }
            case GGUF_TYPE_UINT64: {
                uint64_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                ParseConfigValue(key, val);
                break;
            }
            case GGUF_TYPE_INT64: {
                int64_t val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                ParseConfigValue(key, val);
                break;
            }
            case GGUF_TYPE_FLOAT64: {
                double val = 0;
                if (!ReadAt(cursor, &val, sizeof(val))) return false;
                cursor += sizeof(val);
                break;
            }
            case GGUF_TYPE_STRING: {
                uint64_t strLen = 0;
                if (!ReadAt(cursor, &strLen, sizeof(strLen))) return false;
                cursor += sizeof(strLen);
                std::vector<char> strBuf(static_cast<size_t>(strLen) + 1);
                if (!ReadAt(cursor, strBuf.data(), static_cast<size_t>(strLen))) return false;
                strBuf[strLen] = '\0';
                ParseConfigString(key, strBuf.data());
                cursor += strLen;
                break;
            }
            case GGUF_TYPE_ARRAY: {
                uint32_t elemType = 0;
                uint64_t numElems = 0;
                if (!ReadAt(cursor, &elemType, sizeof(elemType))) return false;
                cursor += sizeof(elemType);
                if (!ReadAt(cursor, &numElems, sizeof(numElems))) return false;
                cursor += sizeof(numElems);
                
                for (uint64_t j = 0; j < numElems; ++j) {
                    switch (elemType) {
                        case GGUF_TYPE_UINT8:  cursor += 1; break;
                        case GGUF_TYPE_INT8:   cursor += 1; break;
                        case GGUF_TYPE_UINT16: cursor += 2; break;
                        case GGUF_TYPE_INT16:  cursor += 2; break;
                        case GGUF_TYPE_UINT32: cursor += 4; break;
                        case GGUF_TYPE_INT32:  cursor += 4; break;
                        case GGUF_TYPE_FLOAT32: cursor += 4; break;
                        case GGUF_TYPE_BOOL:   cursor += 1; break;
                        case GGUF_TYPE_UINT64: cursor += 8; break;
                        case GGUF_TYPE_INT64:  cursor += 8; break;
                        case GGUF_TYPE_FLOAT64: cursor += 8; break;
                        case GGUF_TYPE_STRING: {
                            uint64_t strLen = 0;
                            if (!ReadAt(cursor, &strLen, sizeof(strLen))) return false;
                            cursor += sizeof(strLen) + strLen;
                            break;
                        }
                        default: cursor += 4; break;
                    }
                }
                break;
            }
            default:
                cursor += 4; // unknown, skip 4 bytes
                break;
        }
    }
    
    // Parse tensor info entries
    allTensors_.clear();
    allTensors_.reserve(static_cast<size_t>(tensorCount));
    
    for (uint64_t i = 0; i < tensorCount; ++i) {
        TensorInfo tensor;
        
        // Read name length + name
        uint64_t nameLen = 0;
        if (!ReadAt(cursor, &nameLen, sizeof(nameLen))) return false;
        cursor += sizeof(nameLen);
        
        std::vector<char> nameBuf(static_cast<size_t>(nameLen));
        if (!ReadAt(cursor, nameBuf.data(), static_cast<size_t>(nameLen))) return false;
        cursor += nameLen;
        tensor.name.assign(nameBuf.data(), static_cast<size_t>(nameLen));
        
        // Read number of dimensions
        uint32_t nDims = 0;
        if (!ReadAt(cursor, &nDims, sizeof(nDims))) return false;
        cursor += sizeof(nDims);
        
        // Read dimensions
        tensor.dimensions.resize(nDims);
        for (uint32_t d = 0; d < nDims; ++d) {
            uint64_t dim = 0;
            if (!ReadAt(cursor, &dim, sizeof(dim))) return false;
            cursor += sizeof(dim);
            tensor.dimensions[d] = dim;
        }
        
        // Read type
        uint32_t typeVal = 0;
        if (!ReadAt(cursor, &typeVal, sizeof(typeVal))) return false;
        cursor += sizeof(typeVal);
        tensor.type = static_cast<GGMLType>(typeVal);
        
        // Read offset (GGUF v3: offset is relative to data start)
        if (!ReadAt(cursor, &tensor.offset, sizeof(tensor.offset))) return false;
        cursor += sizeof(tensor.offset);
        
        // Calculate actual byte size
        tensor.size = CalculateTensorBytes(tensor);
    }
    
    // Data section starts at cursor, aligned to 32 bytes
    dataOffset_ = (cursor + 31) & ~(uint64_t)31;
    
    auto end = std::chrono::high_resolution_clock::now();
    double parseMs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
    
    printf("[DeepSeekMoELoader] Parsed %llu tensors in %.2f ms (data at offset %llu)\n",
           (unsigned long long)allTensors_.size(), parseMs,
           (unsigned long long)dataOffset_);
    
    // ============================================================================
    // Architecture Detection and Configuration Parsing
    // ============================================================================
    DetectArchitecture();
    
    if (!ParseArchitectureMetadata()) {
        printf("[DeepSeekMoELoader] ERROR: Failed to parse architecture metadata\n");
        return false;
    }
    
    // Validate configuration
    if (!config_.Validate()) {
        printf("[DeepSeekMoELoader] ERROR: Configuration validation failed: %s\n", 
               config_.validationError.c_str());
        return false;
    }
    
    printf("[DeepSeekMoELoader] Configuration validated successfully\n");
    printf("[DeepSeekMoELoader] Architecture: %s, Experts: %zu, Active: %zu, Layers: %zu\n",
           config_.architectureName.c_str(), config_.numExperts, 
           config_.numExpertsPerToken, config_.numHiddenLayers);
    
    progress_.totalTensors = allTensors_.size();
    
    // Calculate total data bytes
    uint64_t totalDataBytes = 0;
    for (const auto& t : allTensors_) {
        totalDataBytes += t.size;
    }
    progress_.totalBytes = totalDataBytes;
    
    return true;
}

bool DeepSeekMoELoader::ParseExpertName(const std::string& name, int& layer, int& expertIdx) {
    // GGUF names for DeepSeek MoE experts:
    // blk.{L}.ffn_gate_exps.weight    - shape [numExperts, hidden, expertDim]
    // blk.{L}.ffn_up_exps.weight      - shape [numExperts, hidden, expertDim]  
    // blk.{L}.ffn_down_exps.weight    - shape [numExperts, expertDim, hidden]
    // blk.{L}.ffn_gate_shexp.weight   - shared expert
    // blk.{L}.ffn_up_shexp.weight
    // blk.{L}.ffn_down_shexp.weight
    // blk.{L}.ffn_gate_inp.weight     - router gate
    
    static const std::regex expertRe(R"(blk\.(\d+)\.ffn_(gate|up|down)_exps\.weight)");
    static const std::regex sharedRe(R"(blk\.(\d+)\.ffn_(gate|up|down)_shexp\.weight)");
    static const std::regex gateRe(R"(blk\.(\d+)\.ffn_gate_inp\.weight)");
    
    std::smatch match;
    
    if (std::regex_search(name, match, expertRe)) {
        layer = std::stoi(match[1].str());
        expertIdx = -1; // Determined by position within stacked tensor
        return true;
    }
    
    if (std::regex_search(name, match, sharedRe)) {
        layer = std::stoi(match[1].str());
        expertIdx = -2; // -2 indicates shared expert
        return true;
    }
    
    if (std::regex_search(name, match, gateRe)) {
        layer = std::stoi(match[1].str());
        expertIdx = -3; // -3 indicates router gate
        return true;
    }
    
    return false;
}

size_t DeepSeekMoELoader::DiscoverExpertTensors() {
    auto start = std::chrono::high_resolution_clock::now();
    
    expertTensors_.clear();
    expertTensorMap_.clear();
    
    // Track discovered experts per layer for validation
    std::unordered_map<int, size_t> expertsPerLayer;
    size_t maxExpertsInTensor = 0;
    
    // For MoE, each layer has 3 expert tensors (gate, up, down)
    // Each tensor contains all experts stacked in dimension 0
    
    for (const auto& tensor : allTensors_) {
        int layer = -1, expertIdx = -1;
        if (!ParseExpertName(tensor.name, layer, expertIdx)) continue;
        if (layer < 0) continue;
        
        ExpertTensorInfo info;
        info.layerIdx = layer;
        info.name = tensor.name;
        info.type = tensor.type;
        info.dimensions = tensor.dimensions;
        info.fileOffset = dataOffset_ + tensor.offset;
        info.sizeBytes = tensor.size;
        
        // Determine projection type
        if (tensor.name.find("ffn_gate_exps") != std::string::npos) {
            info.proj = ExpertTensorInfo::Proj::Gate;
        } else if (tensor.name.find("ffn_up_exps") != std::string::npos) {
            info.proj = ExpertTensorInfo::Proj::Up;
        } else if (tensor.name.find("ffn_down_exps") != std::string::npos) {
            info.proj = ExpertTensorInfo::Proj::Down;
        } else if (tensor.name.find("ffn_gate_shexp") != std::string::npos) {
            info.proj = ExpertTensorInfo::Proj::Gate;
        } else if (tensor.name.find("ffn_up_shexp") != std::string::npos) {
            info.proj = ExpertTensorInfo::Proj::Up;
        } else if (tensor.name.find("ffn_down_shexp") != std::string::npos) {
            info.proj = ExpertTensorInfo::Proj::Down;
        }
        
        // Calculate per-expert byte size within the stacked tensor
        if (tensor.dimensions.size() >= 3) {
            size_t numExpertsInTensor = static_cast<size_t>(tensor.dimensions[0]);
            size_t elementsPerExpert = 1;
            for (size_t d = 1; d < tensor.dimensions.size(); ++d) {
                elementsPerExpert *= static_cast<size_t>(tensor.dimensions[d]);
            }
            
            // Track max experts found in any tensor
            if (numExpertsInTensor > maxExpertsInTensor) {
                maxExpertsInTensor = numExpertsInTensor;
            }
            
            // Calculate bytes per expert based on quantization type
            size_t blockSize = GGMLTypeBlockSize(tensor.type);
            size_t typeSize = GGMLTypeSize(tensor.type);
            size_t numBlocks = (elementsPerExpert + blockSize - 1) / blockSize;
            info.projSize = numBlocks * typeSize;
            info.numExperts = numExpertsInTensor;
            
            // Track experts per layer
            expertsPerLayer[layer] = numExpertsInTensor;
        } else {
            info.projSize = tensor.size;
            info.numExperts = 1;
        }
        
        expertTensors_.push_back(info);
        expertTensorMap_[tensor.name] = expertTensors_.size() - 1;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double discoveryMs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
    
    // Count unique layers
    std::unordered_set<int> layers;
    for (const auto& info : expertTensors_) {
        layers.insert(info.layerIdx);
    }
    
    printf("[DeepSeekMoELoader] Discovered %zu expert tensors across %zu layers in %.2f ms\n",
           expertTensors_.size(), layers.size(), discoveryMs);
    
    // Cross-validate: compare tensor-discovered experts vs metadata
    if (maxExpertsInTensor > 0 && config_.numExperts > 0) {
        if (maxExpertsInTensor != config_.numExperts) {
            printf("[DeepSeekMoELoader] WARNING: Tensor reports %zu experts, metadata says %zu\n",
                   maxExpertsInTensor, config_.numExperts);
            // Trust the tensor dimensions over metadata
            printf("[DeepSeekMoELoader] Using tensor-discovered expert count: %zu\n", 
                   maxExpertsInTensor);
            config_.numExperts = maxExpertsInTensor;
        }
    } else if (maxExpertsInTensor > 0 && config_.numExperts == 0) {
        // Metadata didn't specify, use tensor discovery
        printf("[DeepSeekMoELoader] Inferred %zu experts from tensor dimensions\n", 
               maxExpertsInTensor);
        config_.numExperts = maxExpertsInTensor;
    }
    
    // Validate layer count
    if (!layers.empty()) {
        int maxLayer = *std::max_element(layers.begin(), layers.end());
        if (config_.numHiddenLayers == 0) {
            config_.numHiddenLayers = maxLayer + 1;
            printf("[DeepSeekMoELoader] Inferred %zu layers from tensor discovery\n", 
                   config_.numHiddenLayers);
        } else if (static_cast<size_t>(maxLayer + 1) > config_.numHiddenLayers) {
            printf("[DeepSeekMoELoader] WARNING: Found tensors for layer %d, but metadata says %zu layers\n",
                   maxLayer, config_.numHiddenLayers);
        }
    }
    
    return expertTensors_.size();
}

// GetExpertTensor implementation removed - defined inline in header

const void* DeepSeekMoELoader::LoadExpert(int layer, int expert) {
    if (progress_.cancelled.load()) return nullptr;
    if (expert < 0 || expert >= static_cast<int>(config_.numExperts)) return nullptr;
    
    CacheKey key{layer, expert};
    
    // Check cache first
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            stats_.cacheHits++;
            it->second.lastAccess = std::chrono::steady_clock::now();
            it->second.accessCount++;
            return it->second.weights;
        }
    }
    
    return LoadExpertInternal(layer, expert);
}

const void* DeepSeekMoELoader::LoadExpertInternal(int layer, int expert) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Find the gate/up/down tensors for this layer
    const ExpertTensorInfo* gateInfo = nullptr;
    const ExpertTensorInfo* upInfo = nullptr;
    const ExpertTensorInfo* downInfo = nullptr;
    
    for (const auto& info : expertTensors_) {
        if (info.layerIdx != layer) continue;
        switch (info.proj) {
            case ExpertTensorInfo::Proj::Gate: gateInfo = &info; break;
            case ExpertTensorInfo::Proj::Up:   upInfo = &info; break;
            case ExpertTensorInfo::Proj::Down: downInfo = &info; break;
        }
    }
    
    if (!gateInfo || !upInfo || !downInfo) {
        printf("[DeepSeekMoELoader] Missing expert tensors for layer %d\n", layer);
        return nullptr;
    }
    
    // Calculate per-expert byte offset within each stacked tensor
    size_t expertBytes = gateInfo->projSize + upInfo->projSize + downInfo->projSize;
    if (expertBytes == 0) {
        printf("[DeepSeekMoELoader] Zero-size expert projection for layer %d\n", layer);
        return nullptr;
    }
    
    // Allocate cache entry
    void* buffer = _aligned_malloc(expertBytes, 32);
    if (!buffer) {
        printf("[DeepSeekMoELoader] Failed to allocate %zu bytes for expert %d layer %d\n",
               expertBytes, expert, layer);
        return nullptr;
    }
    
    // Calculate per-expert offset within each tensor
    uint64_t expertOffset = static_cast<uint64_t>(expert) * gateInfo->projSize;
    
    // Read gate weights
    bool ok = ReadAt(gateInfo->fileOffset + expertOffset,
                     buffer, gateInfo->projSize);
    
    // Read up weights
    if (ok) {
        ok = ReadAt(upInfo->fileOffset + expertOffset,
                    static_cast<uint8_t*>(buffer) + gateInfo->projSize, upInfo->projSize);
    }
    
    // Read down weights
    if (ok) {
        ok = ReadAt(downInfo->fileOffset + expertOffset,
                    static_cast<uint8_t*>(buffer) + gateInfo->projSize + upInfo->projSize,
                    downInfo->projSize);
    }
    
    if (!ok) {
        _aligned_free(buffer);
        printf("[DeepSeekMoELoader] Failed to read expert %d layer %d\n", expert, layer);
        return nullptr;
    }
    
    // Add to cache
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        
        // Evict if needed
        while (currentCacheBytes_ + expertBytes > maxCacheBytes_ && !cache_.empty()) {
            EvictLRU();
        }
        
        CachedExpert entry;
        entry.weights = buffer;
        entry.size = expertBytes;
        entry.lastAccess = std::chrono::steady_clock::now();
        entry.accessCount = 1;
        entry.pinned = false;
        
        cache_[CacheKey{layer, expert}] = std::move(entry);
        currentCacheBytes_ += expertBytes;
    }
    
    // Update stats
    auto end = std::chrono::high_resolution_clock::now();
    double loadMs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
    
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.totalLoads++;
        stats_.cacheMisses++;
        stats_.bytesStreamed += expertBytes;
        stats_.avgLoadTimeMs = (stats_.avgLoadTimeMs * (stats_.totalLoads - 1) + loadMs) / stats_.totalLoads;
    }
    
    progress_.loadedBytes += expertBytes;
    progress_.loadedTensors++;
    progress_.currentLayer = layer;
    progress_.currentExpert = expert;
    
    return buffer;
}

bool DeepSeekMoELoader::LoadExpertDirect(int layer, int expert, void* buffer, size_t bufferSize) {
    if (!buffer || bufferSize == 0) return false;
    if (expert < 0 || expert >= static_cast<int>(config_.numExperts)) return false;
    
    // Find tensors for this layer
    const ExpertTensorInfo* gateInfo = nullptr;
    const ExpertTensorInfo* upInfo = nullptr;
    const ExpertTensorInfo* downInfo = nullptr;
    
    for (const auto& info : expertTensors_) {
        if (info.layerIdx != layer) continue;
        switch (info.proj) {
            case ExpertTensorInfo::Proj::Gate: gateInfo = &info; break;
            case ExpertTensorInfo::Proj::Up:   upInfo = &info; break;
            case ExpertTensorInfo::Proj::Down: downInfo = &info; break;
        }
    }
    
    if (!gateInfo || !upInfo || !downInfo) return false;
    
    size_t totalBytes = gateInfo->projSize + upInfo->projSize + downInfo->projSize;
    if (bufferSize < totalBytes) return false;
    
    uint64_t expertOffset = static_cast<uint64_t>(expert) * gateInfo->projSize;
    
    bool ok = ReadAt(gateInfo->fileOffset + expertOffset, buffer, gateInfo->projSize);
    if (ok) {
        ok = ReadAt(upInfo->fileOffset + expertOffset,
                    static_cast<uint8_t*>(buffer) + gateInfo->projSize, upInfo->projSize);
    }
    if (ok) {
        ok = ReadAt(downInfo->fileOffset + expertOffset,
                    static_cast<uint8_t*>(buffer) + gateInfo->projSize + upInfo->projSize,
                    downInfo->projSize);
    }
    
    return ok;
}

bool DeepSeekMoELoader::LoadRouterWeights(int layer, std::vector<float>& outWeights) {
    std::string gateName = "blk." + std::to_string(layer) + ".ffn_gate_inp.weight";
    
    for (const auto& tensor : allTensors_) {
        if (tensor.name == gateName) {
            size_t numElements = 1;
            for (auto d : tensor.dimensions) numElements *= static_cast<size_t>(d);
            outWeights.resize(numElements);
            return ReadAt(dataOffset_ + tensor.offset, outWeights.data(),
                         numElements * sizeof(float));
        }
    }
    return false;
}

bool DeepSeekMoELoader::LoadSharedExpert(int layer, void* buffer, size_t bufferSize) {
    std::vector<std::string> sharedNames = {
        "blk." + std::to_string(layer) + ".ffn_gate_shexp.weight",
        "blk." + std::to_string(layer) + ".ffn_up_shexp.weight",
        "blk." + std::to_string(layer) + ".ffn_down_shexp.weight"
    };
    
    size_t totalRead = 0;
    for (const auto& name : sharedNames) {
        for (const auto& tensor : allTensors_) {
            if (tensor.name == name) {
                if (totalRead + tensor.size > bufferSize) return false;
                if (!ReadAt(dataOffset_ + tensor.offset,
                           static_cast<uint8_t*>(buffer) + totalRead,
                           static_cast<size_t>(tensor.size))) {
                    return false;
                }
                totalRead += static_cast<size_t>(tensor.size);
                break;
            }
        }
    }
    
    return totalRead > 0;
}

void DeepSeekMoELoader::SetMaxCacheSize(size_t bytes) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    maxCacheBytes_ = bytes;
    while (currentCacheBytes_ > maxCacheBytes_ && !cache_.empty()) {
        EvictLRU();
    }
}

size_t DeepSeekMoELoader::GetCacheSize() const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return currentCacheBytes_;
}

void DeepSeekMoELoader::EvictLRU(size_t targetBytes) {
    if (targetBytes == 0) {
        targetBytes = maxCacheBytes_ / 2;  // Evict down to half
    }
    
    // Find LRU unpinned entry
    auto oldest = cache_.end();
    auto now = std::chrono::steady_clock::now();
    
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->second.isPinned) continue;
        if (oldest == cache_.end() || it->second.lastAccess < oldest->second.lastAccess) {
            oldest = it;
        }
    }
    
    if (oldest != cache_.end()) {
        if (oldest->second.weights) {
            _aligned_free(oldest->second.weights);
        }
        currentCacheBytes_ -= oldest->second.weightBytes;
        cache_.erase(oldest);
        stats_.evictions++;
    }
}

void DeepSeekMoELoader::PinExpert(int layer, int expert) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    CacheKey key{layer, expert};
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        it->second.isPinned = true;
    }
}

void DeepSeekMoELoader::UnpinExpert(int layer, int expert) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    CacheKey key{layer, expert};
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        it->second.isPinned = false;
    }
}

DeepSeekMoELoader::Stats DeepSeekMoELoader::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void DeepSeekMoELoader::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

void DeepSeekMoELoader::TouchCache(int layer, int expert) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    CacheKey key{layer, expert};
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        it->second.lastAccess = std::chrono::steady_clock::now();
        it->second.accessCount++;
    }
}

// ============================================================================
// DeepSeekMoETestHarness Implementation
// ============================================================================
DeepSeekMoETestHarness::DeepSeekMoETestHarness() = default;
DeepSeekMoETestHarness::~DeepSeekMoETestHarness() = default;

size_t DeepSeekMoETestHarness::GetPeakMemoryMB() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.PeakWorkingSetSize / (1024 * 1024);
    }
#endif
    return 0;
}

std::vector<float> DeepSeekMoETestHarness::GenerateRandomEmbedding(size_t hiddenSize) {
    std::vector<float> emb(hiddenSize);
    static thread_local std::mt19937 gen(static_cast<unsigned int>(std::time(nullptr)));
    std::normal_distribution<float> dist(0.0f, 0.02f);
    for (auto& v : emb) v = dist(gen);
    return emb;
}

DeepSeekMoETestHarness::TestResults 
DeepSeekMoETestHarness::RunQuickTest(const char* ggufPath) {
    TestResults results;
    
    printf("========================================\n");
    printf("MoE Quick Test\n");
    printf("========================================\n");
    printf("Model: %s\n", ggufPath);
    
    DeepSeekMoELoader loader;
    auto openStart = std::chrono::high_resolution_clock::now();
    if (!loader.Open(ggufPath, 4096)) {
        results.errorMessage = "Failed to open model file";
        return results;
    }
    auto openEnd = std::chrono::high_resolution_clock::now();
    results.loadTimeMs = std::chrono::duration_cast<std::chrono::microseconds>(openEnd - openStart).count() / 1000.0;
    
    results.success = true;
    results.peakMemoryMB = GetPeakMemoryMB();
    
    printf("\n========================================\n");
    printf("QUICK TEST RESULTS\n");
    printf("========================================\n");
    printf("Load time:        %.2f ms\n", results.loadTimeMs);
    printf("Peak memory:      %zu MB\n", results.peakMemoryMB);
    printf("========================================\n");
    
    return results;
}

} // namespace Deep2


// =============================================================================
// RawrXD-CoreRuntime: GGUF Loader Implementation (Production)
// =============================================================================
// PURPOSE: Headless GGUF model loading without UI dependencies
// =============================================================================

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/gguf_loader.h"
#include "core_runtime/gguf_parser.h"
#include "core_runtime/gguf_tensor.h"
#include "core_runtime/vocab_resolver.h"
#include <cstring>
#include <cstdio>
#include <memory>
#include <unordered_map>
#include <vector>

namespace RawrXD {
namespace Core {

// Model architecture types
enum class ModelArchitecture {
    UNKNOWN,
    LLAMA,
    GPT2,
    GPTJ,
    GPT_NEOX,
    MPT,
    STARCODER,
    PERSIMMON,
    REFACT,
    BERT,
    BLOOM,
    STABLELM,
    QWEN,
    QWEN2,
    PHI2,
    PHI3,
    GEMMA,
    GEMMA2,
    MISTRAL,
    MIXTRAL,
    LLAMA3
};

// Model hyperparameters
struct ModelHyperparameters {
    uint32_t vocabSize = 0;
    uint32_t hiddenSize = 0;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t numKeyValueHeads = 0;
    uint32_t intermediateSize = 0;
    uint32_t maxPositionEmbeddings = 0;
    float rmsNormEps = 1e-6f;
    float ropeTheta = 10000.0f;
    uint32_t ropeScalingType = 0;
    float ropeScalingFactor = 1.0f;
    uint32_t contextLength = 2048;
    uint32_t bosTokenId = 1;
    uint32_t eosTokenId = 2;
    uint32_t padTokenId = 0;
    uint32_t unkTokenId = 0;
    uint32_t numExperts = 0;
    uint32_t numExpertsPerToken = 0;
    bool useParallelResidual = false;
    bool useGqa = false;
    bool useRopeScaling = false;
};

class GGUFLoader::Impl {
public:
    char modelPath[512];
    bool loaded = false;
    std::string errorMessage;
    
    // Parser and components
    std::unique_ptr<GGUFParser> parser;
    std::unique_ptr<VocabResolver> vocabResolver;
    
    // Model info
    ModelArchitecture architecture = ModelArchitecture::UNKNOWN;
    ModelHyperparameters hyperparams;
    std::string modelName;
    std::string modelDescription;
    std::string modelAuthor;
    std::string modelLicense;
    std::string modelVersion;
    
    // Tensor storage
    std::unordered_map<std::string, GGUFTensor*> tensorMap;
    std::vector<std::string> tensorNames;
    size_t totalModelSize = 0;
    
    // Helper: Get architecture from string
    ModelArchitecture ParseArchitecture(const std::string& arch) {
        if (arch == "llama" || arch == "llama3") return ModelArchitecture::LLAMA3;
        if (arch == "llama2") return ModelArchitecture::LLAMA;
        if (arch == "gpt2") return ModelArchitecture::GPT2;
        if (arch == "gptj") return ModelArchitecture::GPTJ;
        if (arch == "gpt_neox" || arch == "gpt-neox") return ModelArchitecture::GPT_NEOX;
        if (arch == "mpt") return ModelArchitecture::MPT;
        if (arch == "starcoder") return ModelArchitecture::STARCODER;
        if (arch == "persimmon") return ModelArchitecture::PERSIMMON;
        if (arch == "refact") return ModelArchitecture::REFACT;
        if (arch == "bert") return ModelArchitecture::BERT;
        if (arch == "bloom") return ModelArchitecture::BLOOM;
        if (arch == "stablelm") return ModelArchitecture::STABLELM;
        if (arch == "qwen") return ModelArchitecture::QWEN;
        if (arch == "qwen2") return ModelArchitecture::QWEN2;
        if (arch == "phi2") return ModelArchitecture::PHI2;
        if (arch == "phi3") return ModelArchitecture::PHI3;
        if (arch == "gemma") return ModelArchitecture::GEMMA;
        if (arch == "gemma2") return ModelArchitecture::GEMMA2;
        if (arch == "mistral") return ModelArchitecture::MISTRAL;
        if (arch == "mixtral") return ModelArchitecture::MIXTRAL;
        return ModelArchitecture::UNKNOWN;
    }
    
    // Helper: Extract hyperparameters from metadata
    void ExtractHyperparameters() {
        if (!parser || !parser->IsParsed()) return;
        
        // Architecture
        const char* arch = parser->GetMetadataString("general.architecture", "");
        if (arch && *arch) {
            architecture = ParseArchitecture(arch);
        }
        
        // Model name and info
        modelName = parser->GetMetadataString("general.name", "");
        modelDescription = parser->GetMetadataString("general.description", "");
        modelAuthor = parser->GetMetadataString("general.author", "");
        modelLicense = parser->GetMetadataString("general.license", "");
        modelVersion = parser->GetMetadataString("general.version", "");
        
        // Vocabulary size
        hyperparams.vocabSize = parser->GetMetadataInt("%s.vocab_size", 0);
        if (hyperparams.vocabSize == 0) {
            hyperparams.vocabSize = parser->GetMetadataInt("general.vocab_size", 32000);
        }
        
        // Hidden size (embedding dimension)
        hyperparams.hiddenSize = parser->GetMetadataInt("%s.embedding_length", 0);
        if (hyperparams.hiddenSize == 0) {
            hyperparams.hiddenSize = parser->GetMetadataInt("general.embedding_length", 4096);
        }
        
        // Number of layers
        hyperparams.numLayers = parser->GetMetadataInt("%s.block_count", 0);
        if (hyperparams.numLayers == 0) {
            hyperparams.numLayers = parser->GetMetadataInt("general.block_count", 32);
        }
        
        // Number of attention heads
        hyperparams.numHeads = parser->GetMetadataInt("%s.attention.head_count", 0);
        if (hyperparams.numHeads == 0) {
            hyperparams.numHeads = parser->GetMetadataInt("general.attention.head_count", 32);
        }
        
        // Number of key-value heads (for GQA)
        hyperparams.numKeyValueHeads = parser->GetMetadataInt("%s.attention.head_count_kv", 0);
        if (hyperparams.numKeyValueHeads == 0) {
            hyperparams.numKeyValueHeads = hyperparams.numHeads; // Default to standard MHA
        }
        hyperparams.useGqa = (hyperparams.numKeyValueHeads != hyperparams.numHeads);
        
        // Feed-forward dimension
        hyperparams.intermediateSize = parser->GetMetadataInt("%s.feed_forward_length", 0);
        if (hyperparams.intermediateSize == 0) {
            hyperparams.intermediateSize = parser->GetMetadataInt("general.feed_forward_length", 11008);
        }
        
        // Context length
        hyperparams.contextLength = parser->GetMetadataInt("%s.context_length", 0);
        if (hyperparams.contextLength == 0) {
            hyperparams.contextLength = parser->GetMetadataInt("general.context_length", 2048);
        }
        hyperparams.maxPositionEmbeddings = hyperparams.contextLength;
        
        // RMS norm epsilon
        hyperparams.rmsNormEps = parser->GetMetadataFloat("%s.attention.layer_norm_rms_epsilon", 1e-6f);
        if (hyperparams.rmsNormEps == 1e-6f) {
            hyperparams.rmsNormEps = parser->GetMetadataFloat("general.layer_norm_rms_epsilon", 1e-6f);
        }
        
        // RoPE theta
        hyperparams.ropeTheta = parser->GetMetadataFloat("%s.rope.freq_base", 10000.0f);
        if (hyperparams.ropeTheta == 10000.0f) {
            hyperparams.ropeTheta = parser->GetMetadataFloat("general.rope_freq_base", 10000.0f);
        }
        
        // Special token IDs
        hyperparams.bosTokenId = parser->GetMetadataInt("%s.tokenizer.ggml.bos_token_id", 1);
        hyperparams.eosTokenId = parser->GetMetadataInt("%s.tokenizer.ggml.eos_token_id", 2);
        hyperparams.padTokenId = parser->GetMetadataInt("%s.tokenizer.ggml.pad_token_id", 0);
        hyperparams.unkTokenId = parser->GetMetadataInt("%s.tokenizer.ggml.unknown_token_id", 0);
        
        // MoE parameters (for Mixtral)
        hyperparams.numExperts = parser->GetMetadataInt("%s.expert_count", 0);
        hyperparams.numExpertsPerToken = parser->GetMetadataInt("%s.expert_used_count", 0);
        
        // Calculate total model size
        const auto* tensors = parser->GetTensors();
        if (tensors) {
            for (const auto& tensor : *tensors) {
                totalModelSize += tensor.GetSize();
            }
        }
    }
    
    // Helper: Build tensor map
    void BuildTensorMap() {
        tensorMap.clear();
        tensorNames.clear();
        
        if (!parser) return;
        
        const auto* tensors = parser->GetTensors();
        if (!tensors) return;
        
        for (auto& tensor : *tensors) {
            const std::string& name = tensor.GetName();
            tensorMap[name] = const_cast<GGUFTensor*>(&tensor);
            tensorNames.push_back(name);
        }
    }
};

GGUFLoader::GGUFLoader() : pImpl(new Impl()) {
    pImpl->modelPath[0] = '\0';
}

GGUFLoader::~GGUFLoader() = default;
GGUFLoader::GGUFLoader(GGUFLoader&&) noexcept = default;
GGUFLoader& GGUFLoader::operator=(GGUFLoader&&) noexcept = default;

bool GGUFLoader::Load(const char* path) {
    if (!path || std::strlen(path) == 0) {
        pImpl->errorMessage = "Invalid path";
        return false;
    }
    
    // Unload any existing model
    Unload();
    
    // Store path
    std::snprintf(pImpl->modelPath, sizeof(pImpl->modelPath), "%s", path);
    
    // Create parser
    pImpl->parser = std::make_unique<GGUFParser>();
    
    // Parse the file
    if (!pImpl->parser->Parse(path)) {
        pImpl->errorMessage = pImpl->parser->GetError();
        pImpl->parser.reset();
        return false;
    }
    
    // Extract hyperparameters
    pImpl->ExtractHyperparameters();
    
    // Build tensor map
    pImpl->BuildTensorMap();
    
    // Initialize vocabulary resolver
    pImpl->vocabResolver = std::make_unique<VocabResolver>();
    // TODO: Load vocabulary from GGUF tokenizer data
    
    pImpl->loaded = true;
    return true;
}

bool GGUFLoader::LoadFromBuffer(const void* data, size_t size) {
    if (!data || size == 0) {
        pImpl->errorMessage = "Invalid buffer";
        return false;
    }
    
    // Unload any existing model
    Unload();
    
    // Create parser
    pImpl->parser = std::make_unique<GGUFParser>();
    
    // Parse from buffer
    if (!pImpl->parser->ParseBuffer(data, size)) {
        pImpl->errorMessage = pImpl->parser->GetError();
        pImpl->parser.reset();
        return false;
    }
    
    // Extract hyperparameters
    pImpl->ExtractHyperparameters();
    
    // Build tensor map
    pImpl->BuildTensorMap();
    
    // Initialize vocabulary resolver
    pImpl->vocabResolver = std::make_unique<VocabResolver>();
    
    pImpl->loaded = true;
    return true;
}

bool GGUFLoader::IsLoaded() const {
    return pImpl->loaded;
}

const char* GGUFLoader::GetModelPath() const {
    return pImpl->modelPath;
}

const char* GGUFLoader::GetError() const {
    return pImpl->errorMessage.c_str();
}

void GGUFLoader::Unload() {
    pImpl->tensorMap.clear();
    pImpl->tensorNames.clear();
    pImpl->parser.reset();
    pImpl->vocabResolver.reset();
    pImpl->loaded = false;
    pImpl->modelPath[0] = '\0';
    pImpl->errorMessage.clear();
    pImpl->totalModelSize = 0;
    pImpl->architecture = ModelArchitecture::UNKNOWN;
}

// Model information
const char* GGUFLoader::GetModelName() const {
    return pImpl->modelName.c_str();
}

const char* GGUFLoader::GetModelDescription() const {
    return pImpl->modelDescription.c_str();
}

const char* GGUFLoader::GetModelArchitecture() const {
    switch (pImpl->architecture) {
        case ModelArchitecture::LLAMA: return "llama";
        case ModelArchitecture::LLAMA3: return "llama3";
        case ModelArchitecture::GPT2: return "gpt2";
        case ModelArchitecture::GPTJ: return "gptj";
        case ModelArchitecture::GPT_NEOX: return "gpt_neox";
        case ModelArchitecture::MPT: return "mpt";
        case ModelArchitecture::STARCODER: return "starcoder";
        case ModelArchitecture::PERSIMMON: return "persimmon";
        case ModelArchitecture::REFACT: return "refact";
        case ModelArchitecture::BERT: return "bert";
        case ModelArchitecture::BLOOM: return "bloom";
        case ModelArchitecture::STABLELM: return "stablelm";
        case ModelArchitecture::QWEN: return "qwen";
        case ModelArchitecture::QWEN2: return "qwen2";
        case ModelArchitecture::PHI2: return "phi2";
        case ModelArchitecture::PHI3: return "phi3";
        case ModelArchitecture::GEMMA: return "gemma";
        case ModelArchitecture::GEMMA2: return "gemma2";
        case ModelArchitecture::MISTRAL: return "mistral";
        case ModelArchitecture::MIXTRAL: return "mixtral";
        default: return "unknown";
    }
}

uint32_t GGUFLoader::GetVocabSize() const {
    return pImpl->hyperparams.vocabSize;
}

uint32_t GGUFLoader::GetHiddenSize() const {
    return pImpl->hyperparams.hiddenSize;
}

uint32_t GGUFLoader::GetNumLayers() const {
    return pImpl->hyperparams.numLayers;
}

uint32_t GGUFLoader::GetNumHeads() const {
    return pImpl->hyperparams.numHeads;
}

uint32_t GGUFLoader::GetContextLength() const {
    return pImpl->hyperparams.contextLength;
}

size_t GGUFLoader::GetModelSize() const {
    return pImpl->totalModelSize;
}

// Tensor access
GGUFTensor* GGUFLoader::GetTensor(const char* name) {
    if (!name || !pImpl->loaded) return nullptr;
    
    auto it = pImpl->tensorMap.find(name);
    if (it != pImpl->tensorMap.end()) {
        return it->second;
    }
    return nullptr;
}

const std::vector<std::string>* GGUFLoader::GetTensorNames() const {
    return &pImpl->tensorNames;
}

size_t GGUFLoader::GetTensorCount() const {
    return pImpl->tensorNames.size();
}

// Vocabulary access
VocabResolver* GGUFLoader::GetVocabResolver() const {
    return pImpl->vocabResolver.get();
}

// Metadata access
const char* GGUFLoader::GetMetadataString(const char* key, const char* defaultValue) const {
    if (!pImpl->parser || !pImpl->loaded) return defaultValue;
    return pImpl->parser->GetMetadataString(key, defaultValue);
}

int32_t GGUFLoader::GetMetadataInt(const char* key, int32_t defaultValue) const {
    if (!pImpl->parser || !pImpl->loaded) return defaultValue;
    return pImpl->parser->GetMetadataInt(key, defaultValue);
}

float GGUFLoader::GetMetadataFloat(const char* key, float defaultValue) const {
    if (!pImpl->parser || !pImpl->loaded) return defaultValue;
    return pImpl->parser->GetMetadataFloat(key, defaultValue);
}

} // namespace Core
} // namespace RawrXD

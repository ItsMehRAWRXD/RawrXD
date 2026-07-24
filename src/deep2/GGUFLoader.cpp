// ============================================================================
// GGUFLoader.cpp - Zero-Dependency GGUF Parser Implementation
// ============================================================================

#include "GGUFLoader.hpp"
#include <chrono>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
    #include <windows.h>
    #include <malloc.h>
#else
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

namespace Deep2 {

// ============================================================================
// Binary Reading Helpers
// ============================================================================

std::string GGUFLoader::ReadString(FILE* fp) {
    uint64_t len = ReadUint64(fp);
    if (len == 0 || len > 1024 * 1024) return "";
    std::string s(len, '\0');
    if (fread(s.data(), 1, len, fp) != len) return "";
    return s;
}

uint64_t GGUFLoader::ReadUint64(FILE* fp) {
    uint64_t v;
    if (fread(&v, 1, 8, fp) != 8) return 0;
    return v;
}

uint32_t GGUFLoader::ReadUint32(FILE* fp) {
    uint32_t v;
    if (fread(&v, 1, 4, fp) != 4) return 0;
    return v;
}

int32_t GGUFLoader::ReadInt32(FILE* fp) {
    int32_t v;
    if (fread(&v, 1, 4, fp) != 4) return 0;
    return v;
}

float GGUFLoader::ReadFloat32(FILE* fp) {
    float v;
    if (fread(&v, 1, 4, fp) != 4) return 0.0f;
    return v;
}

uint16_t GGUFLoader::ReadUint16(FILE* fp) {
    uint16_t v;
    if (fread(&v, 1, 2, fp) != 2) return 0;
    return v;
}

int16_t GGUFLoader::ReadInt16(FILE* fp) {
    int16_t v;
    if (fread(&v, 1, 2, fp) != 2) return 0;
    return v;
}

uint8_t GGUFLoader::ReadUint8(FILE* fp) {
    uint8_t v;
    if (fread(&v, 1, 1, fp) != 1) return 0;
    return v;
}

int8_t GGUFLoader::ReadInt8(FILE* fp) {
    int8_t v;
    if (fread(&v, 1, 1, fp) != 1) return 0;
    return v;
}

double GGUFLoader::ReadFloat64(FILE* fp) {
    double v;
    if (fread(&v, 1, 8, fp) != 8) return 0.0;
    return v;
}

bool GGUFLoader::ReadBool(FILE* fp) {
    uint8_t v;
    if (fread(&v, 1, 1, fp) != 1) return false;
    return v != 0;
}

// ============================================================================
// Header Parsing
// ============================================================================

bool GGUFLoader::ParseHeader(FILE* fp, uint64_t& tensorCount, uint64_t& kvCount) {
    uint32_t magic = ReadUint32(fp);
    if (magic != GGUF_MAGIC) return false;

    uint32_t version = ReadUint32(fp);
    if (version != GGUF_VERSION && version != 2 && version != 1) return false;

    tensorCount = ReadUint64(fp);
    kvCount = ReadUint64(fp);
    return true;
}

// ============================================================================
// Metadata Parsing
// ============================================================================

bool GGUFLoader::ParseMetadataKV(FILE* fp, uint64_t kvCount, ModelMetadata& metadata,
                                  std::unordered_map<std::string, std::string>& rawMeta) {
    for (uint64_t i = 0; i < kvCount; ++i) {
        std::string key = ReadString(fp);
        uint32_t valueType = ReadUint32(fp);

        std::string valueStr;

        switch ((GGUFValueType)valueType) {
            case GGUFValueType::UINT8: {
                uint8_t v = ReadUint8(fp);
                valueStr = std::to_string(v);
                break;
            }
            case GGUFValueType::INT8: {
                int8_t v = ReadInt8(fp);
                valueStr = std::to_string(v);
                break;
            }
            case GGUFValueType::UINT16: {
                uint16_t v = ReadUint16(fp);
                valueStr = std::to_string(v);
                break;
            }
            case GGUFValueType::INT16: {
                int16_t v = ReadInt16(fp);
                valueStr = std::to_string(v);
                break;
            }
            case GGUFValueType::UINT32: {
                uint32_t v = ReadUint32(fp);
                valueStr = std::to_string(v);
                if (key == "tokenizer.ggml.tokens" || key.find(".count") != std::string::npos) {
                    // Skip array values for now
                }
                break;
            }
            case GGUFValueType::INT32: {
                int32_t v = ReadInt32(fp);
                valueStr = std::to_string(v);
                break;
            }
            case GGUFValueType::FLOAT32: {
                float v = ReadFloat32(fp);
                valueStr = std::to_string(v);
                break;
            }
            case GGUFValueType::BOOL: {
                bool v = ReadBool(fp);
                valueStr = v ? "true" : "false";
                break;
            }
            case GGUFValueType::STRING: {
                valueStr = ReadString(fp);
                break;
            }
            case GGUFValueType::ARRAY: {
                uint32_t elemType = ReadUint32(fp);
                uint64_t arrCount = ReadUint64(fp);
                // Skip array data
                for (uint64_t j = 0; j < arrCount; ++j) {
                    switch ((GGUFValueType)elemType) {
                        case GGUFValueType::UINT8: ReadUint8(fp); break;
                        case GGUFValueType::INT8: ReadInt8(fp); break;
                        case GGUFValueType::UINT16: ReadUint16(fp); break;
                        case GGUFValueType::INT16: ReadInt16(fp); break;
                        case GGUFValueType::UINT32: ReadUint32(fp); break;
                        case GGUFValueType::INT32: ReadInt32(fp); break;
                        case GGUFValueType::FLOAT32: ReadFloat32(fp); break;
                        case GGUFValueType::BOOL: ReadBool(fp); break;
                        case GGUFValueType::STRING: ReadString(fp); break;
                        case GGUFValueType::UINT64: ReadUint64(fp); break;
                        case GGUFValueType::INT64: { int64_t v; fread(&v, 1, 8, fp); break; }
                        case GGUFValueType::FLOAT64: ReadFloat64(fp); break;
                        default: ReadUint32(fp); break;
                    }
                }
                valueStr = "[array:" + std::to_string(arrCount) + "]";
                break;
            }
            case GGUFValueType::UINT64: {
                uint64_t v = ReadUint64(fp);
                valueStr = std::to_string(v);
                break;
            }
            case GGUFValueType::INT64: {
                int64_t v;
                fread(&v, 1, 8, fp);
                valueStr = std::to_string(v);
                break;
            }
            case GGUFValueType::FLOAT64: {
                double v = ReadFloat64(fp);
                valueStr = std::to_string(v);
                break;
            }
            default:
                // Unknown type - can't continue safely
                return false;
        }

        rawMeta[key] = valueStr;

        // Map known keys to metadata fields
        if (key == "general.architecture") {
            metadata.architecture = valueStr;
        } else if (key == "tokenizer.ggml.model" || key == "tokenizer.model") {
            // Tokenizer model type
        } else {
            // Architecture-specific keys
            std::string arch = metadata.architecture;
            std::string prefix = arch + ".";

            if (key.substr(0, prefix.size()) == prefix) {
                std::string subkey = key.substr(prefix.size());

                if (subkey == "vocab_size" || subkey == "embedding_length") {
                    // Will be set below
                }
            }

            // Common keys (without architecture prefix)
            if (key == "vocab_size" || key.find(".vocab_size") != std::string::npos) {
                metadata.vocabSize = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("embedding_length") != std::string::npos) {
                metadata.hiddenSize = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("block_count") != std::string::npos || key.find("n_layer") != std::string::npos) {
                metadata.numLayers = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("attention.head_count") != std::string::npos || key.find("n_head") != std::string::npos) {
                metadata.numHeads = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("attention.head_count_kv") != std::string::npos || key.find("n_head_kv") != std::string::npos) {
                metadata.numKeyValueHeads = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("feed_forward_length") != std::string::npos || key.find("intermediate_size") != std::string::npos) {
                metadata.intermediateSize = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("rms_norm_eps") != std::string::npos || key.find("layer_norm_eps") != std::string::npos) {
                metadata.rmsNormEps = (float)atof(valueStr.c_str());
            }
            if (key.find("rope.dimension_count") != std::string::npos) {
                // rope dims
            }
            if (key.find("rope.freq_base") != std::string::npos) {
                metadata.ropeTheta = (float)atof(valueStr.c_str());
            }
            if (key.find("context_length") != std::string::npos || key.find("max_position_embeddings") != std::string::npos) {
                metadata.maxPositionEmbeddings = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            // MoE metadata (real parsing - no stubs)
            if (key.find("expert_count") != std::string::npos || key.find("num_experts") != std::string::npos) {
                metadata.numExperts = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("expert_used_count") != std::string::npos || key.find("num_experts_per_tok") != std::string::npos || key.find("moE.topk") != std::string::npos) {
                metadata.numExpertsPerToken = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("shared_expert_count") != std::string::npos || key.find("num_shared_experts") != std::string::npos) {
                metadata.numSharedExperts = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("expert_feed_forward_length") != std::string::npos || key.find("moe_intermediate_size") != std::string::npos) {
                metadata.moeIntermediateSize = (uint32_t)strtoul(valueStr.c_str(), nullptr, 10);
            }
            if (key.find("rope.scaling.factor") != std::string::npos) {
                metadata.ropeScaling = (float)atof(valueStr.c_str());
            }
        }
    }
    return true;
}

// ============================================================================
// Tensor Info Parsing
// ============================================================================

bool GGUFLoader::ParseTensors(FILE* fp, uint64_t tensorCount,
                               std::vector<TensorInfo>& tensors,
                               uint64_t& dataOffset, bool verbose) {
    tensors.clear();
    tensors.reserve(tensorCount);

    for (uint64_t i = 0; i < tensorCount; ++i) {
        TensorInfo t;
        t.name = ReadString(fp);
        uint32_t nDims = ReadUint32(fp);

        for (uint32_t d = 0; d < nDims; ++d) {
            t.dimensions.push_back(ReadUint64(fp));
        }

        uint32_t type = ReadUint32(fp);
        t.type = (GGMLType)type;
        t.offset = ReadUint64(fp);

        // Calculate size
        t.size = CalculateTensorSize(t);

        if (verbose) {
            printf("[GGUF] Tensor: %s type=%u dims=%u size=%zu\n",
                   t.name.c_str(), type, nDims, t.size);
        }

        tensors.push_back(std::move(t));
    }

    // Data section starts after all tensor info
    // Align to 32 bytes
    long currentPos = ftell(fp);
    dataOffset = ((currentPos + 31) / 32) * 32;

    return true;
}

// ============================================================================
// Tensor Data Loading
// ============================================================================

bool GGUFLoader::LoadTensorData(FILE* fp, std::vector<TensorInfo>& tensors,
                                 uint64_t dataOffset) {
    for (auto& t : tensors) {
        if (t.size == 0) continue;

        // Allocate aligned memory
#ifdef _WIN32
        t.data = _aligned_malloc(t.size, 32);
#else
        t.data = aligned_alloc(32, t.size);
#endif
        if (!t.data) {
            printf("[GGUF] ERROR: Failed to allocate %zu bytes for tensor %s\n",
                   t.size, t.name.c_str());
            return false;
        }

        // Seek to tensor data
        if (fseek(fp, (long)(dataOffset + t.offset), SEEK_SET) != 0) {
            printf("[GGUF] ERROR: Failed to seek to tensor %s\n", t.name.c_str());
            return false;
        }

        // Read data
        if (fread(t.data, 1, t.size, fp) != t.size) {
            printf("[GGUF] ERROR: Failed to read tensor %s\n", t.name.c_str());
            return false;
        }
    }
    return true;
}

// ============================================================================
// Calculate Tensor Size
// ============================================================================

size_t GGUFLoader::CalculateTensorSize(const TensorInfo& tensor) {
    size_t numElements = tensor.GetNumElements();
    if (numElements == 0) return 0;

    if (!tensor.IsQuantized()) {
        // Unquantized: size = elements * sizeof(type)
        switch (tensor.type) {
            case GGMLType::GGML_TYPE_F32: return numElements * 4;
            case GGMLType::GGML_TYPE_F16: return numElements * 2;
            case GGMLType::GGML_TYPE_I8:  return numElements;
            case GGMLType::GGML_TYPE_I16: return numElements * 2;
            case GGMLType::GGML_TYPE_I32: return numElements * 4;
            case GGMLType::GGML_TYPE_I64: return numElements * 8;
            case GGMLType::GGML_TYPE_F64: return numElements * 8;
            default: return numElements * 4;
        }
    }

    // Quantized: size = numBlocks * blockSize
    size_t elemsPerBlock = tensor.GetElemsPerBlock();
    size_t blockSize = tensor.GetBlockSize();
    size_t numBlocks = (numElements + elemsPerBlock - 1) / elemsPerBlock;
    return numBlocks * blockSize;
}

// ============================================================================
// Main Load Function
// ============================================================================

GGUFLoadResult GGUFLoader::Load(const char* filepath, const GGUFLoadOptions& options) {
    GGUFLoadResult result;
    auto startTime = std::chrono::high_resolution_clock::now();

    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        snprintf(result.error, sizeof(result.error), "Cannot open file: %s", filepath);
        return result;
    }

    // Parse header
    uint64_t tensorCount = 0, kvCount = 0;
    if (!ParseHeader(fp, tensorCount, kvCount)) {
        snprintf(result.error, sizeof(result.error), "Invalid GGUF header");
        fclose(fp);
        return result;
    }

    if (options.verbose) {
        printf("[GGUF] Header: tensors=%llu kv=%llu\n",
               (unsigned long long)tensorCount, (unsigned long long)kvCount);
    }

    // Parse metadata
    std::unordered_map<std::string, std::string> rawMeta;
    if (!ParseMetadataKV(fp, kvCount, result.metadata, rawMeta)) {
        snprintf(result.error, sizeof(result.error), "Failed to parse metadata");
        fclose(fp);
        return result;
    }

    // Parse tensor info
    uint64_t dataOffset = 0;
    if (!ParseTensors(fp, tensorCount, result.tensors, dataOffset, options.verbose)) {
        snprintf(result.error, sizeof(result.error), "Failed to parse tensor info");
        fclose(fp);
        return result;
    }

    // Load tensor data
    if (options.loadTensors) {
        if (!LoadTensorData(fp, result.tensors, dataOffset)) {
            snprintf(result.error, sizeof(result.error), "Failed to load tensor data");
            fclose(fp);
            return result;
        }
    }

    fclose(fp);

    auto endTime = std::chrono::high_resolution_clock::now();
    result.loadTimeMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    result.success = true;

    // Calculate total size
    result.totalSize = 0;
    for (const auto& t : result.tensors) {
        result.totalSize += t.size;
    }

    if (options.verbose) {
        printf("[GGUF] Loaded %zu tensors, %.2f MB in %.1f ms\n",
               result.tensors.size(),
               result.totalSize / (1024.0 * 1024.0),
               result.loadTimeMs);
        result.metadata.Print();
    }

    return result;
}

GGUFLoadResult GGUFLoader::LoadMetadata(const char* filepath) {
    GGUFLoadOptions opts;
    opts.loadTensors = false;
    opts.verbose = false;
    return Load(filepath, opts);
}

int GGUFLoader::ConvertType(GGMLType ggmlType) {
    return (int)ggmlType;
}

const char* GGUFLoader::GetTypeName(GGMLType type) {
    switch (type) {
        case GGMLType::GGML_TYPE_F32: return "F32";
        case GGMLType::GGML_TYPE_F16: return "F16";
        case GGMLType::GGML_TYPE_Q4_0: return "Q4_0";
        case GGMLType::GGML_TYPE_Q4_1: return "Q4_1";
        case GGMLType::GGML_TYPE_Q5_0: return "Q5_0";
        case GGMLType::GGML_TYPE_Q5_1: return "Q5_1";
        case GGMLType::GGML_TYPE_Q8_0: return "Q8_0";
        case GGMLType::GGML_TYPE_Q4_K: return "Q4_K";
        case GGMLType::GGML_TYPE_Q5_K: return "Q5_K";
        case GGMLType::GGML_TYPE_Q6_K: return "Q6_K";
        default: return "UNKNOWN";
    }
}

bool GGUFLoader::ValidateFile(const char* filepath, char* error) {
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        if (error) snprintf(error, 256, "Cannot open file");
        return false;
    }

    uint32_t magic = ReadUint32(fp);
    fclose(fp);

    if (magic != GGUF_MAGIC) {
        if (error) snprintf(error, 256, "Invalid magic: 0x%08X", magic);
        return false;
    }
    return true;
}

} // namespace Deep2
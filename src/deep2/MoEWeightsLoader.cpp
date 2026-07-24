// ============================================================================
// MoEWeightsLoader.cpp - Real MoE expert weight streaming
// No stubs. No shortcuts. Reads actual GGUF bytes from disk.
// ============================================================================

#include "MoEWeightsLoader.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <regex>
#include <unordered_set>

#ifdef _WIN32
    #include <psapi.h>
    #pragma comment(lib, "psapi.lib")
    #ifdef GetFileSize
        #undef GetFileSize
    #endif
#endif

namespace Deep2 {

// ============================================================================
// MoEWeightsLoader Implementation
// ============================================================================
MoEWeightsLoader::MoEWeightsLoader()
#ifdef _WIN32
    : fileHandle_(INVALID_HANDLE_VALUE)
    , fileMapping_(nullptr)
    , mappedBase_(nullptr)
#else
    : fileHandle_(-1)
#endif
{
}

MoEWeightsLoader::~MoEWeightsLoader() {
    Close();
}

bool MoEWeightsLoader::Open(const char* ggufPath) {
    Close();

    if (!OpenFile(ggufPath)) {
        fprintf(stderr, "MoEWeightsLoader: OpenFile failed for %s\n", ggufPath);
        return false;
    }

    if (!ParseIndex()) {
        fprintf(stderr, "MoEWeightsLoader: ParseIndex failed at cursor\n");
        CloseFile();
        return false;
    }

    DiscoverExpertProjections();
    return true;
}

void MoEWeightsLoader::Close() {
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        for (auto& pair : cache_) {
            if (pair.second.data) {
                _aligned_free(pair.second.data);
            }
        }
        cache_.clear();
        currentCacheBytes_ = 0;
    }
    CloseFile();
    allTensors_.clear();
    expertProjections_.clear();
    tensorNameMap_.clear();
}

bool MoEWeightsLoader::IsOpen() const {
#ifdef _WIN32
    return fileHandle_ != INVALID_HANDLE_VALUE;
#else
    return fileHandle_ >= 0;
#endif
}

bool MoEWeightsLoader::OpenFile(const char* path) {
#ifdef _WIN32
    fileHandle_ = CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr
    );
    if (fileHandle_ == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileA failed for %s (error %lu)\n", path, GetLastError());
        return false;
    }

    LARGE_INTEGER size;
    if (!GetFileSizeEx(fileHandle_, &size)) {
        fprintf(stderr, "GetFileSizeEx failed (error %lu)\n", GetLastError());
        CloseHandle(fileHandle_);
        fileHandle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    fileSize_ = (uint64_t)size.QuadPart;

    // Only use file mapping for files <= 4 GB (mismatch with size_t on 32-bit indexing)
    if (fileSize_ <= 0xFFFFFFFFULL) {
        fileMapping_ = CreateFileMappingA(fileHandle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (fileMapping_) {
            mappedBase_ = MapViewOfFile(fileMapping_, FILE_MAP_READ, 0, 0, 0);
            if (!mappedBase_) {
                fprintf(stderr, "MapViewOfFile failed (error %lu), falling back to ReadFile\n", GetLastError());
            }
        } else {
            fprintf(stderr, "CreateFileMappingA failed (error %lu), using ReadFile\n", GetLastError());
        }
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
    mappedSize_ = fileSize_;

    mappedBase_ = mmap(nullptr, mappedSize_, PROT_READ, MAP_PRIVATE, fileHandle_, 0);
    if (mappedBase_ == MAP_FAILED) {
        mappedBase_ = nullptr;
    }
#endif
    return true;
}

void MoEWeightsLoader::CloseFile() {
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
        munmap(mappedBase_, mappedSize_);
        mappedBase_ = nullptr;
    }
    if (fileHandle_ >= 0) {
        close(fileHandle_);
        fileHandle_ = -1;
    }
#endif
    fileSize_ = 0;
}

bool MoEWeightsLoader::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!buffer || size == 0) return false;
    if (offset + size > fileSize_) {
        fprintf(stderr, "ReadAt: offset+size %llu+%zu > fileSize %llu\n",
                (unsigned long long)offset, size, (unsigned long long)fileSize_);
        return false;
    }

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
        fprintf(stderr, "ReadFile failed at offset %llu size %zu (error %lu)\n",
                (unsigned long long)offset, size, GetLastError());
        return false;
    }
    if (bytesRead != (DWORD)size) {
        fprintf(stderr, "ReadFile short read at offset %llu: got %lu expected %zu\n",
                (unsigned long long)offset, bytesRead, size);
        return false;
    }
    return true;
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

size_t GGMLTypeBlockSizeStatic(GGMLType type) {
    switch (type) {
        case Deep2::GGMLType::GGML_TYPE_F32:     return 1;
        case Deep2::GGMLType::GGML_TYPE_F16:     return 1;
        case Deep2::GGMLType::GGML_TYPE_Q4_0:    return QK4_0;
        case Deep2::GGMLType::GGML_TYPE_Q4_1:    return QK4_1;
        case Deep2::GGMLType::GGML_TYPE_Q5_0:    return QK5_0;
        case Deep2::GGMLType::GGML_TYPE_Q5_1:    return QK5_1;
        case Deep2::GGMLType::GGML_TYPE_Q8_0:    return QK8_0;
        case Deep2::GGMLType::GGML_TYPE_Q2_K:    return QK_K;
        case Deep2::GGMLType::GGML_TYPE_Q3_K:    return QK_K;
        case Deep2::GGMLType::GGML_TYPE_Q4_K:    return QK_K;
        case Deep2::GGMLType::GGML_TYPE_Q5_K:    return QK_K;
        case Deep2::GGMLType::GGML_TYPE_Q6_K:    return QK_K;
        case Deep2::GGMLType::GGML_TYPE_Q8_K:    return QK_K;
        case Deep2::GGMLType::GGML_TYPE_IQ2_XXS: return QK_K;
        case Deep2::GGMLType::GGML_TYPE_IQ2_XS:  return QK_K;
        case Deep2::GGMLType::GGML_TYPE_IQ3_XXS: return QK_K;
        case Deep2::GGMLType::GGML_TYPE_IQ1_S:   return QK_K;
        case Deep2::GGMLType::GGML_TYPE_IQ4_NL:  return QK4_NL;
        case Deep2::GGMLType::GGML_TYPE_IQ3_S:   return QK_K;
        case Deep2::GGMLType::GGML_TYPE_IQ2_S:   return QK_K;
        case Deep2::GGMLType::GGML_TYPE_IQ4_XS:  return QK_K;
        default:                return 1;
    }
}

size_t GGMLTypeSizeStatic(GGMLType type) {
    switch (type) {
        case Deep2::GGMLType::GGML_TYPE_F32:     return 4;
        case Deep2::GGMLType::GGML_TYPE_F16:     return 2;
        case Deep2::GGMLType::GGML_TYPE_Q4_0:    return sizeof(block_q4_0);
        case Deep2::GGMLType::GGML_TYPE_Q4_1:    return sizeof(block_q4_1);
        case Deep2::GGMLType::GGML_TYPE_Q5_0:    return sizeof(block_q5_0);
        case Deep2::GGMLType::GGML_TYPE_Q5_1:    return sizeof(block_q5_1);
        case Deep2::GGMLType::GGML_TYPE_Q8_0:    return sizeof(block_q8_0);
        case Deep2::GGMLType::GGML_TYPE_Q2_K:    return sizeof(block_q2_K);
        case Deep2::GGMLType::GGML_TYPE_Q3_K:    return sizeof(block_q3_K);
        case Deep2::GGMLType::GGML_TYPE_Q4_K:    return sizeof(block_q4_K);
        case Deep2::GGMLType::GGML_TYPE_Q5_K:    return sizeof(block_q5_K);
        case Deep2::GGMLType::GGML_TYPE_Q6_K:    return sizeof(block_q6_K);
        case Deep2::GGMLType::GGML_TYPE_Q8_K:    return sizeof(block_q8_K);
        case Deep2::GGMLType::GGML_TYPE_IQ2_XXS: return sizeof(block_iq2_xxs);
        case Deep2::GGMLType::GGML_TYPE_IQ2_XS:  return sizeof(block_iq2_xs);
        case Deep2::GGMLType::GGML_TYPE_IQ3_XXS: return sizeof(block_iq3_xxs);
        case Deep2::GGMLType::GGML_TYPE_IQ1_S:   return sizeof(block_iq1_s);
        case Deep2::GGMLType::GGML_TYPE_IQ4_NL:  return sizeof(block_iq4_nl);
        case Deep2::GGMLType::GGML_TYPE_IQ3_S:   return sizeof(block_iq3_s);
        case Deep2::GGMLType::GGML_TYPE_IQ2_S:   return sizeof(block_iq2_s);
        case Deep2::GGMLType::GGML_TYPE_IQ4_XS:  return sizeof(block_iq4_xs);
        case Deep2::GGMLType::GGML_TYPE_I8:      return 1;
        case Deep2::GGMLType::GGML_TYPE_I16:     return 2;
        case Deep2::GGMLType::GGML_TYPE_I32:     return 4;
        case Deep2::GGMLType::GGML_TYPE_I64:     return 8;
        case Deep2::GGMLType::GGML_TYPE_F64:     return 8;
        default:                return 4;
    }
}

size_t CalculateTensorBytesStatic(const TensorInfo& t) {
    if (t.dimensions.empty()) return 0;
    size_t elements = 1;
    for (auto d : t.dimensions) elements *= (size_t)d;
    size_t blockSize = GGMLTypeBlockSizeStatic(t.type);
    size_t typeSize = GGMLTypeSizeStatic(t.type);
    size_t numBlocks = (elements + blockSize - 1) / blockSize;
    return numBlocks * typeSize;
}

bool MoEWeightsLoader::ParseIndex() {
    progress_.Reset();

    // GGUF format:
    //   magic (4) | version (4) | tensorCount (8) | kvCount (8)
    //   metadata KV pairs
    //   tensor info entries
    //   alignment padding to 32 bytes
    //   tensor data

    constexpr uint32_t GGUF_MAGIC = 0x46554747u; // "GGUF"

    uint64_t cursor = 0;

    uint32_t magic = 0;
    if (!ReadAt(cursor, &magic, sizeof(magic))) {
        fprintf(stderr, "ParseIndex: failed to read magic\n");
        return false;
    }
    cursor += sizeof(magic);
    if (magic != GGUF_MAGIC) {
        fprintf(stderr, "ParseIndex: bad magic 0x%08X\n", magic);
        return false;
    }

    uint32_t version = 0;
    if (!ReadAt(cursor, &version, sizeof(version))) return false;
    cursor += sizeof(version);
    if (version < 2 || version > 3) {
        fprintf(stderr, "ParseIndex: unsupported version %u\n", version);
        return false;
    }

    uint64_t tensorCount = 0, kvCount = 0;
    if (!ReadAt(cursor, &tensorCount, sizeof(tensorCount))) return false;
    cursor += sizeof(tensorCount);
    if (!ReadAt(cursor, &kvCount, sizeof(kvCount))) return false;
    cursor += sizeof(kvCount);

        fprintf(stderr, "ParseIndex: tensors=%llu kv=%llu\n",
                (unsigned long long)tensorCount, (unsigned long long)kvCount);
    
    // Parse metadata KV pairs
    for (uint64_t i = 0; i < kvCount; ++i) {
        uint64_t keyLen = 0;
        if (!ReadAt(cursor, &keyLen, sizeof(keyLen))) {
            fprintf(stderr, "ParseIndex: failed to read keyLen at %llu\n",
                    (unsigned long long)cursor);
            return false;
        }
        // Bounds check
        if (keyLen > fileSize_ || cursor + sizeof(keyLen) + keyLen > fileSize_) {
            fprintf(stderr, "ParseIndex: invalid keyLen %llu at %llu (fileSize %llu) KV#%llu\n",
                    (unsigned long long)keyLen, (unsigned long long)cursor,
                    (unsigned long long)fileSize_, (unsigned long long)i);
            return false;
        }
        cursor += sizeof(keyLen);

        // Read key to extract architecture
        std::vector<char> keyBuf(static_cast<size_t>(keyLen + 1), 0);
        if (keyLen < 256) {
            if (ReadAt(cursor, keyBuf.data(), static_cast<size_t>(keyLen))) {
                std::string key(keyBuf.data(), static_cast<size_t>(keyLen));
                if (key == "general.architecture") {
                    uint32_t valType = 0;
                    uint64_t peekCursor = cursor + keyLen;
                    if (ReadAt(peekCursor, &valType, sizeof(valType)) && valType == 8) {
                        peekCursor += sizeof(valType);
                        uint64_t strLen = 0;
                        if (ReadAt(peekCursor, &strLen, sizeof(strLen))) {
                            peekCursor += sizeof(strLen);
                            std::vector<char> strBuf(static_cast<size_t>(strLen + 1), 0);
                            if (ReadAt(peekCursor, strBuf.data(), static_cast<size_t>(strLen))) {
                                architecture_.assign(strBuf.data(), static_cast<size_t>(strLen));
                            }
                        }
                    }
                }
            }
        }
        cursor += keyLen;

        uint32_t valueType = 0;
        if (!ReadAt(cursor, &valueType, sizeof(valueType))) return false;
        cursor += sizeof(valueType);

        uint64_t cursorBeforeValue = cursor;

        switch (valueType) {
            case 0: cursor += 1; break;  // UINT8 = 1 byte
            case 1: cursor += 1; break;  // INT8 = 1 byte
            case 2: cursor += 2; break;  // UINT16
            case 3: cursor += 2; break;  // INT16
            case 4: cursor += 4; break;  // UINT32
            case 5: cursor += 4; break;  // INT32
            case 6: cursor += 4; break;  // FLOAT32
            case 7: cursor += 1; break;  // BOOL = 1 byte (NOT 4!)
            case 8: {
                uint64_t strLen = 0;
                if (!ReadAt(cursor, &strLen, sizeof(strLen))) return false;
                if (cursor + sizeof(strLen) + strLen > fileSize_) return false;
                cursor += sizeof(strLen) + strLen;
                break;
            }
            case 9: {
                // GGUF array: read element type, element count, then data
                uint32_t elemType = 0;
                uint64_t numElems = 0;
                if (!ReadAt(cursor, &elemType, sizeof(elemType))) return false;
                cursor += sizeof(elemType);
                if (!ReadAt(cursor, &numElems, sizeof(numElems))) return false;
                cursor += sizeof(numElems);

                if (elemType == 8) {
                    // ARRAY of STRING
                    for (uint64_t s = 0; s < numElems; ++s) {
                        uint64_t slen = 0;
                        if (!ReadAt(cursor, &slen, sizeof(slen))) return false;
                        if (cursor + sizeof(slen) + slen > fileSize_) return false;
                        cursor += sizeof(slen) + slen;
                    }
                } else if (elemType == 9) {
                    // Nested ARRAY - bail
                    fprintf(stderr, "ParseIndex: nested ARRAY metadata unsupported, aborting\n");
                    return false;
                } else {
                    // Fixed-size element array
                    size_t elemSize = 0;
                    switch (elemType) {
                        case 0: case 1: elemSize = 1; break;
                        case 2: case 3: elemSize = 2; break;
                        case 4: case 5: case 6: case 7: elemSize = 4; break;
                        case 10: case 11: case 12: elemSize = 8; break;
                        default: elemSize = 0; break;
                    }
                    if (elemSize == 0) {
                        fprintf(stderr, "ParseIndex: unknown array element type %u\n", elemType);
                        return false;
                    }
                    if (numElems > fileSize_ / elemSize) return false;
                    if (cursor + numElems * elemSize > fileSize_) return false;
                    cursor += numElems * elemSize;
                }
                break;
            }
            case 10:
            case 11:
            case 12:
                cursor += 8;
                break;
            default:
                cursor += 8;
                break;
        }
    }

    // Parse tensor info
    allTensors_.clear();
    allTensors_.reserve(static_cast<size_t>(tensorCount));
    
    for (uint64_t i = 0; i < tensorCount; ++i) {
        TensorInfo tensor;
        
        uint64_t nameLen = 0;
        if (!ReadAt(cursor, &nameLen, sizeof(nameLen))) return false;
        cursor += sizeof(nameLen);
        
        std::vector<char> nameBuf(static_cast<size_t>(nameLen + 1), 0);
        if (!ReadAt(cursor, nameBuf.data(), static_cast<size_t>(nameLen))) return false;
        cursor += nameLen;
        tensor.name.assign(nameBuf.data(), static_cast<size_t>(nameLen));
        
        uint32_t nDims = 0;
        if (!ReadAt(cursor, &nDims, sizeof(nDims))) return false;
        cursor += sizeof(nDims);
        
        tensor.dimensions.resize(nDims);
        for (uint32_t d = 0; d < nDims; ++d) {
            uint64_t dim = 0;
            if (!ReadAt(cursor, &dim, sizeof(dim))) return false;
            cursor += sizeof(dim);
            tensor.dimensions[d] = dim;
        }
        
        uint32_t typeVal = 0;
        if (!ReadAt(cursor, &typeVal, sizeof(typeVal))) return false;
        cursor += sizeof(typeVal);
        tensor.type = static_cast<Deep2::GGMLType>(typeVal);
        
        if (!ReadAt(cursor, &tensor.offset, sizeof(tensor.offset))) return false;
        cursor += sizeof(tensor.offset);
        
        tensor.size = CalculateTensorBytesStatic(tensor);
        allTensors_.push_back(std::move(tensor));
    }
    
    // Data section: aligned to 32 bytes
    dataOffset_ = (cursor + 31ULL) & ~31ULL;
    
    progress_.tensorsTotal = allTensors_.size();
    uint64_t totalBytes = 0;
    for (const auto& t : allTensors_) totalBytes += t.size;
    progress_.bytesTotal = totalBytes;
    
    return true;
}

bool MoEWeightsLoader::ParseExpertName(const std::string& name, int& layer,
                                        int& expertIdx, ExpertProjection& proj) {
    // Match common MoE expert tensor name patterns:
    //   blk.{L}.ffn_gate_exps.weight  - stacked [numExperts, ...]
    //   blk.{L}.ffn_up_exps.weight    - stacked [numExperts, ...]
    //   blk.{L}.ffn_down_exps.weight  - stacked [numExperts, ...]
    //   blk.{L}.ffn_gate_shexp.weight - shared expert
    //   blk.{L}.ffn_up_shexp.weight
    //   blk.{L}.ffn_down_shexp.weight
    //   blk.{L}.ffn_gate_inp.weight   - router gate
    
    static const std::regex expertRe(R"(blk\.(\d+)\.ffn_(gate|up|down)_exps\.weight)");
    static const std::regex sharedRe(R"(blk\.(\d+)\.ffn_(gate|up|down)_shexp\.weight)");
    static const std::regex gateRe(R"(blk\.(\d+)\.ffn_gate_inp\.weight)");
    
    std::smatch match;
    
    if (std::regex_search(name, match, expertRe)) {
        layer = std::stoi(match[1].str());
        expertIdx = -1;
        std::string p = match[2].str();
        proj = (p == "gate") ? ExpertProjection::Gate :
               (p == "up")   ? ExpertProjection::Up   : ExpertProjection::Down;
        return true;
    }
    
    if (std::regex_search(name, match, sharedRe)) {
        layer = std::stoi(match[1].str());
        expertIdx = -2;
        std::string p = match[2].str();
        proj = (p == "gate") ? ExpertProjection::Gate :
               (p == "up")   ? ExpertProjection::Up   : ExpertProjection::Down;
        return true;
    }
    
    if (std::regex_search(name, match, gateRe)) {
        layer = std::stoi(match[1].str());
        expertIdx = -3;
        proj = ExpertProjection::Gate;
        return true;
    }
    
    return false;
}

size_t MoEWeightsLoader::DiscoverExpertProjections() {
    expertProjections_.clear();
    tensorNameMap_.clear();
    
    std::unordered_set<int> layerSet;
    size_t maxExperts = 0;
    
    for (const auto& tensor : allTensors_) {
        int layer = -1, expertIdx = -1;
        ExpertProjection proj = ExpertProjection::Gate;
        if (!ParseExpertName(tensor.name, layer, expertIdx, proj)) continue;
        if (layer < 0) continue;
        
        ExpertProjectionInfo info;
        info.layerIdx = layer;
        info.expertIdx = expertIdx;
        info.proj = proj;
        info.tensorName = tensor.name;
        info.type = tensor.type;
        info.fileOffset = dataOffset_ + tensor.offset;
        info.sizeBytes = tensor.size;
        
        // Calculate per-expert slice size
        // GGUF stores dims in reverse order from numpy/PyTorch:
        //   [hidden, expertDim, numExperts] — last dim is the expert count
        if (tensor.dimensions.size() >= 3 && expertIdx == -1) {
            info.numExperts = (size_t)tensor.dimensions.back();
            size_t elementsPerExpert = 1;
            for (size_t d = 0; d + 1 < tensor.dimensions.size(); ++d) {
                elementsPerExpert *= (size_t)tensor.dimensions[d];
            }
            size_t blockSize = GGMLTypeBlockSizeStatic(tensor.type);
            size_t typeSize = GGMLTypeSizeStatic(tensor.type);
            size_t numBlocks = (elementsPerExpert + blockSize - 1) / blockSize;
            info.bytesPerExpert = numBlocks * typeSize;
            if (info.numExperts > maxExperts) maxExperts = info.numExperts;
        } else {
            info.numExperts = 1;
            info.bytesPerExpert = (size_t)tensor.size;
        }
        
        expertProjections_.push_back(std::move(info));
        tensorNameMap_[tensor.name] = expertProjections_.size() - 1;
        layerSet.insert(layer);
    }
    
    numExpertLayers_ = layerSet.size();
    expertsPerLayer_ = maxExperts;
    return expertProjections_.size();
}

const std::vector<ExpertProjectionInfo>& MoEWeightsLoader::GetExpertProjections() const {
    return expertProjections_;
}

const void* MoEWeightsLoader::LoadExpert(int layer, int expert) {
    if (progress_.cancelled.load()) return nullptr;
    
    CacheKey key{layer, expert};
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            it->second.lastAccess = std::chrono::steady_clock::now();
            it->second.accessCount++;
            std::lock_guard<std::mutex> sl(statsMutex_);
            stats_.cacheHits++;
            return it->second.data;
        }
    }
    return LoadExpertInternal(layer, expert);
}

const void* MoEWeightsLoader::LoadExpertInternal(int layer, int expert) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Find gate/up/down for this layer (gate is optional for ReLU² FFN)
    const ExpertProjectionInfo* gateInfo = nullptr;
    const ExpertProjectionInfo* upInfo = nullptr;
    const ExpertProjectionInfo* downInfo = nullptr;
    
    for (const auto& info : expertProjections_) {
        if (info.layerIdx != layer) continue;
        if (info.expertIdx != -1) continue;  // Only stacked expert tensors
        switch (info.proj) {
            case ExpertProjection::Gate: gateInfo = &info; break;
            case ExpertProjection::Up:   upInfo = &info;   break;
            case ExpertProjection::Down: downInfo = &info; break;
        }
    }
    
    // Gate is optional (Nemotron uses ReLU² FFN with only up+down)
    if (!upInfo || !downInfo) return nullptr;
    
    size_t gateBytes = gateInfo ? gateInfo->bytesPerExpert : 0;
    size_t expertBytes = gateBytes + upInfo->bytesPerExpert + downInfo->bytesPerExpert;
    if (expertBytes == 0) return nullptr;
    
    void* buffer = _aligned_malloc(expertBytes, 32);
    if (!buffer) return nullptr;
    
    // Per-expert offset within the stacked tensor
    // For up_exps [numExperts, hidden, expertDim]: offset = expert * hidden * expertDim * typeSize
    // For gate_exps (if present): same layout as up
    uint64_t upExpertOffset = (uint64_t)expert * upInfo->bytesPerExpert;
    uint64_t gateExpertOffset = gateInfo ? (uint64_t)expert * gateInfo->bytesPerExpert : 0;
    uint64_t downExpertOffset = (uint64_t)expert * downInfo->bytesPerExpert;
    
    bool ok = true;
    size_t offset = 0;
    
    // Read gate (if present)
    if (gateInfo && ok) {
        ok = ReadAt(gateInfo->fileOffset + gateExpertOffset,
                     buffer, gateInfo->bytesPerExpert);
        offset += gateInfo->bytesPerExpert;
    }
    // Read up
    if (ok) {
        ok = ReadAt(upInfo->fileOffset + upExpertOffset,
                    (uint8_t*)buffer + offset,
                    upInfo->bytesPerExpert);
        offset += upInfo->bytesPerExpert;
    }
    // Read down
    if (ok) {
        ok = ReadAt(downInfo->fileOffset + downExpertOffset,
                    (uint8_t*)buffer + offset,
                    downInfo->bytesPerExpert);
    }
    
    if (!ok) {
        _aligned_free(buffer);
        return nullptr;
    }
    
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        while (currentCacheBytes_ + expertBytes > maxCacheBytes_ && !cache_.empty()) {
            EvictLRU();
        }
        ExpertCacheEntry entry;
        entry.data = buffer;
        entry.bytes = expertBytes;
        entry.lastAccess = std::chrono::steady_clock::now();
        entry.accessCount = 1;
        entry.pinned = false;
        cache_[CacheKey{layer, expert}] = std::move(entry);
        currentCacheBytes_ += expertBytes;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double loadMs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
    
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.totalLoads++;
        stats_.cacheMisses++;
        stats_.bytesStreamed += expertBytes;
        stats_.avgLoadTimeMs = (stats_.avgLoadTimeMs * (stats_.totalLoads - 1) + loadMs) / stats_.totalLoads;
    }
    
    progress_.bytesStreamed += expertBytes;
    progress_.tensorsLoaded++;
    progress_.lastLayer = layer;
    progress_.lastExpert = expert;
    
    return buffer;
}

bool MoEWeightsLoader::LoadExpertDirect(int layer, int expert, void* buffer, size_t bufferSize) {
    if (!buffer || bufferSize == 0) return false;
    
    const ExpertProjectionInfo* gateInfo = nullptr;
    const ExpertProjectionInfo* upInfo = nullptr;
    const ExpertProjectionInfo* downInfo = nullptr;
    
    for (const auto& info : expertProjections_) {
        if (info.layerIdx != layer) continue;
        if (info.expertIdx != -1) continue;
        switch (info.proj) {
            case ExpertProjection::Gate: gateInfo = &info; break;
            case ExpertProjection::Up:   upInfo = &info;   break;
            case ExpertProjection::Down: downInfo = &info; break;
        }
    }
    
    if (!upInfo || !downInfo) return false;
    
    size_t gateBytes = gateInfo ? gateInfo->bytesPerExpert : 0;
    size_t totalBytes = gateBytes + upInfo->bytesPerExpert + downInfo->bytesPerExpert;
    if (bufferSize < totalBytes) return false;
    
    uint64_t upExpertOffset = (uint64_t)expert * upInfo->bytesPerExpert;
    uint64_t gateExpertOffset = gateInfo ? (uint64_t)expert * gateInfo->bytesPerExpert : 0;
    uint64_t downExpertOffset = (uint64_t)expert * downInfo->bytesPerExpert;
    
    bool ok = true;
    size_t offset = 0;
    if (gateInfo && ok) {
        ok = ReadAt(gateInfo->fileOffset + gateExpertOffset, buffer, gateInfo->bytesPerExpert);
        offset += gateInfo->bytesPerExpert;
    }
    if (ok) {
        ok = ReadAt(upInfo->fileOffset + upExpertOffset,
                    (uint8_t*)buffer + offset, upInfo->bytesPerExpert);
        offset += upInfo->bytesPerExpert;
    }
    if (ok) {
        ok = ReadAt(downInfo->fileOffset + downExpertOffset,
                    (uint8_t*)buffer + offset, downInfo->bytesPerExpert);
    }
    return ok;
}

bool MoEWeightsLoader::LoadRouterGate(int layer, std::vector<float>& outWeights) {
    std::string name = "blk." + std::to_string(layer) + ".ffn_gate_inp.weight";
    for (const auto& tensor : allTensors_) {
        if (tensor.name == name) {
            size_t numElements = 1;
            for (auto d : tensor.dimensions) numElements *= (size_t)d;
            // For non-F32 gate, we'd need dequant; for now assume F32
            if (tensor.type != GGMLType::GGML_TYPE_F32) return false;
            outWeights.resize(numElements);
            return ReadAt(dataOffset_ + tensor.offset, outWeights.data(),
                          numElements * sizeof(float));
        }
    }
    return false;
}

bool MoEWeightsLoader::LoadSharedExpert(int layer, void* buffer, size_t bufferSize) {
    size_t totalRead = 0;
    for (int p = 0; p < 3; ++p) {
        ExpertProjection proj = (ExpertProjection)p;
        const char* suffix = (proj == ExpertProjection::Gate) ? "gate" :
                              (proj == ExpertProjection::Up)   ? "up"   : "down";
        std::string name = "blk." + std::to_string(layer) + ".ffn_" + 
                           std::string(suffix) + "_shexp.weight";
        for (const auto& tensor : allTensors_) {
            if (tensor.name == name) {
                if (totalRead + tensor.size > bufferSize) return false;
                if (!ReadAt(dataOffset_ + tensor.offset,
                            (uint8_t*)buffer + totalRead,
                            (size_t)tensor.size)) return false;
                totalRead += (size_t)tensor.size;
                break;
            }
        }
    }
    return totalRead > 0;
}

void MoEWeightsLoader::SetMaxCacheSize(size_t bytes) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    maxCacheBytes_ = bytes;
    while (currentCacheBytes_ > maxCacheBytes_ && !cache_.empty()) {
        EvictLRU();
    }
}

size_t MoEWeightsLoader::GetCacheSize() const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return currentCacheBytes_;
}

void MoEWeightsLoader::EvictLRU() {
    auto oldest = cache_.end();
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->second.pinned) continue;
        if (oldest == cache_.end() || it->second.lastAccess < oldest->second.lastAccess) {
            oldest = it;
        }
    }
    if (oldest != cache_.end()) {
        if (oldest->second.data) _aligned_free(oldest->second.data);
        currentCacheBytes_ -= oldest->second.bytes;
        cache_.erase(oldest);
        std::lock_guard<std::mutex> sl(statsMutex_);
        stats_.evictions++;
    }
}

void MoEWeightsLoader::Pin(int layer, int expert) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    CacheKey key{layer, expert};
    auto it = cache_.find(key);
    if (it != cache_.end()) it->second.pinned = true;
}

void MoEWeightsLoader::Unpin(int layer, int expert) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    CacheKey key{layer, expert};
    auto it = cache_.find(key);
    if (it != cache_.end()) it->second.pinned = false;
}

size_t MoEWeightsLoader::GetNumExpertLayers() const { return numExpertLayers_; }
size_t MoEWeightsLoader::GetExpertsPerLayer() const { return expertsPerLayer_; }

MoEWeightsLoader::Stats MoEWeightsLoader::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void MoEWeightsLoader::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

} // namespace Deep2

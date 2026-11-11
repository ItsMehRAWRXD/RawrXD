// ============================================================================
// ModelLoader.cpp — Model Loading Pipeline Implementation
// ============================================================================

#include "ModelLoader.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <fileapi.h>
#endif

namespace rawr {

// GGUF magic and header constants
constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF"
constexpr uint32_t GGUF_VERSION = 3;

#pragma pack(push, 1)
struct GGUFFileHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensorCount;
    uint64_t metadataSize;
};
#pragma pack(pop)

ModelLoader& ModelLoader::Get() {
    static ModelLoader instance;
    return instance;
}

bool ModelLoader::Initialize() {
    RawrRuntime::Get().Log(LogLevel::Info, "ModelLoader initialized");
    return true;
}

void ModelLoader::Shutdown() {
    Unload();
}

bool ModelLoader::Load(const char* path, LoadProgressCallback onProgress) {
    if (m_loaded) Unload();
    if (!path) return false;

    RawrRuntime::Get().Log(LogLevel::Info, "Loading model...");

#ifdef _WIN32
    // Memory-map the GGUF file
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        RawrRuntime::Get().Log(LogLevel::Error, "Failed to open model file");
        return false;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    m_fileSize = fileSize.QuadPart;

    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    m_fileData = (uint8_t*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    if (!m_fileData) {
        RawrRuntime::Get().Log(LogLevel::Error, "Failed to map model file");
        return false;
    }
#else
    // Fallback: read file into memory
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    m_fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    m_fileData = new uint8_t[m_fileSize];
    fread(m_fileData, 1, m_fileSize, f);
    fclose(f);
#endif

    // Parse header
    if (!ParseGGUFHeader(m_fileData, m_fileSize)) {
        RawrRuntime::Get().Log(LogLevel::Error, "Invalid GGUF file");
        Unload();
        return false;
    }

    // Load tensors
    if (!LoadTensors(m_fileData, m_fileSize, onProgress)) {
        RawrRuntime::Get().Log(LogLevel::Error, "Failed to load tensors");
        Unload();
        return false;
    }

    m_loaded = true;
    RawrRuntime::Get().Log(LogLevel::Info, "Model loaded successfully");
    return true;
}

void ModelLoader::Unload() {
    if (m_fileData) {
#ifdef _WIN32
        UnmapViewOfFile(m_fileData);
#else
        delete[] m_fileData;
#endif
        m_fileData = nullptr;
    }
    m_tensors.clear();
    m_loaded = false;
    m_fileSize = 0;
    m_totalWeightSize = 0;
    m_loadedSize = 0;
}

bool ModelLoader::ParseGGUFHeader(const uint8_t* data, uint64_t size) {
    if (size < sizeof(GGUFFileHeader)) return false;

    const auto* header = reinterpret_cast<const GGUFFileHeader*>(data);
    if (header->magic != GGUF_MAGIC) {
        RawrRuntime::Get().Log(LogLevel::Error, "Not a valid GGUF file");
        return false;
    }

    // Parse metadata key-value pairs
    uint64_t offset = sizeof(GGUFFileHeader);
    for (uint64_t i = 0; i < header->metadataSize && offset < size; ++i) {
        // Skip key
        uint64_t keyLen = *reinterpret_cast<const uint64_t*>(data + offset);
        offset += sizeof(uint64_t) + keyLen;

        // Skip value (simplified — real impl reads typed values)
        uint32_t valueType = *reinterpret_cast<const uint32_t*>(data + offset);
        offset += sizeof(uint32_t);

        switch (valueType) {
            case 0: case 1: case 2: case 3: case 4: // uint8, int8, uint16, int16, uint32
                offset += 4; break;
            case 5: case 6: // int32, float32
                offset += 4; break;
            case 7: case 8: // bool, string
                if (valueType == 8) { // string
                    uint64_t strLen = *reinterpret_cast<const uint64_t*>(data + offset);
                    offset += sizeof(uint64_t) + strLen;
                } else {
                    offset += 1;
                }
                break;
            case 9: case 10: // array, uint64
                offset += 8; break;
            case 11: case 12: // int64, float64
                offset += 8; break;
            default:
                offset += 4; break;
        }
    }

    // Read tensor info count
    m_tensors.reserve(header->tensorCount);
    return true;
}

bool ModelLoader::LoadTensors(const uint8_t* data, uint64_t size, LoadProgressCallback onProgress) {
    const auto* header = reinterpret_cast<const GGUFFileHeader*>(data);

    // Skip to tensor info section
    uint64_t offset = sizeof(GGUFFileHeader) + header->metadataSize;

    for (uint64_t i = 0; i < header->tensorCount; ++i) {
        if (offset + 28 > size) break;

        TensorInfo info;
        info.nDims = *reinterpret_cast<const uint32_t*>(data + offset);
        offset += 4;

        for (uint32_t d = 0; d < info.nDims; ++d) {
            info.shape[d] = *reinterpret_cast<const uint64_t*>(data + offset);
            offset += 8;
        }
        for (uint32_t d = info.nDims; d < 4; ++d) {
            info.shape[d] = 1;
        }

        info.type = static_cast<TensorType>(*reinterpret_cast<const uint32_t*>(data + offset));
        offset += 4;

        info.offset = *reinterpret_cast<const uint64_t*>(data + offset);
        offset += 8;

        // Read name
        uint64_t nameLen = *reinterpret_cast<const uint64_t*>(data + offset);
        offset += sizeof(uint64_t);
        info.name.assign(reinterpret_cast<const char*>(data + offset), nameLen);
        offset += nameLen;

        // Calculate size
        uint64_t tensorSize = info.shape[0];
        for (uint32_t d = 1; d < info.nDims; ++d) {
            tensorSize *= info.shape[d];
        }
        // Adjust for quantization
        switch (info.type) {
            case TensorType::Q4_0: tensorSize = tensorSize / 2 + sizeof(float); break;
            case TensorType::Q4_K: tensorSize = (tensorSize + 255) / 256 * 288; break;
            default: tensorSize *= 4; break;  // F32
        }
        info.size = tensorSize;
        info.data = nullptr;
        m_totalWeightSize += tensorSize;

        m_tensors.push_back(info);

        if (onProgress) {
            onProgress(static_cast<uint32_t>(i + 1),
                      static_cast<uint32_t>(header->tensorCount),
                      info.name.c_str());
        }
    }

    return true;
}

const TensorInfo* ModelLoader::GetTensor(const char* name) const {
    if (!name) return nullptr;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& t : m_tensors) {
        if (t.name == name) return &t;
    }
    return nullptr;
}

const TensorInfo* ModelLoader::GetTensorByIndex(uint32_t index) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (index >= m_tensors.size()) return nullptr;
    return &m_tensors[index];
}

void* ModelLoader::GetTensorData(const char* name) const {
    auto* info = GetTensor(name);
    if (!info) return nullptr;
    if (!info->data && m_fileData) {
        // Lazy load: point to file data
        return m_fileData + info->offset;
    }
    return info->data;
}

const float* ModelLoader::GetWeights(const char* layer, const char* type) const {
    // Build tensor name: "blk.{layer}.{type}.weight"
    std::string tensorName = "blk.";
    tensorName += layer;
    tensorName += ".";
    tensorName += type;
    tensorName += ".weight";

    return static_cast<const float*>(GetTensorData(tensorName.c_str()));
}

} // namespace rawr

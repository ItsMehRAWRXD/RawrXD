#include "../../native_gguf_loader.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <windows.h>

namespace {
constexpr uint64_t kMaxMetadataCount = 1ULL << 20;      // 1,048,576 entries
constexpr uint64_t kMaxTensorCount = 1ULL << 20;        // 1,048,576 tensors
constexpr uint64_t kMaxKeyLength = 1ULL << 20;          // 1 MiB
constexpr uint64_t kMaxStringLength = 1ULL << 24;       // 16 MiB
constexpr uint64_t kMaxArrayLength = 1ULL << 28;        // 256 MiB
constexpr uint64_t kMaxTensorNameLength = 1ULL << 20;   // 1 MiB
constexpr uint32_t kMaxTensorDimensions = 8;

std::atomic<uint64_t> g_openCalls{0};
std::atomic<uint64_t> g_parseHeaderCalls{0};
std::atomic<uint64_t> g_parseMetadataCalls{0};
std::atomic<uint64_t> g_parseTensorInfoCalls{0};
std::atomic<uint64_t> g_rejectCount{0};
std::atomic<uint64_t> g_tensorLookupMisses{0};

template <typename T>
bool readExact(std::ifstream& file, T* out)
{
    file.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(sizeof(T)));
    return file.good();
}

bool readBlob(std::ifstream& file, char* dst, uint64_t size)
{
    if (size == 0) {
        return true;
    }
    if (!dst) {
        return false;
    }
    file.read(dst, static_cast<std::streamsize>(size));
    return file.good();
}
} // namespace

namespace GGUFUtils {
uint32_t GetDataTypeSize(uint32_t type)
{
    switch (type) {
        case 0:
            return 1; // F32
        case 1:
            return 2; // F16
        case 2:
            return 4; // Q4_0
        case 3:
            return 4; // Q4_1
        case 6:
            return 2; // Q4_2
        case 7:
            return 2; // Q4_3
        case 8:
            return 1; // Q8_0
        case 9:
            return 1; // Q8_1
        case 10:
            return 4; // Q2_K
        case 11:
            return 2; // Q3_K
        case 12:
            return 4; // Q4_K
        case 13:
            return 2; // Q5_K
        case 14:
            return 4; // Q6_K
        case 15:
            return 2; // Q8_K
        case 16:
            return 4; // I8
        case 17:
            return 2; // I16
        case 18:
            return 4; // I32
        case 19:
            return 1; // I8
        case 20:
            return 2; // I16
        case 21:
            return 4; // I32
        case 22:
            return 1; // F8_E4M3
        case 23:
            return 2; // F8_E5M2
        default:
            return 1;
    }
}
} // namespace GGUFUtils

NativeGGUFLoader::NativeGGUFLoader()
    : fileHandle(INVALID_HANDLE_VALUE),
      mappingHandle(nullptr),
      mappedBase(nullptr),
      mappedSize(0),
      version(0),
      metadataCount(0),
      tensorCount(0)
{}

NativeGGUFLoader::~NativeGGUFLoader()
{
    Close();
}

bool NativeGGUFLoader::OpenMemoryMap(const std::string& filePath)
{
    fileHandle = static_cast<void*>(CreateFileA(filePath.c_str(),
                                                GENERIC_READ,
                                                FILE_SHARE_READ,
                                                nullptr,
                                                OPEN_EXISTING,
                                                FILE_ATTRIBUTE_NORMAL,
                                                nullptr));
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(static_cast<HANDLE>(fileHandle), &fileSize) || fileSize.QuadPart <= 0) {
        CloseMemoryMap();
        return false;
    }

    mappingHandle = static_cast<void*>(CreateFileMappingA(static_cast<HANDLE>(fileHandle), nullptr, PAGE_READONLY, 0, 0, nullptr));
    if (!mappingHandle) {
        CloseMemoryMap();
        return false;
    }

    mappedBase = static_cast<const uint8_t*>(MapViewOfFile(static_cast<HANDLE>(mappingHandle), FILE_MAP_READ, 0, 0, 0));
    if (!mappedBase) {
        CloseMemoryMap();
        return false;
    }

    mappedSize = static_cast<uint64_t>(fileSize.QuadPart);
    return true;
}

void NativeGGUFLoader::CloseMemoryMap()
{
    if (mappedBase) {
        UnmapViewOfFile(mappedBase);
        mappedBase = nullptr;
    }
    if (mappingHandle) {
        CloseHandle(static_cast<HANDLE>(mappingHandle));
        mappingHandle = nullptr;
    }
    if (fileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(static_cast<HANDLE>(fileHandle));
        fileHandle = INVALID_HANDLE_VALUE;
    }
    mappedSize = 0;
}

bool NativeGGUFLoader::Open(const std::string& filePath)
{
    g_openCalls.fetch_add(1, std::memory_order_relaxed);
    Close();

    if (!OpenMemoryMap(filePath)) {
        return false;
    }

    file.open(filePath, std::ios::binary);
    if (!file.is_open()) {
        CloseMemoryMap();
        return false;
    }

    metadata.clear();
    tensors.clear();
    version = 0;
    metadataCount = 0;
    tensorCount = 0;
    return true;
}

void NativeGGUFLoader::Close()
{
    if (file.is_open()) {
        file.close();
    }
    CloseMemoryMap();
    metadata.clear();
    tensors.clear();
    version = 0;
    metadataCount = 0;
    tensorCount = 0;
}

bool NativeGGUFLoader::ParseHeader()
{
    g_parseHeaderCalls.fetch_add(1, std::memory_order_relaxed);
    if (!file) {
        g_rejectCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    char magic[4]{};
    file.read(magic, 4);
    if (std::memcmp(magic, "GGUF", 4) != 0) {
        g_rejectCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (!readExact(file, &version) || !readExact(file, &tensorCount) || !readExact(file, &metadataCount)) {
        g_rejectCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (tensorCount > kMaxTensorCount || metadataCount > kMaxMetadataCount) {
        g_rejectCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    return true;
}

bool NativeGGUFLoader::ParseMetadata()
{
    g_parseMetadataCalls.fetch_add(1, std::memory_order_relaxed);
    if (!file) {
        g_rejectCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    metadata.clear();
    metadata.resize(static_cast<size_t>(metadataCount));

    for (auto& meta : metadata) {
        uint64_t keyLen = 0;
        if (!readExact(file, &keyLen) || keyLen > kMaxKeyLength) {
            g_rejectCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        meta.key.resize(static_cast<size_t>(keyLen));
        if (!readBlob(file, keyLen ? &meta.key[0] : nullptr, keyLen)) {
            g_rejectCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        uint32_t type = 0;
        if (!readExact(file, &type)) {
            g_rejectCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        switch (type) {
            case 0: {
                uint64_t len = 0;
                if (!readExact(file, &len) || len > kMaxStringLength) {
                    g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                std::string val(static_cast<size_t>(len), '\0');
                if (!readBlob(file, len ? &val[0] : nullptr, len)) {
                    g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                meta.value = std::move(val);
                break;
            }
            case 1: {
                int64_t val = 0;
                if (!readExact(file, &val)) {
                    g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                meta.value = val;
                break;
            }
            case 2: {
                float val = 0.0f;
                if (!readExact(file, &val)) {
                    g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                meta.value = val;
                break;
            }
            case 3: {
                bool val = false;
                if (!readExact(file, &val)) {
                    g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                meta.value = val;
                break;
            }
            case 4: {
                uint32_t arrType = 0;
                uint64_t arrLen = 0;
                if (!readExact(file, &arrType) || !readExact(file, &arrLen) || arrLen > kMaxArrayLength) {
                    g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                std::vector<uint8_t> arr(static_cast<size_t>(arrLen));
                if (!readBlob(file, arrLen ? reinterpret_cast<char*>(&arr[0]) : nullptr, arrLen)) {
                    g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
                meta.value = std::move(arr);
                (void)arrType;
                break;
            }
            default:
                g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                return false;
        }
    }
    return true;
}

bool NativeGGUFLoader::ParseTensorInfo()
{
    g_parseTensorInfoCalls.fetch_add(1, std::memory_order_relaxed);
    if (!file) {
        g_rejectCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    tensors.clear();
    tensors.resize(static_cast<size_t>(tensorCount));
    for (auto& tensor : tensors) {
        uint64_t nameLen = 0;
        if (!readExact(file, &nameLen) || nameLen > kMaxTensorNameLength) {
            g_rejectCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        tensor.name.resize(static_cast<size_t>(nameLen));
        if (!readBlob(file, nameLen ? &tensor.name[0] : nullptr, nameLen)) {
            g_rejectCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        if (!readExact(file, &tensor.dimensions) || tensor.dimensions > kMaxTensorDimensions) {
            g_rejectCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        tensor.shape.resize(static_cast<size_t>(tensor.dimensions));
        for (auto& dim : tensor.shape) {
            if (!readExact(file, &dim)) {
                g_rejectCount.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
        }

        if (!readExact(file, &tensor.type) || !readExact(file, &tensor.offset)) {
            g_rejectCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }
    return true;
}

bool NativeGGUFLoader::LoadTensorData(const std::string& tensorName, std::vector<uint8_t>& data)
{
    uint64_t size = 0;
    const uint8_t* ptr = GetTensorDataPointer(tensorName, &size);
    if (!ptr || size == 0) {
        return false;
    }

    data.assign(ptr, ptr + size);
    return true;
}

const uint8_t* NativeGGUFLoader::GetTensorDataPointer(const std::string& tensorName, uint64_t* sizeBytes) const
{
    if (!mappedBase || mappedSize == 0) {
        return nullptr;
    }

    auto it = std::find_if(tensors.begin(), tensors.end(),
                           [&](const NativeGGUFTensorInfo& t) { return t.name == tensorName; });
    if (it == tensors.end()) {
        g_tensorLookupMisses.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    uint64_t size = 1;
    for (uint64_t dim : it->shape) {
        if (dim == 0 || size > std::numeric_limits<uint64_t>::max() / dim) {
            g_rejectCount.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        size *= dim;
    }
    const uint64_t dtype = GGUFUtils::GetDataTypeSize(it->type);
    if (dtype == 0 || size > std::numeric_limits<uint64_t>::max() / dtype) {
        g_rejectCount.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    size *= dtype;

    if (it->offset >= mappedSize || size > mappedSize - it->offset) {
        return nullptr;
    }

    if (sizeBytes) {
        *sizeBytes = size;
    }
    return mappedBase + it->offset;
}

extern "C" unsigned __int64 rawrxd_native_gguf_loader_stub_stats()
{
    // [63:48] reject, [47:32] lookup_miss, [31:24] parse_tensor, [23:16] parse_meta,
    // [15:8] parse_header, [7:0] open_calls
    const uint64_t reject = g_rejectCount.load(std::memory_order_relaxed) & 0xFFFFu;
    const uint64_t miss = g_tensorLookupMisses.load(std::memory_order_relaxed) & 0xFFFFu;
    const uint64_t tensor = g_parseTensorInfoCalls.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t meta = g_parseMetadataCalls.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t header = g_parseHeaderCalls.load(std::memory_order_relaxed) & 0xFFu;
    const uint64_t open = g_openCalls.load(std::memory_order_relaxed) & 0xFFu;
    return (reject << 48) | (miss << 32) | (tensor << 24) | (meta << 16) | (header << 8) | open;
}

bool NativeGGUFLoader::IsMemoryMapped() const
{
    return mappedBase != nullptr && mappedSize > 0;
}

uint64_t NativeGGUFLoader::GetMappedSize() const
{
    return mappedSize;
}

const std::vector<NativeGGUFTensorInfo>& NativeGGUFLoader::GetTensors() const
{
    return tensors;
}

const std::vector<NativeGGUFMetadata>& NativeGGUFLoader::GetMetadata() const
{
    return metadata;
}

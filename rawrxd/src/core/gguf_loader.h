// ============================================================================
// gguf_loader.h — Canonical GGUF file loader interface (RawrXD v14.7)
//
// Provides:
//   - GGUFLoader        : simple per-TU loader (header-only, no link dep)
//   - GGUFMetadata      : model architecture / vocab metadata
//   - GGUF_MAGIC        : 'GGUF' magic constant
//
// Design:
//   - Header-only for compile-time inclusion in any .cpp
//   - No std::function, no exceptions inside hot path
//   - Thread-safe at instance level (one loader per model)
//
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>

namespace RawrXD {

// ============================================================================
// Magic
// ============================================================================
constexpr uint32_t GGUF_MAGIC = 0x46475547u; // 'GGUF' little-endian

// ============================================================================
// GGUFMetadata — Architecture and vocabulary metadata extracted from header
// ============================================================================
struct GGUFMetadata {
    uint32_t    version         = 0;    // GGUF spec version
    uint32_t    tensor_count    = 0;    // Number of tensors
    uint64_t    param_count     = 0;    // Total parameter count (if known)

    // Architecture
    std::string architecture_type;      // e.g. "llama", "gpt2", "mpt"
    uint32_t    vocab_size      = 0;
    uint32_t    context_length  = 0;
    uint32_t    embedding_dim   = 0;    // e.g. hidden_size
    uint32_t    num_layers       = 0;   // n_layers
    uint32_t    num_heads        = 0;   // n_heads
    uint32_t    num_kv_heads     = 0;   // n_kv_heads
    uint32_t    intermediate_size = 0;  // feed-forward dim
    float       rms_norm_eps    = 1e-5f;
    float       rope_theta      = 10000.0f;
    float       rope_scale      = 1.0f;

    // Quantization
    std::string quantization;           // e.g. "Q4_0", "Q8_0", "F16"
};

// ============================================================================
// TensorInfo — Minimal descriptor (name + shape + type + offset)
// ============================================================================
struct TensorInfo {
    char        name[128] = {};
    uint32_t    dims      = 0;
    uint64_t    shape[4]  = {0,0,0,0};
    uint32_t    type      = 0;          // GGML type enum value
    uint64_t    offset    = 0;          // Byte offset in file
    uint64_t    byteSize  = 0;          // Size on disk
};

// ============================================================================
// GGUFLoader — Simple file-based loader (one instance per model)
// ============================================================================
class GGUFLoader {
public:
    GGUFLoader() = default;
    ~GGUFLoader() { Close(); }

    // Disable copy; allow move
    GGUFLoader(const GGUFLoader&) = delete;
    GGUFLoader& operator=(const GGUFLoader&) = delete;
    GGUFLoader(GGUFLoader&&) noexcept = default;
    GGUFLoader& operator=(GGUFLoader&&) noexcept = default;

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Open(const std::string& filePath) {
        Close();
        m_path = filePath;
        m_hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_hFile == INVALID_HANDLE_VALUE) {
            m_hFile = nullptr;
            m_path.clear();
            return false;
        }
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(m_hFile, &sz)) {
            CloseHandle(m_hFile);
            m_hFile = nullptr;
            m_path.clear();
            return false;
        }
        m_fileSize = static_cast<uint64_t>(sz.QuadPart);
        return true;
    }

    void Close() {
        Unmap();
        if (m_hFile) {
            CloseHandle(m_hFile);
            m_hFile = nullptr;
        }
        m_path.clear();
        m_fileSize = 0;
        m_metaCount = 0;
        m_meta = GGUFMetadata{};
        m_tensors.clear();
    }

    bool ParseHeader() {
        if (!m_hFile) return false;
        uint32_t magic = 0;
        DWORD read = 0;
        if (!ReadFile(m_hFile, &magic, sizeof(magic), &read, nullptr) || read != sizeof(magic))
            return false;
        if (magic != GGUF_MAGIC) return false;
        // Version
        uint32_t version = 0;
        if (!ReadFile(m_hFile, &version, sizeof(version), &read, nullptr) || read != sizeof(version))
            return false;
        m_meta.version = version;
        // tensor_count, n_kv (GGUF v3: u64)
        uint64_t tensor_count_u64 = 0;
        if (!ReadFile(m_hFile, &tensor_count_u64, sizeof(tensor_count_u64), &read, nullptr) || read != sizeof(tensor_count_u64))
            return false;
        m_meta.tensor_count = static_cast<uint32_t>(tensor_count_u64);
        // metadata_kv_count
        uint64_t meta_count_u64 = 0;
        if (!ReadFile(m_hFile, &meta_count_u64, sizeof(meta_count_u64), &read, nullptr) || read != sizeof(meta_count_u64))
            return false;
        m_metaCount = meta_count_u64;
        return true;
    }

    bool ParseMetadata() {
        if (!m_hFile) return false;
        // File pointer is already past header (24 bytes) after ParseHeader()
        for (uint64_t i = 0; i < m_metaCount; ++i) {
            if (!SkipKvPair()) return false;
        }
        return true;
    }

    bool ParseTensorInfo() {
        if (!m_hFile) return false;
        m_tensors.clear();
        m_tensors.reserve(m_meta.tensor_count);
        for (uint32_t i = 0; i < m_meta.tensor_count; ++i) {
            TensorInfo t{};
            // name_len (u64) + name
            uint64_t nameLen = 0;
            DWORD read = 0;
            if (!ReadFile(m_hFile, &nameLen, sizeof(nameLen), &read, nullptr) || read != sizeof(nameLen))
                return false;
            if (nameLen >= sizeof(t.name)) nameLen = sizeof(t.name) - 1;
            if (!ReadFile(m_hFile, t.name, static_cast<DWORD>(nameLen), &read, nullptr) || read != static_cast<DWORD>(nameLen))
                return false;
            t.name[nameLen] = '\0';
            // n_dims (u32)
            if (!ReadFile(m_hFile, &t.dims, sizeof(t.dims), &read, nullptr) || read != sizeof(t.dims))
                return false;
            if (t.dims > 4) t.dims = 4;
            // shape (u64 * dims)
            for (uint32_t d = 0; d < t.dims; ++d) {
                if (!ReadFile(m_hFile, &t.shape[d], sizeof(t.shape[d]), &read, nullptr) || read != sizeof(t.shape[d]))
                    return false;
            }
            // type (u32)
            if (!ReadFile(m_hFile, &t.type, sizeof(t.type), &read, nullptr) || read != sizeof(t.type))
                return false;
            // offset (u64)
            if (!ReadFile(m_hFile, &t.offset, sizeof(t.offset), &read, nullptr) || read != sizeof(t.offset))
                return false;
            // Compute byteSize
            uint64_t elemCount = 1;
            for (uint32_t d = 0; d < t.dims; ++d) elemCount *= t.shape[d];
            switch (t.type) {
                case 0: t.byteSize = elemCount * 4; break; // F32
                case 1: t.byteSize = elemCount * 2; break; // F16
                default: t.byteSize = elemCount * 4; break; // fallback
            }
            m_tensors.push_back(t);
        }
        return true;
    }

private:
    bool SkipKvPair() {
        // key_len (u64) + key string
        uint64_t keyLen = 0;
        DWORD read = 0;
        if (!ReadFile(m_hFile, &keyLen, sizeof(keyLen), &read, nullptr) || read != sizeof(keyLen))
            return false;
        if (keyLen > 4096) return false; // sanity
        std::vector<char> keyBuf(keyLen + 1);
        if (!ReadFile(m_hFile, keyBuf.data(), static_cast<DWORD>(keyLen), &read, nullptr) || read != static_cast<DWORD>(keyLen))
            return false;
        // value_type (u32)
        uint32_t valType = 0;
        if (!ReadFile(m_hFile, &valType, sizeof(valType), &read, nullptr) || read != sizeof(valType))
            return false;
        return SkipValue(valType);
    }

    bool SkipValue(uint32_t valType) {
        DWORD read = 0;
        switch (valType) {
            case 0: case 1: case 7: { // uint8, int8, bool
                uint8_t tmp; return ReadFile(m_hFile, &tmp, sizeof(tmp), &read, nullptr) && read == sizeof(tmp);
            }
            case 2: case 3: { // uint16, int16
                uint16_t tmp; return ReadFile(m_hFile, &tmp, sizeof(tmp), &read, nullptr) && read == sizeof(tmp);
            }
            case 4: case 5: case 6: { // uint32, int32, float32
                uint32_t tmp; return ReadFile(m_hFile, &tmp, sizeof(tmp), &read, nullptr) && read == sizeof(tmp);
            }
            case 10: case 11: case 12: { // uint64, int64, float64
                uint64_t tmp; return ReadFile(m_hFile, &tmp, sizeof(tmp), &read, nullptr) && read == sizeof(tmp);
            }
            case 8: { // string
                uint64_t strLen = 0;
                if (!ReadFile(m_hFile, &strLen, sizeof(strLen), &read, nullptr) || read != sizeof(strLen)) return false;
                if (strLen > 0) {
                    std::vector<char> buf(strLen);
                    if (!ReadFile(m_hFile, buf.data(), static_cast<DWORD>(strLen), &read, nullptr) || read != static_cast<DWORD>(strLen)) return false;
                }
                return true;
            }
            case 9: { // array
                uint32_t arrType = 0;
                if (!ReadFile(m_hFile, &arrType, sizeof(arrType), &read, nullptr) || read != sizeof(arrType)) return false;
                uint64_t arrLen = 0;
                if (!ReadFile(m_hFile, &arrLen, sizeof(arrLen), &read, nullptr) || read != sizeof(arrLen)) return false;
                if (arrType == 8) { // array of strings
                    for (uint64_t i = 0; i < arrLen; ++i) {
                        uint64_t sl = 0;
                        if (!ReadFile(m_hFile, &sl, sizeof(sl), &read, nullptr) || read != sizeof(sl)) return false;
                        if (sl > 0) {
                            std::vector<char> buf(sl);
                            if (!ReadFile(m_hFile, buf.data(), static_cast<DWORD>(sl), &read, nullptr) || read != static_cast<DWORD>(sl)) return false;
                        }
                    }
                    return true;
                } else {
                    uint64_t elemSize = 1;
                    switch (arrType) {
                        case 0: case 1: case 7: elemSize = 1; break;
                        case 2: case 3: elemSize = 2; break;
                        case 4: case 5: case 6: elemSize = 4; break;
                        case 10: case 11: case 12: elemSize = 8; break;
                        default: elemSize = 1; break;
                    }
                    uint64_t skipBytes = arrLen * elemSize;
                    while (skipBytes > 0) {
                        uint32_t chunk = (skipBytes > 0x7FFFFFFFu) ? 0x7FFFFFFFu : static_cast<uint32_t>(skipBytes);
                        std::vector<char> buf(chunk);
                        if (!ReadFile(m_hFile, buf.data(), chunk, &read, nullptr) || read != chunk) return false;
                        skipBytes -= chunk;
                    }
                    return true;
                }
            }
            default:
                return false;
        }
    }

public:

    bool ParseTensors() {
        if (!ParseHeader()) return false;
        if (!ParseMetadata()) return false;
        if (!ParseTensorInfo()) return false;
        return true;
    }

    // ------------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------------
    bool IsOpen() const { return m_hFile != nullptr && m_hFile != INVALID_HANDLE_VALUE; }
    const std::string& GetPath() const { return m_path; }

    const GGUFMetadata& GetMetadata() const { return m_meta; }
    GGUFMetadata&       GetMetadata()       { return m_meta; }

    size_t GetTensorCount() const { return m_tensors.size(); }
    const TensorInfo* GetTensor(size_t index) const {
        return (index < m_tensors.size()) ? &m_tensors[index] : nullptr;
    }
    const TensorInfo* GetTensor(const char* name) const {
        for (const auto& t : m_tensors) {
            if (std::strcmp(t.name, name) == 0) return &t;
        }
        return nullptr;
    }

    // ------------------------------------------------------------------------
    // Data access (reads from mapped file)
    // ------------------------------------------------------------------------
    bool ReadTensorData(const TensorInfo& info, void* outBuffer, size_t bufferSize) const {
        if (!m_hFile || !outBuffer) return false;
        if (bufferSize < info.byteSize) return false;
        DWORD posLow = static_cast<DWORD>(info.offset & 0xFFFFFFFFu);
        LONG posHigh = static_cast<LONG>(info.offset >> 32);
        SetFilePointer(m_hFile, posLow, &posHigh, FILE_BEGIN);
        DWORD read = 0;
        return ReadFile(m_hFile, outBuffer, static_cast<DWORD>(info.byteSize), &read, nullptr)
               && read == static_cast<DWORD>(info.byteSize);
    }

    const void* GetTensorDataPointer(const TensorInfo& /*info*/) const {
        // Would require memory mapping; return nullptr for now.
        return nullptr;
    }

private:
    std::string         m_path;
    GGUFMetadata        m_meta;
    uint64_t            m_metaCount = 0;
    std::vector<TensorInfo> m_tensors;

    HANDLE              m_hFile    = nullptr;
    HANDLE              m_hMapping = nullptr;
    void*               m_pView    = nullptr;
    uint64_t            m_fileSize = 0;

    void Unmap() {
        if (m_pView) { UnmapViewOfFile(m_pView); m_pView = nullptr; }
        if (m_hMapping) { CloseHandle(m_hMapping); m_hMapping = nullptr; }
    }
};

} // namespace RawrXD

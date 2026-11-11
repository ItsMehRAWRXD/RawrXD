// ============================================================================
// RawrXD Universal Header Sniffer - Extension-Agnostic Binary Ingestion
// ============================================================================
// Purpose: Detect file type by magic numbers, not extensions.
//          Maps arbitrary byte streams to canonical ModelDescriptor IR.
//
// Philosophy: The extension is human metadata. The magic is the truth.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>
#include <functional>

namespace RawrXD {

// ============================================================================
// Magic Number Registry - Cryptographic Signatures at Offset 0
// ============================================================================

enum class FileFormat : uint32_t {
    Unknown     = 0,
    
    // Tensor/Model Formats
    GGUF        = 0x46554747,   // "GGUF" (little-endian)
    GGML        = 0x4C4D4747,   // "GGML" (legacy)
    Safetensors = 0x7B7B7B7B,   // "{{{{" JSON header start
    ONNX        = 0x4F4E4E58,   // "ONNX" protobuf wrapper
    PyTorch     = 0x8A0A,       // PyTorch ZIP magic (0x8A0A)
    TensorFlow  = 0x0880,       // TF SavedModel indicator
    
    // Native Binary Formats
    PE32        = 0x4D5A,       // "MZ" Windows PE
    PE64        = 0x4D5A,       // "MZ" (same, checked at offset 0x3C)
    ELF         = 0x7F454C46,   // 0x7F "ELF"
    MachO       = 0xFEEDFACE,   // Mach-O header
    MachO64     = 0xFEEDFACF,   // Mach-O 64-bit
    
    // Archive/Container Formats
    ZIP         = 0x504B0304,   // PK\x03\x04
    GZIP        = 0x1F8B,       // GZIP magic
    ZSTD        = 0x28B52FFD,   // Zstandard
    
    // Raw Tensor Blobs
    RawFloat32  = 0x52415746,   // "RAWF" - RawrXD raw float marker
    RawFloat16  = 0x52415748,   // "RAWH" - RawrXD raw half marker
    RawInt8     = 0x52415742,   // "RAWB" - RawrXD raw byte marker
    
    // Custom/Encrypted
    Encrypted   = 0x52414445,   // "RADE" - RawrXD encrypted container
    CustomVM    = 0x5241564D,   // "RAVM" - RawrXD VM bytecode
    
    MaxFormat
};

// ============================================================================
// Magic Signature Definition
// ============================================================================

struct MagicSignature {
    FileFormat      format;
    std::string_view name;
    uint32_t        magicOffset;        // Usually 0, but some formats have headers
    uint32_t        magicValue;         // The expected magic number
    uint32_t        magicMask;          // Mask for partial matches (0xFFFFFFFF = exact)
    uint32_t        secondaryOffset;    // For formats needing verification at second location
    uint32_t        secondaryMagic;     // Secondary verification value
    bool            requiresSecondary;  // If true, both magics must match
};

// ============================================================================
// Universal Sniffer - Content-Based Format Detection
// ============================================================================

class UniversalHeaderSniffer {
public:
    UniversalHeaderSniffer();
    ~UniversalHeaderSniffer() = default;
    
    // Non-copyable (holds function registry)
    UniversalHeaderSniffer(const UniversalHeaderSniffer&) = delete;
    UniversalHeaderSniffer& operator=(const UniversalHeaderSniffer&) = delete;
    
    // Core API: Sniff a byte stream
    [[nodiscard]] FileFormat Sniff(const void* data, size_t size) const;
    [[nodiscard]] FileFormat SniffFile(const std::string& path) const;
    
    // Get human-readable format name
    [[nodiscard]] std::string_view GetFormatName(FileFormat fmt) const;
    [[nodiscard]] bool IsTensorFormat(FileFormat fmt) const;
    [[nodiscard]] bool IsNativeBinary(FileFormat fmt) const;
    [[nodiscard]] bool IsSupported(FileFormat fmt) const;
    
    // Registry: Add custom magic signatures at runtime
    void RegisterMagic(const MagicSignature& sig);
    void UnregisterMagic(FileFormat fmt);
    
    // Get all registered signatures
    [[nodiscard]] const std::vector<MagicSignature>& GetSignatures() const { return signatures_; }
    
private:
    std::vector<MagicSignature> signatures_;
    
    void InitializeDefaultSignatures();
    [[nodiscard]] bool VerifySecondary(const void* data, size_t size, 
                                       const MagicSignature& sig) const;
};

// ============================================================================
// Memory-Mapped Stream - Zero-Copy Ingestion
// ============================================================================

class MemoryMappedStream {
public:
    MemoryMappedStream() = default;
    explicit MemoryMappedStream(const std::string& path);
    ~MemoryMappedStream();
    
    // Move-only (handles OS resources)
    MemoryMappedStream(MemoryMappedStream&& other) noexcept;
    MemoryMappedStream& operator=(MemoryMappedStream&& other) noexcept;
    
    MemoryMappedStream(const MemoryMappedStream&) = delete;
    MemoryMappedStream& operator=(const MemoryMappedStream&) = delete;
    
    // Map/unmap
    bool Map(const std::string& path);
    void Unmap();
    
    // Access
    [[nodiscard]] const void* Data() const { return data_; }
    [[nodiscard]] size_t Size() const { return size_; }
    [[nodiscard]] bool IsValid() const { return data_ != nullptr && size_ > 0; }
    
    // Read helpers
    template<typename T>
    [[nodiscard]] T ReadAt(size_t offset) const {
        if (offset + sizeof(T) > size_) return T{};
        return *reinterpret_cast<const T*>(static_cast<const uint8_t*>(data_) + offset);
    }
    
    [[nodiscard]] const uint8_t* BytesAt(size_t offset) const {
        if (offset >= size_) return nullptr;
        return static_cast<const uint8_t*>(data_) + offset;
    }
    
private:
    void* data_ = nullptr;
    size_t size_ = 0;
    
#ifdef _WIN32
    void* fileHandle_ = nullptr;
    void* mappingHandle_ = nullptr;
#else
    int fd_ = -1;
#endif
};

// ============================================================================
// Polymorphic Dispatch Table - Format → Handler Registry
// ============================================================================

class IModelImporter {
public:
    virtual ~IModelImporter() = default;
    
    // Probe: Quick check if this importer can handle the stream
    [[nodiscard]] virtual bool Probe(const MemoryMappedStream& stream) const = 0;
    
    // Import: Convert stream to canonical ModelDescriptor
    // virtual ModelDescriptor Import(const MemoryMappedStream& stream) = 0;
    
    // Get importer metadata
    [[nodiscard]] virtual std::string_view GetName() const = 0;
    [[nodiscard]] virtual std::string_view GetVersion() const = 0;
    [[nodiscard]] virtual std::vector<FileFormat> GetSupportedFormats() const = 0;
};

class ImporterRegistry {
public:
    static ImporterRegistry& Instance();
    
    // Register/unregister importers
    void Register(std::unique_ptr<IModelImporter> importer);
    void Unregister(FileFormat fmt);
    void Clear();
    
    // Find importer for format
    [[nodiscard]] IModelImporter* FindImporter(FileFormat fmt) const;
    [[nodiscard]] IModelImporter* FindImporterForStream(const MemoryMappedStream& stream) const;
    
    // Auto-import: sniff → find importer → import
    // [[nodiscard]] ModelDescriptor AutoImport(const MemoryMappedStream& stream) const;
    
    // List registered importers
    [[nodiscard]] std::vector<std::string_view> ListImporters() const;
    
private:
    ImporterRegistry() = default;
    ~ImporterRegistry() = default;
    
    std::vector<std::unique_ptr<IModelImporter>> importers_;
    std::unordered_map<FileFormat, IModelImporter*> formatMap_;
};

// ============================================================================
// Universal Loader - High-Level API
// ============================================================================

class UniversalLoader {
public:
    UniversalLoader();
    explicit UniversalLoader(const std::string& path);
    
    // Load any file, auto-detect format
    bool Load(const std::string& path);
    void Unload();
    
    // Access
    [[nodiscard]] FileFormat GetDetectedFormat() const { return detectedFormat_; }
    [[nodiscard]] const MemoryMappedStream& GetStream() const { return stream_; }
    [[nodiscard]] bool IsLoaded() const { return stream_.IsValid(); }
    
    // Get importer that would handle this
    [[nodiscard]] IModelImporter* GetImporter() const;
    
    // Import to canonical IR (requires ModelDescriptor implementation)
    // [[nodiscard]] ModelDescriptor ImportToIR() const;
    
private:
    MemoryMappedStream stream_;
    FileFormat detectedFormat_ = FileFormat::Unknown;
    UniversalHeaderSniffer sniffer_;
};

// ============================================================================
// Convenience Macros for Magic Definition
// ============================================================================

#define RAWXD_MAGIC_4CC(a, b, c, d) \
    (static_cast<uint32_t>(a) | (static_cast<uint32_t>(b) << 8) | \
     (static_cast<uint32_t>(c) << 16) | (static_cast<uint32_t>(d) << 24))

#define RAWXD_MAGIC_2CC(a, b) \
    (static_cast<uint32_t>(a) | (static_cast<uint32_t>(b) << 8))

} // namespace RawrXD

// ============================================================================
// RawrXD Universal Header Sniffer - Implementation
// ============================================================================

#include "UniversalHeaderSniffer.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <fstream>
#include <algorithm>

namespace RawrXD {

// ============================================================================
// UniversalHeaderSniffer Implementation
// ============================================================================

UniversalHeaderSniffer::UniversalHeaderSniffer() {
    InitializeDefaultSignatures();
}

void UniversalHeaderSniffer::InitializeDefaultSignatures() {
    // GGUF: "GGUF" at offset 0
    signatures_.push_back({
        FileFormat::GGUF,
        "GGUF",
        0,
        RAWXD_MAGIC_4CC('G', 'G', 'U', 'F'),
        0xFFFFFFFF,
        0, 0, false
    });
    
    // GGML: "GGML" at offset 0
    signatures_.push_back({
        FileFormat::GGML,
        "GGML (Legacy)",
        0,
        RAWXD_MAGIC_4CC('G', 'G', 'M', 'L'),
        0xFFFFFFFF,
        0, 0, false
    });
    
    // Safetensors: JSON starts with '{' - check for valid JSON structure
    signatures_.push_back({
        FileFormat::Safetensors,
        "Safetensors",
        0,
        RAWXD_MAGIC_4CC('{', '\n', ' ', '"'),  // Relaxed match
        0xFF000000,  // Only check first byte is '{'
        0, 0, false
    });
    
    // PE32/64: "MZ" at offset 0, PE at offset from DOS header
    signatures_.push_back({
        FileFormat::PE32,
        "PE32/PE64",
        0,
        RAWXD_MAGIC_2CC('M', 'Z'),
        0xFFFF,
        0x3C,  // PE header offset location
        RAWXD_MAGIC_4CC('P', 'E', '\0', '\0'),
        true
    });
    
    // ELF: 0x7F "ELF" at offset 0
    signatures_.push_back({
        FileFormat::ELF,
        "ELF",
        0,
        0x464C457F,  // 0x7F 'E' 'L' 'F'
        0xFFFFFFFF,
        0, 0, false
    });
    
    // Mach-O: 0xFEEDFACE (32-bit) or 0xFEEDFACF (64-bit)
    signatures_.push_back({
        FileFormat::MachO,
        "Mach-O",
        0,
        0xFEEDFACE,
        0xFFFFFFFF,
        0, 0, false
    });
    
    signatures_.push_back({
        FileFormat::MachO64,
        "Mach-O 64",
        0,
        0xFEEDFACF,
        0xFFFFFFFF,
        0, 0, false
    });
    
    // ZIP: PK\x03\x04
    signatures_.push_back({
        FileFormat::ZIP,
        "ZIP",
        0,
        RAWXD_MAGIC_4CC('P', 'K', 0x03, 0x04),
        0xFFFFFFFF,
        0, 0, false
    });
    
    // GZIP: 0x1F8B
    signatures_.push_back({
        FileFormat::GZIP,
        "GZIP",
        0,
        0x8B1F,
        0xFFFF,
        0, 0, false
    });
    
    // ZSTD: 0x28B52FFD
    signatures_.push_back({
        FileFormat::ZSTD,
        "Zstandard",
        0,
        0xFD2FB528,
        0xFFFFFFFF,
        0, 0, false
    });
    
    // RawrXD Raw Float32: "RAWF"
    signatures_.push_back({
        FileFormat::RawFloat32,
        "RawrXD Raw Float32",
        0,
        RAWXD_MAGIC_4CC('R', 'A', 'W', 'F'),
        0xFFFFFFFF,
        0, 0, false
    });
    
    // RawrXD Raw Float16: "RAWH"
    signatures_.push_back({
        FileFormat::RawFloat16,
        "RawrXD Raw Float16",
        0,
        RAWXD_MAGIC_4CC('R', 'A', 'W', 'H'),
        0xFFFFFFFF,
        0, 0, false
    });
    
    // RawrXD Raw Int8: "RAWB"
    signatures_.push_back({
        FileFormat::RawInt8,
        "RawrXD Raw Int8",
        0,
        RAWXD_MAGIC_4CC('R', 'A', 'W', 'B'),
        0xFFFFFFFF,
        0, 0, false
    });
    
    // RawrXD Encrypted: "RADE"
    signatures_.push_back({
        FileFormat::Encrypted,
        "RawrXD Encrypted",
        0,
        RAWXD_MAGIC_4CC('R', 'A', 'D', 'E'),
        0xFFFFFFFF,
        0, 0, false
    });
    
    // RawrXD VM Bytecode: "RAVM"
    signatures_.push_back({
        FileFormat::CustomVM,
        "RawrXD VM Bytecode",
        0,
        RAWXD_MAGIC_4CC('R', 'A', 'V', 'M'),
        0xFFFFFFFF,
        0, 0, false
    });
}

FileFormat UniversalHeaderSniffer::Sniff(const void* data, size_t size) const {
    if (!data || size < 4) {
        return FileFormat::Unknown;
    }
    
    const uint32_t* ptr32 = static_cast<const uint32_t*>(data);
    const uint16_t* ptr16 = static_cast<const uint16_t*>(data);
    
    for (const auto& sig : signatures_) {
        bool matched = false;
        
        // Check based on magic size
        if (sig.magicMask == 0xFFFF) {
            // 16-bit magic
            if (size >= 2) {
                uint16_t value = *ptr16;
                matched = ((value & sig.magicMask) == (sig.magicValue & sig.magicMask));
            }
        } else {
            // 32-bit magic
            if (size >= 4) {
                uint32_t value = *ptr32;
                matched = ((value & sig.magicMask) == (sig.magicValue & sig.magicMask));
            }
        }
        
        if (matched) {
            // Secondary verification if required
            if (sig.requiresSecondary) {
                if (!VerifySecondary(data, size, sig)) {
                    continue;
                }
            }
            return sig.format;
        }
    }
    
    return FileFormat::Unknown;
}

FileFormat UniversalHeaderSniffer::SniffFile(const std::string& path) const {
    // Fast path: read first 64 bytes
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return FileFormat::Unknown;
    }
    
    uint8_t buffer[64] = {};
    file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
    size_t bytesRead = file.gcount();
    
    return Sniff(buffer, bytesRead);
}

bool UniversalHeaderSniffer::VerifySecondary(const void* data, size_t size, 
                                              const MagicSignature& sig) const {
    if (sig.secondaryOffset + 4 > size) {
        return false;
    }
    
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t value = *reinterpret_cast<const uint32_t*>(bytes + sig.secondaryOffset);
    return (value == sig.secondaryMagic);
}

std::string_view UniversalHeaderSniffer::GetFormatName(FileFormat fmt) const {
    auto it = std::find_if(signatures_.begin(), signatures_.end(),
        [fmt](const MagicSignature& sig) { return sig.format == fmt; });
    
    if (it != signatures_.end()) {
        return it->name;
    }
    
    switch (fmt) {
        case FileFormat::Unknown: return "Unknown";
        case FileFormat::ONNX: return "ONNX";
        case FileFormat::PyTorch: return "PyTorch";
        case FileFormat::TensorFlow: return "TensorFlow";
        default: return "Unregistered";
    }
}

bool UniversalHeaderSniffer::IsTensorFormat(FileFormat fmt) const {
    switch (fmt) {
        case FileFormat::GGUF:
        case FileFormat::GGML:
        case FileFormat::Safetensors:
        case FileFormat::ONNX:
        case FileFormat::PyTorch:
        case FileFormat::RawFloat32:
        case FileFormat::RawFloat16:
        case FileFormat::RawInt8:
            return true;
        default:
            return false;
    }
}

bool UniversalHeaderSniffer::IsNativeBinary(FileFormat fmt) const {
    switch (fmt) {
        case FileFormat::PE32:
        case FileFormat::PE64:
        case FileFormat::ELF:
        case FileFormat::MachO:
        case FileFormat::MachO64:
            return true;
        default:
            return false;
    }
}

bool UniversalHeaderSniffer::IsSupported(FileFormat fmt) const {
    return fmt != FileFormat::Unknown && fmt != FileFormat::MaxFormat;
}

void UniversalHeaderSniffer::RegisterMagic(const MagicSignature& sig) {
    // Remove existing entry for this format if present
    UnregisterMagic(sig.format);
    signatures_.push_back(sig);
}

void UniversalHeaderSniffer::UnregisterMagic(FileFormat fmt) {
    signatures_.erase(
        std::remove_if(signatures_.begin(), signatures_.end(),
            [fmt](const MagicSignature& sig) { return sig.format == fmt; }),
        signatures_.end()
    );
}

// ============================================================================
// MemoryMappedStream Implementation
// ============================================================================

#ifdef _WIN32

MemoryMappedStream::MemoryMappedStream(MemoryMappedStream&& other) noexcept
    : data_(other.data_)
    , size_(other.size_)
    , fileHandle_(other.fileHandle_)
    , mappingHandle_(other.mappingHandle_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.fileHandle_ = nullptr;
    other.mappingHandle_ = nullptr;
}

MemoryMappedStream& MemoryMappedStream::operator=(MemoryMappedStream&& other) noexcept {
    if (this != &other) {
        Unmap();
        data_ = other.data_;
        size_ = other.size_;
        fileHandle_ = other.fileHandle_;
        mappingHandle_ = other.mappingHandle_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.fileHandle_ = nullptr;
        other.mappingHandle_ = nullptr;
    }
    return *this;
}

MemoryMappedStream::~MemoryMappedStream() {
    Unmap();
}

bool MemoryMappedStream::Map(const std::string& path) {
    Unmap();
    
    // Open file
    fileHandle_ = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (fileHandle_ == INVALID_HANDLE_VALUE) {
        fileHandle_ = nullptr;
        return false;
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(fileHandle_, &fileSize)) {
        CloseHandle(fileHandle_);
        fileHandle_ = nullptr;
        return false;
    }
    size_ = static_cast<size_t>(fileSize.QuadPart);
    
    if (size_ == 0) {
        CloseHandle(fileHandle_);
        fileHandle_ = nullptr;
        return false;
    }
    
    // Create file mapping
    mappingHandle_ = CreateFileMapping(
        fileHandle_,
        nullptr,
        PAGE_READONLY,
        0, 0,
        nullptr
    );
    
    if (!mappingHandle_) {
        CloseHandle(fileHandle_);
        fileHandle_ = nullptr;
        return false;
    }
    
    // Map view
    data_ = MapViewOfFile(mappingHandle_, FILE_MAP_READ, 0, 0, 0);
    if (!data_) {
        CloseHandle(mappingHandle_);
        CloseHandle(fileHandle_);
        mappingHandle_ = nullptr;
        fileHandle_ = nullptr;
        return false;
    }
    
    return true;
}

void MemoryMappedStream::Unmap() {
    if (data_) {
        UnmapViewOfFile(data_);
        data_ = nullptr;
    }
    if (mappingHandle_) {
        CloseHandle(mappingHandle_);
        mappingHandle_ = nullptr;
    }
    if (fileHandle_) {
        CloseHandle(fileHandle_);
        fileHandle_ = nullptr;
    }
    size_ = 0;
}

#else // POSIX

MemoryMappedStream::MemoryMappedStream(MemoryMappedStream&& other) noexcept
    : data_(other.data_)
    , size_(other.size_)
    , fd_(other.fd_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.fd_ = -1;
}

MemoryMappedStream& MemoryMappedStream::operator=(MemoryMappedStream&& other) noexcept {
    if (this != &other) {
        Unmap();
        data_ = other.data_;
        size_ = other.size_;
        fd_ = other.fd_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.fd_ = -1;
    }
    return *this;
}

MemoryMappedStream::~MemoryMappedStream() {
    Unmap();
}

bool MemoryMappedStream::Map(const std::string& path) {
    Unmap();
    
    fd_ = open(path.c_str(), O_RDONLY);
    if (fd_ < 0) {
        return false;
    }
    
    struct stat st;
    if (fstat(fd_, &st) < 0) {
        close(fd_);
        fd_ = -1;
        return false;
    }
    
    size_ = st.st_size;
    if (size_ == 0) {
        close(fd_);
        fd_ = -1;
        return false;
    }
    
    data_ = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (data_ == MAP_FAILED) {
        data_ = nullptr;
        close(fd_);
        fd_ = -1;
        return false;
    }
    
    return true;
}

void MemoryMappedStream::Unmap() {
    if (data_) {
        munmap(data_, size_);
        data_ = nullptr;
    }
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    size_ = 0;
}

#endif

// ============================================================================
// ImporterRegistry Implementation
// ============================================================================

ImporterRegistry& ImporterRegistry::Instance() {
    static ImporterRegistry instance;
    return instance;
}

void ImporterRegistry::Register(std::unique_ptr<IModelImporter> importer) {
    if (!importer) return;
    
    auto formats = importer->GetSupportedFormats();
    for (auto fmt : formats) {
        formatMap_[fmt] = importer.get();
    }
    
    importers_.push_back(std::move(importer));
}

void ImporterRegistry::Unregister(FileFormat fmt) {
    formatMap_.erase(fmt);
}

void ImporterRegistry::Clear() {
    formatMap_.clear();
    importers_.clear();
}

IModelImporter* ImporterRegistry::FindImporter(FileFormat fmt) const {
    auto it = formatMap_.find(fmt);
    if (it != formatMap_.end()) {
        return it->second;
    }
    return nullptr;
}

IModelImporter* ImporterRegistry::FindImporterForStream(const MemoryMappedStream& stream) const {
    if (!stream.IsValid()) return nullptr;
    
    UniversalHeaderSniffer sniffer;
    FileFormat fmt = sniffer.Sniff(stream.Data(), std::min(stream.Size(), size_t(64)));
    
    return FindImporter(fmt);
}

std::vector<std::string_view> ImporterRegistry::ListImporters() const {
    std::vector<std::string_view> names;
    for (const auto& imp : importers_) {
        names.push_back(imp->GetName());
    }
    return names;
}

// ============================================================================
// UniversalLoader Implementation
// ============================================================================

UniversalLoader::UniversalLoader() = default;

UniversalLoader::UniversalLoader(const std::string& path) {
    Load(path);
}

bool UniversalLoader::Load(const std::string& path) {
    Unload();
    
    if (!stream_.Map(path)) {
        return false;
    }
    
    detectedFormat_ = sniffer_.Sniff(stream_.Data(), 
                                       std::min(stream_.Size(), size_t(64)));
    
    return true;
}

void UniversalLoader::Unload() {
    stream_.Unmap();
    detectedFormat_ = FileFormat::Unknown;
}

IModelImporter* UniversalLoader::GetImporter() const {
    if (!IsLoaded()) return nullptr;
    return ImporterRegistry::Instance().FindImporter(detectedFormat_);
}

} // namespace RawrXD

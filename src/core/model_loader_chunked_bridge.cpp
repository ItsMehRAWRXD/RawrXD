// ============================================================================
// model_loader_chunked_bridge.cpp — Bridge ChunkedIO to Model Loader
// Fixes P0 Blocker: 2GB+ GGUF File Loading
// ============================================================================

#include "model_loader.h"
#include "../core/native_ide_tools.h"
#include "rawrxd_quant_container.h"
#include <filesystem>
#include <fstream>
#include <cstdio>
#include <vector>

namespace RawrXD::Inference {

// ============================================================================
// Chunked GGUF Loader — Handles >2GB Files
// ============================================================================

class ChunkedGGUFLoader {
public:
    ChunkedGGUFLoader() : m_file(nullptr), m_fileSize(0), m_position(0) {}
    
    ~ChunkedGGUFLoader() {
        close();
    }
    
    bool open(const std::string& path) {
        close();
        
        // Use ChunkedIO for large file support
        m_fileSize = NativeIDE::ChunkedIO::ChunkedGetSize(path.c_str());
        if (m_fileSize == 0) {
            return false;
        }
        
        m_file = NativeIDE::ChunkedIO::ChunkedOpen(path.c_str(), true);
        if (!m_file) {
            return false;
        }
        
        m_path = path;
        m_position = 0;
        
        // Log for large files
        if (m_fileSize > 100 * 1024 * 1024) { // >100MB
            double sizeMB = (double)m_fileSize / (1024.0 * 1024.0);
            double sizeGB = sizeMB / 1024.0;
            
            if (sizeGB >= 1.0) {
                printf("[ChunkedGGUF] Loading large file: %.2f GB (%.0f MB)\n", 
                       sizeGB, sizeMB);
            } else {
                printf("[ChunkedGGUF] Loading file: %.0f MB\n", sizeMB);
            }
            
            // Check if memory mapping is available
            if (m_file->useMemoryMap) {
                printf("[ChunkedGGUF] Using memory-mapped I/O for optimal performance\n");
            } else {
                printf("[ChunkedGGUF] Using chunked I/O (64MB blocks)\n");
            }
        }
        
        return true;
    }
    
    void close() {
        if (m_file) {
            NativeIDE::ChunkedIO::ChunkedClose(m_file);
            m_file = nullptr;
        }
        m_fileSize = 0;
        m_position = 0;
    }
    
    size_t read(void* buffer, size_t size) {
        if (!m_file || m_position >= m_fileSize) {
            return 0;
        }
        
        size_t toRead = std::min(size, m_fileSize - m_position);
        size_t read = NativeIDE::ChunkedIO::ChunkedRead(m_file, buffer, m_position, toRead);
        m_position += read;
        
        return read;
    }
    
    bool seek(size_t position) {
        if (!m_file || position > m_fileSize) {
            return false;
        }
        m_position = position;
        return true;
    }
    
    size_t tell() const {
        return m_position;
    }
    
    size_t size() const {
        return m_fileSize;
    }
    
    bool isOpen() const {
        return m_file != nullptr && m_file->isOpen;
    }
    
    bool isLargeFile() const {
        return m_fileSize > (2ULL * 1024 * 1024 * 1024); // >2GB
    }
    
    const std::string& path() const {
        return m_path;
    }
    
private:
    NativeIDE::ChunkedIO::ChunkedFile* m_file;
    std::string m_path;
    size_t m_fileSize;
    size_t m_position;
};

// ============================================================================
// Model Loader Integration
// ============================================================================

bool ModelLoader::loadGGUF(const std::string& path, Model& model) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Use ChunkedGGUFLoader for >2GB file support
    ChunkedGGUFLoader loader;
    
    if (!loader.open(path)) {
        return false;
    }

    const uint64_t fileSize = static_cast<uint64_t>(loader.size());
    if (fileSize < sizeof(uint32_t)) {
        loader.close();
        return false;
    }
    
    // Log for large models
    if (loader.isLargeFile()) {
        printf("[ModelLoader] Loading large GGUF model (>2GB): %s\n", path.c_str());
        printf("[ModelLoader] File size: %.2f GB\n", 
               (double)loader.size() / (1024.0 * 1024.0 * 1024.0));
    }
    
    // Read GGUF header
    GGUFHeader header;
    if (loader.read(&header.magic, sizeof(header.magic)) != sizeof(header.magic) ||
        loader.read(&header.version, sizeof(header.version)) != sizeof(header.version) ||
        loader.read(&header.tensorCount, sizeof(header.tensorCount)) != sizeof(header.tensorCount) ||
        loader.read(&header.metadataCount, sizeof(header.metadataCount)) != sizeof(header.metadataCount)) {
        loader.close();
        return false;
    }

    // RXQF quant container path: validate hard and fail closed on malformed files.
    if (header.magic == RAWRXD_QUANT_MAGIC) {
        RawrXDQuantFileHeader qh{};
        if (!loader.seek(0) || loader.read(&qh, sizeof(qh)) != sizeof(qh) ||
            !RawrXDQuantValidateHeader(&qh, fileSize)) {
            loader.close();
            return false;
        }

        model.format = ModelFormat::RXQF;
        model.version = qh.version;
        model.tensors.clear();
        model.metadata.clear();
        std::vector<std::string> rxqfNames;

        auto quantTypeFromMode = [](uint32_t mode) {
            switch (mode) {
                case RAWRXD_QUANT_FILE_FP16: return QuantizationType::F16;
                case RAWRXD_QUANT_FILE_INT8: return QuantizationType::Q8_0;
                case RAWRXD_QUANT_FILE_INT4:
                case RAWRXD_QUANT_FILE_INT4_NF:
                    return QuantizationType::Q4_0;
                default: return QuantizationType::None;
            }
        };
        auto tensorTypeFromMode = [](uint32_t mode) {
            switch (mode) {
                case RAWRXD_QUANT_FILE_FP16: return TensorType::F16;
                case RAWRXD_QUANT_FILE_INT8: return TensorType::Q8_0;
                case RAWRXD_QUANT_FILE_INT4:
                case RAWRXD_QUANT_FILE_INT4_NF:
                    return TensorType::Q4_0;
                default: return TensorType::F32;
            }
        };

        bool quantTypeSet = false;

        if (qh.reserved0 != 0) {
            RawrXDQuantNameTableHeader nh{};
            if (!loader.seek(static_cast<size_t>(qh.reserved0)) ||
                loader.read(&nh, sizeof(nh)) != sizeof(nh) ||
                !RawrXDQuantValidateNameTableHeader(&qh, &nh, fileSize)) {
                loader.close();
                return false;
            }

            rxqfNames.reserve(static_cast<size_t>(nh.tensor_count));
            for (uint64_t i = 0; i < nh.tensor_count; ++i) {
                uint16_t nameLen = 0;
                if (loader.read(&nameLen, sizeof(nameLen)) != sizeof(nameLen) || nameLen == 0 || nameLen > 255) {
                    loader.close();
                    return false;
                }
                std::string name;
                name.resize(nameLen);
                if (loader.read(name.data(), nameLen) != nameLen) {
                    loader.close();
                    return false;
                }
                rxqfNames.push_back(std::move(name));
            }
        }

        for (uint64_t i = 0; i < qh.tensor_count; ++i) {
            RawrXDQuantTensorDescriptor desc{};
            const uint64_t descOffset = qh.descriptor_table_offset + (i * qh.descriptor_bytes);
            if (!loader.seek(static_cast<size_t>(descOffset)) ||
                loader.read(&desc, sizeof(desc)) != sizeof(desc) ||
                !RawrXDQuantValidateDescriptor(&qh, &desc, fileSize)) {
                loader.close();
                return false;
            }

            TensorInfo tensor;
            char tensorName[64] = {0};
            if (i < rxqfNames.size() && !rxqfNames[static_cast<size_t>(i)].empty()) {
                tensor.name = rxqfNames[static_cast<size_t>(i)];
            } else {
                std::snprintf(tensorName, sizeof(tensorName), "rxqf_%llu_%016llx",
                              static_cast<unsigned long long>(i),
                              static_cast<unsigned long long>(desc.name_hash));
                tensor.name = tensorName;
            }
            tensor.type = tensorTypeFromMode(desc.quant_mode);
            tensor.offset = desc.payload_offset;

            if (desc.shape_bytes >= sizeof(RawrXDQuantShapeRecord) &&
                (desc.shape_offset + sizeof(RawrXDQuantShapeRecord)) <= qh.shape_bytes) {
                RawrXDQuantShapeRecord shape{};
                const uint64_t shapeOffset = qh.shape_table_offset + desc.shape_offset;
                if (!loader.seek(static_cast<size_t>(shapeOffset)) ||
                    loader.read(&shape, sizeof(shape)) != sizeof(shape)) {
                    loader.close();
                    return false;
                }
                if (shape.rank > 0 && shape.rank <= 8) {
                    tensor.dimensions.assign(shape.dims, shape.dims + shape.rank);
                }
            }

            if (desc.payload_bytes > static_cast<uint64_t>(SIZE_MAX)) {
                loader.close();
                return false;
            }

            tensor.data.resize(static_cast<size_t>(desc.payload_bytes));
            if (!loader.seek(static_cast<size_t>(desc.payload_offset)) ||
                loader.read(tensor.data.data(), tensor.data.size()) != tensor.data.size()) {
                loader.close();
                return false;
            }

            if (!quantTypeSet) {
                model.quantizationType = quantTypeFromMode(desc.quant_mode);
                quantTypeSet = true;
            }

            model.tensors[tensor.name] = std::move(tensor);
            if (m_progressCallback) {
                float progress = static_cast<float>(i + 1) / static_cast<float>(qh.tensor_count == 0 ? 1 : qh.tensor_count);
                m_progressCallback(tensorName, progress);
            }
        }

        model.quantizationVersion = qh.version;
        model.name = std::filesystem::path(path).stem().string();
        loader.close();
        return true;
    }
    
    // Verify magic (GGUF in little-endian)
    if (header.magic != 0x46554747) {
        printf("[ModelLoader] Invalid GGUF magic: 0x%08X\n", header.magic);
        loader.close();
        return false;
    }
    
    model.format = ModelFormat::GGUF;
    model.version = header.version;
    
    // Progress callback
    if (m_progressCallback) {
        m_progressCallback("header", 0.05f);
    }
    
    // Read metadata
    for (uint64_t i = 0; i < header.metadataCount; ++i) {
        if (m_progressCallback && i % 100 == 0) {
            float progress = 0.05f + 0.15f * (float)i / (float)header.metadataCount;
            m_progressCallback("metadata", progress);
        }
        
        MetadataEntry entry;
        
        // Read key length and key
        uint64_t keyLen;
        if (loader.read(&keyLen, sizeof(keyLen)) != sizeof(keyLen)) {
            break;
        }
        
        entry.key.resize(keyLen);
        if (loader.read(entry.key.data(), keyLen) != keyLen) {
            break;
        }
        
        // Read value type
        uint32_t valueType;
        if (loader.read(&valueType, sizeof(valueType)) != sizeof(valueType)) {
            break;
        }
        entry.type = static_cast<MetadataType>(valueType);
        
        // Read value based on type
        switch (entry.type) {
            case MetadataType::Uint8: {
                uint8_t val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Int8: {
                int8_t val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Uint16: {
                uint16_t val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Int16: {
                int16_t val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Uint32: {
                uint32_t val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Int32: {
                int32_t val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Float32: {
                float val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Bool: {
                uint8_t val;
                loader.read(&val, sizeof(val));
                entry.value = (val != 0);
                break;
            }
            case MetadataType::String: {
                uint64_t strLen;
                loader.read(&strLen, sizeof(strLen));
                std::string str;
                str.resize(strLen);
                loader.read(str.data(), strLen);
                entry.value = str;
                break;
            }
            case MetadataType::Uint64: {
                uint64_t val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Int64: {
                int64_t val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Float64: {
                double val;
                loader.read(&val, sizeof(val));
                entry.value = val;
                break;
            }
            case MetadataType::Array: {
                // Skip arrays for now
                uint32_t arrType;
                uint64_t arrLen;
                loader.read(&arrType, sizeof(arrType));
                loader.read(&arrLen, sizeof(arrLen));
                
                // Skip array data
                for (uint64_t j = 0; j < arrLen; ++j) {
                    switch (static_cast<MetadataType>(arrType)) {
                        case MetadataType::Uint8: { uint8_t v; loader.read(&v, 1); break; }
                        case MetadataType::Int8: { int8_t v; loader.read(&v, 1); break; }
                        case MetadataType::Uint16: { uint16_t v; loader.read(&v, 2); break; }
                        case MetadataType::Int16: { int16_t v; loader.read(&v, 2); break; }
                        case MetadataType::Uint32: { uint32_t v; loader.read(&v, 4); break; }
                        case MetadataType::Int32: { int32_t v; loader.read(&v, 4); break; }
                        case MetadataType::Float32: { float v; loader.read(&v, 4); break; }
                        case MetadataType::Bool: { uint8_t v; loader.read(&v, 1); break; }
                        case MetadataType::String: {
                            uint64_t slen;
                            loader.read(&slen, sizeof(slen));
                            std::string s;
                            s.resize(slen);
                            loader.read(s.data(), slen);
                            break;
                        }
                        default: break;
                    }
                }
                break;
            }
            default:
                break;
        }
        
        model.metadata[entry.key] = entry;
    }
    
    // Extract common metadata
    extractCommonMetadata(model);
    
    if (m_progressCallback) {
        m_progressCallback("metadata", 0.20f);
    }
    
    // Read tensor info
    for (uint64_t i = 0; i < header.tensorCount; ++i) {
        if (m_progressCallback && i % 10 == 0) {
            float progress = 0.20f + 0.30f * (float)i / (float)header.tensorCount;
            m_progressCallback("tensors", progress);
        }
        
        TensorInfo tensor;
        
        // Read tensor name
        uint64_t nameLen;
        if (loader.read(&nameLen, sizeof(nameLen)) != sizeof(nameLen)) {
            break;
        }
        tensor.name.resize(nameLen);
        if (loader.read(tensor.name.data(), nameLen) != nameLen) {
            break;
        }
        
        // Read number of dimensions
        uint32_t nDims;
        if (loader.read(&nDims, sizeof(nDims)) != sizeof(nDims)) {
            break;
        }
        
        // Read dimensions
        tensor.dimensions.resize(nDims);
        for (uint32_t d = 0; d < nDims; ++d) {
            uint64_t dim;
            if (loader.read(&dim, sizeof(dim)) != sizeof(dim)) {
                break;
            }
            tensor.dimensions[d] = dim;
        }
        
        // Read tensor type
        uint32_t tensorType;
        if (loader.read(&tensorType, sizeof(tensorType)) != sizeof(tensorType)) {
            break;
        }
        tensor.type = static_cast<TensorType>(tensorType);
        
        // Read offset
        if (loader.read(&tensor.offset, sizeof(tensor.offset)) != sizeof(tensor.offset)) {
            break;
        }
        
        model.tensors[tensor.name] = tensor;
    }
    
    if (m_progressCallback) {
        m_progressCallback("tensors", 0.50f);
    }
    
    // Calculate tensor data offset (aligned to 32 bytes)
    size_t tensorDataOffset = loader.tell();
    size_t alignment = 32;
    size_t alignedOffset = ((tensorDataOffset + alignment - 1) / alignment) * alignment;
    
    if (alignedOffset > tensorDataOffset) {
        loader.seek(alignedOffset);
    }
    
    // Store tensor data offset for later use
    model.metadata["__tensor_data_offset"] = MetadataEntry{
        "__tensor_data_offset",
        MetadataType::Uint64,
        static_cast<uint64_t>(loader.tell())
    };
    
    loader.close();
    
    if (m_progressCallback) {
        m_progressCallback("complete", 1.0f);
    }
    
    return true;
}

// ============================================================================
// Large File Detection Helper
// ============================================================================

bool IsLargeGGUFFile(const std::string& path) {
    size_t size = NativeIDE::ChunkedIO::ChunkedGetSize(path.c_str());
    return size > (2ULL * 1024 * 1024 * 1024); // >2GB
}

size_t GetGGUFFileSize(const std::string& path) {
    return NativeIDE::ChunkedIO::ChunkedGetSize(path.c_str());
}

std::string FormatFileSize(size_t bytes) {
    double kb = (double)bytes / 1024.0;
    double mb = kb / 1024.0;
    double gb = mb / 1024.0;
    
    char buffer[64];
    if (gb >= 1.0) {
        snprintf(buffer, sizeof(buffer), "%.2f GB", gb);
    } else if (mb >= 1.0) {
        snprintf(buffer, sizeof(buffer), "%.2f MB", mb);
    } else if (kb >= 1.0) {
        snprintf(buffer, sizeof(buffer), "%.2f KB", kb);
    } else {
        snprintf(buffer, sizeof(buffer), "%zu bytes", bytes);
    }
    
    return std::string(buffer);
}

} // namespace RawrXD::Inference

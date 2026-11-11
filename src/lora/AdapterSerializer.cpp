#include "AdapterSerializer.h"
#include <cstring>
#include <algorithm>
#include <numeric>
#include <chrono>

// CRC32 lookup table (simplified - use proper implementation in production)
static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

namespace RawrXD {

// ============================================================================
// SerializeResult to String
// ============================================================================

const char* serialize_result_to_string(SerializeResult result) {
    switch (result) {
        case SerializeResult::SUCCESS: return "Success";
        case SerializeResult::ERROR_FILE_OPEN: return "Failed to open file";
        case SerializeResult::ERROR_FILE_WRITE: return "Failed to write file";
        case SerializeResult::ERROR_FILE_READ: return "Failed to read file";
        case SerializeResult::ERROR_INVALID_MAGIC: return "Invalid file magic";
        case SerializeResult::ERROR_UNSUPPORTED_VERSION: return "Unsupported version";
        case SerializeResult::ERROR_INVALID_DIMENSIONS: return "Invalid dimensions";
        case SerializeResult::ERROR_ALIGNMENT: return "Alignment error";
        case SerializeResult::ERROR_CHECKSUM_MISMATCH: return "Checksum mismatch";
        case SerializeResult::ERROR_COMPRESSION_FAILED: return "Compression failed";
        case SerializeResult::ERROR_OUT_OF_MEMORY: return "Out of memory";
        case SerializeResult::ERROR_INVALID_DATA: return "Invalid data";
        default: return "Unknown error";
    }
}

// ============================================================================
// Config Factory Methods
// ============================================================================

AdapterSerializer::Config AdapterSerializer::Config::fast() {
    Config config;
    config.flags = LoRAFileFlags::CHECKSUM_CRC32;
    config.compression_level = 1;
    config.verify_alignment = true;
    config.validate_checksums = true;
    return config;
}

AdapterSerializer::Config AdapterSerializer::Config::compact() {
    Config config;
    config.flags = LoRAFileFlags::CHECKSUM_CRC32 | LoRAFileFlags::COMPRESSED_ZSTD;
    config.compression_level = 19;  // High compression
    config.verify_alignment = true;
    config.validate_checksums = true;
    return config;
}

AdapterSerializer::Config AdapterSerializer::Config::secure() {
    Config config;
    config.flags = LoRAFileFlags::CHECKSUM_SHA256 | LoRAFileFlags::ENCRYPTED_AES;
    config.compression_level = 3;
    config.verify_alignment = true;
    config.validate_checksums = true;
    return config;
}

// ============================================================================
// CRC32 Calculation
// ============================================================================

uint32_t AdapterSerializer::calculate_crc32(const void* data, size_t size) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < size; ++i) {
        crc = crc32_table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

// ============================================================================
// Header Validation
// ============================================================================

bool AdapterSerializer::validate_header(const LoRAFileHeader& header) {
    // Check magic
    if (std::memcmp(header.magic, LORA_MAGIC, 8) != 0) {
        return false;
    }
    
    // Check version
    if (header.version < LORA_FORMAT_VERSION_MIN || 
        header.version > LORA_FORMAT_VERSION_CURRENT) {
        return false;
    }
    
    // Check dimensions
    if (header.rank == 0 || header.rank > 1024 ||
        header.in_features == 0 || header.in_features > 8192 ||
        header.out_features == 0 || header.out_features > 8192) {
        return false;
    }
    
    // Check offsets are reasonable
    if (header.matrix_a_offset < sizeof(LoRAFileHeader) ||
        header.matrix_b_offset < sizeof(LoRAFileHeader) ||
        header.metadata_offset < sizeof(LoRAFileHeader)) {
        return false;
    }
    
    return true;
}

bool AdapterSerializer::write_header(std::ofstream& file, const LoRAFileHeader& header) {
    file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    return file.good();
}

bool AdapterSerializer::read_header(std::ifstream& file, LoRAFileHeader& header) {
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    return file.good() && file.gcount() == sizeof(header);
}

// ============================================================================
// Alignment Helpers
// ============================================================================

size_t AdapterSerializer::align_size(size_t size, size_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

void* AdapterSerializer::align_pointer(void* ptr, size_t alignment) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    addr = (addr + alignment - 1) & ~(alignment - 1);
    return reinterpret_cast<void*>(addr);
}

// ============================================================================
// Compression Stubs (implement with zstd/lz4 if available)
// ============================================================================

std::vector<uint8_t> AdapterSerializer::compress_zstd(
    const void* data, size_t size, int level) {
    // Stub: return uncompressed data with header
    // In production, link against zstd and use ZSTD_compress
    std::vector<uint8_t> result;
    result.resize(size + 8);
    
    // Store original size in first 8 bytes
    *reinterpret_cast<uint64_t*>(result.data()) = size;
    std::memcpy(result.data() + 8, data, size);
    
    return result;
}

std::vector<uint8_t> AdapterSerializer::decompress_zstd(
    const void* data, size_t compressed_size, size_t original_size) {
    // Stub: skip header and return data
    std::vector<uint8_t> result;
    result.resize(original_size);
    std::memcpy(result.data(), static_cast<const uint8_t*>(data) + 8, original_size);
    return result;
}

// ============================================================================
// Serialization
// ============================================================================

SerializeResult AdapterSerializer::serialize(
    const AdapterData& data,
    const std::filesystem::path& filepath,
    const Config& config) {
    
    if (!data.is_valid()) {
        return SerializeResult::ERROR_INVALID_DATA;
    }
    
    // Create header
    LoRAFileHeader header = {};
    std::memcpy(header.magic, LORA_MAGIC, 8);
    header.version = LORA_FORMAT_VERSION_CURRENT;
    header.flags = static_cast<uint32_t>(config.flags);
    header.rank = data.rank;
    header.in_features = data.in_features;
    header.out_features = data.out_features;
    
    // Calculate sizes and offsets
    size_t a_size = data.matrix_a.size() * sizeof(float);
    size_t b_size = data.matrix_b.size() * sizeof(float);
    size_t metadata_size = data.metadata_json.size();
    
    // Apply alignment
    size_t alignment = has_flag(config.flags, LoRAFileFlags::ALIGN_64) ? 64 : 32;
    size_t header_size = align_size(sizeof(LoRAFileHeader), alignment);
    
    header.matrix_a_offset = header_size;
    header.matrix_a_size = a_size;
    
    header.matrix_b_offset = header_size + align_size(a_size, alignment);
    header.matrix_b_size = b_size;
    
    header.metadata_offset = header.matrix_b_offset + align_size(b_size, alignment);
    header.metadata_size = metadata_size;
    
    // Open file
    std::ofstream file(filepath, std::ios::binary);
    if (!file) {
        return SerializeResult::ERROR_FILE_OPEN;
    }
    
    // Write header (will update checksum later)
    if (!write_header(file, header)) {
        return SerializeResult::ERROR_FILE_WRITE;
    }
    
    // Pad to alignment
    size_t padding = header_size - sizeof(LoRAFileHeader);
    if (padding > 0) {
        std::vector<char> pad(padding, 0);
        file.write(pad.data(), padding);
    }
    
    // Write matrix A
    file.write(reinterpret_cast<const char*>(data.matrix_a.data()), a_size);
    padding = align_size(a_size, alignment) - a_size;
    if (padding > 0) {
        std::vector<char> pad(padding, 0);
        file.write(pad.data(), padding);
    }
    
    // Write matrix B
    file.write(reinterpret_cast<const char*>(data.matrix_b.data()), b_size);
    padding = align_size(b_size, alignment) - b_size;
    if (padding > 0) {
        std::vector<char> pad(padding, 0);
        file.write(pad.data(), padding);
    }
    
    // Write metadata
    if (!data.metadata_json.empty()) {
        file.write(data.metadata_json.data(), metadata_size);
    }
    
    if (!file) {
        return SerializeResult::ERROR_FILE_WRITE;
    }
    
    file.close();
    
    // Calculate and update checksum
    if (has_flag(config.flags, LoRAFileFlags::CHECKSUM_CRC32)) {
        std::ifstream read_file(filepath, std::ios::binary);
        if (read_file) {
            read_file.seekg(0, std::ios::end);
            size_t file_size = read_file.tellg();
            read_file.seekg(0, std::ios::beg);
            
            std::vector<uint8_t> file_data(file_size);
            read_file.read(reinterpret_cast<char*>(file_data.data()), file_size);
            
            // Zero out checksum field before calculating
            std::memset(file_data.data() + offsetof(LoRAFileHeader, crc32_checksum), 0, 4);
            
            uint32_t crc = calculate_crc32(file_data.data(), file_size);
            
            // Update checksum in file
            std::fstream update_file(filepath, std::ios::in | std::ios::out | std::ios::binary);
            update_file.seekp(offsetof(LoRAFileHeader, crc32_checksum));
            update_file.write(reinterpret_cast<const char*>(&crc), sizeof(crc));
        }
    }
    
    return SerializeResult::SUCCESS;
}

// ============================================================================
// Deserialization
// ============================================================================

SerializeResult AdapterSerializer::deserialize(
    const std::filesystem::path& filepath,
    AdapterData& out_data,
    const Config& config) {
    
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        return SerializeResult::ERROR_FILE_OPEN;
    }
    
    // Read header
    LoRAFileHeader header;
    if (!read_header(file, header)) {
        return SerializeResult::ERROR_FILE_READ;
    }
    
    // Validate header
    if (!validate_header(header)) {
        return SerializeResult::ERROR_INVALID_MAGIC;
    }
    
    // Verify checksum if requested
    if (config.validate_checksums && has_flag(static_cast<LoRAFileFlags>(header.flags), LoRAFileFlags::CHECKSUM_CRC32)) {
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<uint8_t> file_data(file_size);
        file.read(reinterpret_cast<char*>(file_data.data()), file_size);
        
        uint32_t stored_crc = *reinterpret_cast<uint32_t*>(
            file_data.data() + offsetof(LoRAFileHeader, crc32_checksum));
        
        // Zero out checksum field before calculating
        std::memset(file_data.data() + offsetof(LoRAFileHeader, crc32_checksum), 0, 4);
        
        uint32_t calculated_crc = calculate_crc32(file_data.data(), file_size);
        
        if (stored_crc != calculated_crc) {
            return SerializeResult::ERROR_CHECKSUM_MISMATCH;
        }
        
        // Re-read header from validated data
        std::memcpy(&header, file_data.data(), sizeof(header));
    }
    
    // Read matrices
    out_data.rank = header.rank;
    out_data.in_features = header.in_features;
    out_data.out_features = header.out_features;
    
    // Read matrix A
    out_data.matrix_a.resize(header.rank * header.in_features);
    file.seekg(header.matrix_a_offset);
    file.read(reinterpret_cast<char*>(out_data.matrix_a.data()), header.matrix_a_size);
    
    // Read matrix B
    out_data.matrix_b.resize(header.out_features * header.rank);
    file.seekg(header.matrix_b_offset);
    file.read(reinterpret_cast<char*>(out_data.matrix_b.data()), header.matrix_b_size);
    
    // Read metadata
    if (header.metadata_size > 0) {
        out_data.metadata_json.resize(header.metadata_size);
        file.seekg(header.metadata_offset);
        file.read(out_data.metadata_json.data(), header.metadata_size);
    }
    
    if (!file) {
        return SerializeResult::ERROR_FILE_READ;
    }
    
    // Verify alignment if requested
    if (config.verify_alignment) {
        size_t alignment = has_flag(static_cast<LoRAFileFlags>(header.flags), LoRAFileFlags::ALIGN_64) ? 64 : 32;
        if (reinterpret_cast<uintptr_t>(out_data.matrix_a.data()) % alignment != 0 ||
            reinterpret_cast<uintptr_t>(out_data.matrix_b.data()) % alignment != 0) {
            return SerializeResult::ERROR_ALIGNMENT;
        }
    }
    
    return SerializeResult::SUCCESS;
}

// ============================================================================
// Buffer Serialization
// ============================================================================

SerializeResult AdapterSerializer::serialize_to_buffer(
    const AdapterData& data,
    std::vector<uint8_t>& out_buffer,
    const Config& config) {
    
    if (!data.is_valid()) {
        return SerializeResult::ERROR_INVALID_DATA;
    }
    
    // Calculate total size
    size_t a_size = data.matrix_a.size() * sizeof(float);
    size_t b_size = data.matrix_b.size() * sizeof(float);
    size_t metadata_size = data.metadata_json.size();
    size_t total_size = sizeof(LoRAFileHeader) + a_size + b_size + metadata_size + 256; // Extra padding
    
    out_buffer.resize(total_size);
    
    // Build header
    LoRAFileHeader* header = reinterpret_cast<LoRAFileHeader*>(out_buffer.data());
    std::memcpy(header->magic, LORA_MAGIC, 8);
    header->version = LORA_FORMAT_VERSION_CURRENT;
    header->flags = static_cast<uint32_t>(config.flags);
    header->rank = data.rank;
    header->in_features = data.in_features;
    header->out_features = data.out_features;
    header->matrix_a_offset = sizeof(LoRAFileHeader);
    header->matrix_a_size = a_size;
    header->matrix_b_offset = sizeof(LoRAFileHeader) + a_size;
    header->matrix_b_size = b_size;
    header->metadata_offset = sizeof(LoRAFileHeader) + a_size + b_size;
    header->metadata_size = metadata_size;
    header->crc32_checksum = 0;
    
    // Copy data
    std::memcpy(out_buffer.data() + header->matrix_a_offset, data.matrix_a.data(), a_size);
    std::memcpy(out_buffer.data() + header->matrix_b_offset, data.matrix_b.data(), b_size);
    if (!data.metadata_json.empty()) {
        std::memcpy(out_buffer.data() + header->metadata_offset, data.metadata_json.data(), metadata_size);
    }
    
    // Calculate checksum
    if (has_flag(config.flags, LoRAFileFlags::CHECKSUM_CRC32)) {
        header->crc32_checksum = calculate_crc32(out_buffer.data(), total_size);
    }
    
    return SerializeResult::SUCCESS;
}

SerializeResult AdapterSerializer::deserialize_from_buffer(
    const std::vector<uint8_t>& buffer,
    AdapterData& out_data,
    const Config& config) {
    
    if (buffer.size() < sizeof(LoRAFileHeader)) {
        return SerializeResult::ERROR_INVALID_DATA;
    }
    
    const LoRAFileHeader* header = reinterpret_cast<const LoRAFileHeader*>(buffer.data());
    
    if (!validate_header(*header)) {
        return SerializeResult::ERROR_INVALID_MAGIC;
    }
    
    // Verify checksum
    if (config.validate_checksums && has_flag(static_cast<LoRAFileFlags>(header->flags), LoRAFileFlags::CHECKSUM_CRC32)) {
        uint32_t stored_crc = header->crc32_checksum;
        
        // Create mutable copy for checksum calculation
        std::vector<uint8_t> mutable_buffer = buffer;
        LoRAFileHeader* mutable_header = reinterpret_cast<LoRAFileHeader*>(mutable_buffer.data());
        mutable_header->crc32_checksum = 0;
        
        uint32_t calculated_crc = calculate_crc32(mutable_buffer.data(), mutable_buffer.size());
        
        if (stored_crc != calculated_crc) {
            return SerializeResult::ERROR_CHECKSUM_MISMATCH;
        }
    }
    
    // Extract data
    out_data.rank = header->rank;
    out_data.in_features = header->in_features;
    out_data.out_features = header->out_features;
    
    out_data.matrix_a.resize(header->rank * header->in_features);
    out_data.matrix_b.resize(header->out_features * header->rank);
    
    std::memcpy(out_data.matrix_a.data(), buffer.data() + header->matrix_a_offset, header->matrix_a_size);
    std::memcpy(out_data.matrix_b.data(), buffer.data() + header->matrix_b_offset, header->matrix_b_size);
    
    if (header->metadata_size > 0) {
        out_data.metadata_json.resize(header->metadata_size);
        std::memcpy(out_data.metadata_json.data(), buffer.data() + header->metadata_offset, header->metadata_size);
    }
    
    return SerializeResult::SUCCESS;
}

// ============================================================================
// Validation and Peeking
// ============================================================================

SerializeResult AdapterSerializer::validate(
    const std::filesystem::path& filepath,
    LoRAFileHeader* out_header) {
    
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        return SerializeResult::ERROR_FILE_OPEN;
    }
    
    LoRAFileHeader header;
    if (!read_header(file, header)) {
        return SerializeResult::ERROR_FILE_READ;
    }
    
    if (out_header) {
        *out_header = header;
    }
    
    if (!validate_header(header)) {
        return SerializeResult::ERROR_INVALID_MAGIC;
    }
    
    return SerializeResult::SUCCESS;
}

std::optional<AdapterData> AdapterSerializer::peek(
    const std::filesystem::path& filepath) {
    
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    
    LoRAFileHeader header;
    if (!read_header(file, header) || !validate_header(header)) {
        return std::nullopt;
    }
    
    AdapterData data;
    data.rank = header.rank;
    data.in_features = header.in_features;
    data.out_features = header.out_features;
    
    // Read metadata if present
    if (header.metadata_size > 0) {
        data.metadata_json.resize(header.metadata_size);
        file.seekg(header.metadata_offset);
        file.read(data.metadata_json.data(), header.metadata_size);
    }
    
    return data;
}

// ============================================================================
// Upgrade
// ============================================================================

SerializeResult AdapterSerializer::upgrade(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    uint16_t target_version) {
    
    if (target_version > LORA_FORMAT_VERSION_CURRENT) {
        return SerializeResult::ERROR_UNSUPPORTED_VERSION;
    }
    
    AdapterData data;
    SerializeResult result = deserialize(input_path, data);
    if (result != SerializeResult::SUCCESS) {
        return result;
    }
    
    return serialize(data, output_path);
}

// ============================================================================
// AdapterCacheManager
// ============================================================================

AdapterCacheManager& AdapterCacheManager::instance() {
    static AdapterCacheManager instance;
    return instance;
}

void AdapterCacheManager::initialize(const CacheConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
}

std::optional<AdapterData> AdapterCacheManager::load(
    const std::string& adapter_name,
    bool bypass_cache) {
    
    if (!bypass_cache) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_cache.find(adapter_name);
        if (it != m_cache.end()) {
            // Check TTL
            auto now = std::chrono::system_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.timestamp);
            
            if (age < m_config.ttl) {
                it->second.access_count++;
                m_hits++;
                return it->second.data;
            }
            
            // Expired
            m_cache.erase(it);
        }
    }
    
    m_misses++;
    
    // Load from disk
    std::filesystem::path filepath = get_cache_path(adapter_name);
    AdapterData data;
    SerializeResult result = AdapterSerializer::deserialize(filepath, data);
    
    if (result != SerializeResult::SUCCESS) {
        return std::nullopt;
    }
    
    // Store in cache
    if (!bypass_cache) {
        store(adapter_name, data);
    }
    
    return data;
}

void AdapterCacheManager::store(const std::string& adapter_name, const AdapterData& data) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    CacheEntry entry;
    entry.data = data;
    entry.timestamp = std::chrono::system_clock::now();
    entry.access_count = 1;
    
    m_cache[adapter_name] = std::move(entry);
    
    evict_if_needed();
}

void AdapterCacheManager::invalidate(const std::string& adapter_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cache.erase(adapter_name);
}

void AdapterCacheManager::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cache.clear();
}

AdapterCacheManager::Stats AdapterCacheManager::get_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Stats stats;
    stats.entries_count = m_cache.size();
    stats.hits = m_hits.load();
    stats.misses = m_misses.load();
    stats.hit_rate = (stats.hits + stats.misses > 0) 
        ? static_cast<float>(stats.hits) / (stats.hits + stats.misses) 
        : 0.0f;
    
    stats.memory_used_bytes = 0;
    for (const auto& [name, entry] : m_cache) {
        stats.memory_used_bytes += entry.data.total_size_bytes();
    }
    
    return stats;
}

void AdapterCacheManager::evict_if_needed() {
    while (m_cache.size() > m_config.max_adapters) {
        // Find least recently used
        auto lru_it = m_cache.begin();
        for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
            if (it->second.timestamp < lru_it->second.timestamp) {
                lru_it = it;
            }
        }
        m_cache.erase(lru_it);
    }
    
    // Check memory limit
    size_t total_memory = 0;
    for (const auto& [name, entry] : m_cache) {
        total_memory += entry.data.total_size_bytes();
    }
    
    while (total_memory > m_config.max_memory_mb * 1024 * 1024 && !m_cache.empty()) {
        auto lru_it = m_cache.begin();
        for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
            if (it->second.timestamp < lru_it->second.timestamp) {
                lru_it = it;
            }
        }
        total_memory -= lru_it->second.data.total_size_bytes();
        m_cache.erase(lru_it);
    }
}

std::filesystem::path AdapterCacheManager::get_cache_path(const std::string& name) const {
    const char* user_profile = std::getenv("USERPROFILE");
    if (user_profile) {
        return std::filesystem::path(user_profile) / ".rawrxd" / "adapters" / (name + ".lora");
    }
    return std::filesystem::temp_directory_path() / "rawrxd_adapters" / (name + ".lora");
}

// ============================================================================
// Utility Functions
// ============================================================================

bool quick_save_adapter(
    const std::string& name,
    const std::vector<float>& A,
    const std::vector<float>& B,
    uint32_t rank,
    uint32_t in_features,
    uint32_t out_features) {
    
    AdapterData data;
    data.matrix_a = A;
    data.matrix_b = B;
    data.rank = rank;
    data.in_features = in_features;
    data.out_features = out_features;
    
    const char* user_profile = std::getenv("USERPROFILE");
    std::filesystem::path filepath;
    if (user_profile) {
        filepath = std::filesystem::path(user_profile) / ".rawrxd" / "adapters" / (name + ".lora");
    } else {
        filepath = std::filesystem::temp_directory_path() / "rawrxd_adapters" / (name + ".lora");
    }
    
    std::filesystem::create_directories(filepath.parent_path());
    
    SerializeResult result = AdapterSerializer::serialize(data, filepath);
    return result == SerializeResult::SUCCESS;
}

std::optional<AdapterData> quick_load_adapter(const std::string& name) {
    return AdapterCacheManager::instance().load(name);
}

std::vector<std::string> list_available_adapters() {
    std::vector<std::string> result;
    
    const char* user_profile = std::getenv("USERPROFILE");
    std::filesystem::path adapter_dir;
    if (user_profile) {
        adapter_dir = std::filesystem::path(user_profile) / ".rawrxd" / "adapters";
    } else {
        adapter_dir = std::filesystem::temp_directory_path() / "rawrxd_adapters";
    }
    
    if (!std::filesystem::exists(adapter_dir)) {
        return result;
    }
    
    for (const auto& entry : std::filesystem::directory_iterator(adapter_dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".lora") {
            result.push_back(entry.path().stem().string());
        }
    }
    
    return result;
}

bool delete_adapter(const std::string& name) {
    // Remove from cache
    AdapterCacheManager::instance().invalidate(name);
    
    // Remove from disk
    const char* user_profile = std::getenv("USERPROFILE");
    std::filesystem::path filepath;
    if (user_profile) {
        filepath = std::filesystem::path(user_profile) / ".rawrxd" / "adapters" / (name + ".lora");
    } else {
        filepath = std::filesystem::temp_directory_path() / "rawrxd_adapters" / (name + ".lora");
    }
    
    return std::filesystem::remove(filepath);
}

bool copy_adapter(const std::string& source, const std::string& dest) {
    auto data = quick_load_adapter(source);
    if (!data) {
        return false;
    }
    
    return quick_save_adapter(dest, data->matrix_a, data->matrix_b,
                              data->rank, data->in_features, data->out_features);
}

} // namespace RawrXD

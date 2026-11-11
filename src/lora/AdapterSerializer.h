#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <mutex>
#include <chrono>

// ============================================================================
// LoRA Adapter Serialization
// ============================================================================
// Handles persistence of LoRA weights with:
// - Versioned binary format for backward compatibility
// - Alignment guarantees for SIMD loading
// - Checksum validation for integrity
// - Compression support for large adapters
// - Cross-platform endianness handling

namespace RawrXD {

// Binary format version history:
// 1.0 (0x0100): Initial format
// 1.1 (0x0101): Added compression support
// 2.0 (0x0200): Added multi-adapter chains
constexpr uint16_t LORA_FORMAT_VERSION_CURRENT = 0x0100;
constexpr uint16_t LORA_FORMAT_VERSION_MIN = 0x0100;

// Magic number for file identification
constexpr char LORA_MAGIC[8] = {'R', 'A', 'W', 'R', 'L', 'O', 'R', 'A'};

// File flags
enum class LoRAFileFlags : uint32_t {
    NONE = 0,
    COMPRESSED_ZSTD = 1 << 0,    // ZSTD compression
    COMPRESSED_LZ4 = 1 << 1,     // LZ4 compression
    ENCRYPTED_AES = 1 << 2,      // AES-256-GCM encryption
    CHECKSUM_CRC32 = 1 << 3,     // CRC32 checksum
    CHECKSUM_SHA256 = 1 << 4,    // SHA256 checksum
    ALIGN_64 = 1 << 5,           // 64-byte alignment (AVX-512)
    CHAIN_MEMBER = 1 << 6         // Part of adapter chain
};

inline LoRAFileFlags operator|(LoRAFileFlags a, LoRAFileFlags b) {
    return static_cast<LoRAFileFlags>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b)
    );
}

inline bool has_flag(LoRAFileFlags flags, LoRAFileFlags flag) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
}

// ============================================================================
// Binary File Header (64 bytes, aligned)
// ============================================================================
#pragma pack(push, 1)
struct LoRAFileHeader {
    char magic[8];                     // "RAWRLORA"
    uint16_t version;                  // Format version
    uint16_t reserved;                 // Padding
    uint32_t flags;                    // LoRAFileFlags
    
    // Dimensions
    uint32_t rank;
    uint32_t in_features;
    uint32_t out_features;
    uint32_t reserved2;              // Padding to 8 bytes
    
    // Data offsets (from file start)
    uint64_t matrix_a_offset;          // Offset to A matrix data
    uint64_t matrix_b_offset;          // Offset to B matrix data
    uint64_t metadata_offset;          // Offset to JSON metadata
    
    // Data sizes
    uint64_t matrix_a_size;            // Size in bytes (uncompressed)
    uint64_t matrix_b_size;            // Size in bytes (uncompressed)
    uint64_t metadata_size;            // Size in bytes
    
    // Integrity
    uint32_t crc32_checksum;           // CRC32 of header + data
    uint32_t reserved3;                // Padding
};
static_assert(sizeof(LoRAFileHeader) == 88, "Header must be 88 bytes");
#pragma pack(pop)

// ============================================================================
// Serialization Result
// ============================================================================
enum class SerializeResult {
    SUCCESS = 0,
    ERROR_FILE_OPEN,
    ERROR_FILE_WRITE,
    ERROR_FILE_READ,
    ERROR_INVALID_MAGIC,
    ERROR_UNSUPPORTED_VERSION,
    ERROR_INVALID_DIMENSIONS,
    ERROR_ALIGNMENT,
    ERROR_CHECKSUM_MISMATCH,
    ERROR_COMPRESSION_FAILED,
    ERROR_OUT_OF_MEMORY,
    ERROR_INVALID_DATA
};

const char* serialize_result_to_string(SerializeResult result);

// ============================================================================
// Adapter Data Container
// ============================================================================
struct AdapterData {
    std::vector<float> matrix_a;      // [rank, in_features]
    std::vector<float> matrix_b;      // [out_features, rank]
    uint32_t rank = 0;
    uint32_t in_features = 0;
    uint32_t out_features = 0;
    
    // Metadata (JSON string)
    std::string metadata_json;
    
    // Validation
    bool is_valid() const {
        if (rank == 0 || in_features == 0 || out_features == 0) return false;
        if (matrix_a.size() != rank * in_features) return false;
        if (matrix_b.size() != out_features * rank) return false;
        return true;
    }
    
    size_t total_size_bytes() const {
        return (matrix_a.size() + matrix_b.size()) * sizeof(float);
    }
};

// ============================================================================
// Adapter Serializer
// ============================================================================
class AdapterSerializer {
public:
    // Configuration for serialization
    struct Config {
        LoRAFileFlags flags = LoRAFileFlags::CHECKSUM_CRC32;
        int compression_level = 3;       // 1-22 for ZSTD, 1-12 for LZ4
        bool verify_alignment = true;      // Check 32/64-byte alignment
        bool validate_checksums = true;    // Verify on load
        
        static Config fast();              // Minimal overhead
        static Config compact();           // Maximum compression
        static Config secure();            // Encryption + SHA256
    };
    
    // Serialize adapter to file
    static SerializeResult serialize(
        const AdapterData& data,
        const std::filesystem::path& filepath,
        const Config& config = Config::fast()
    );
    
    // Deserialize adapter from file
    static SerializeResult deserialize(
        const std::filesystem::path& filepath,
        AdapterData& out_data,
        const Config& config = Config::fast()
    );
    
    // Serialize to memory buffer (for network transmission)
    static SerializeResult serialize_to_buffer(
        const AdapterData& data,
        std::vector<uint8_t>& out_buffer,
        const Config& config = Config::fast()
    );
    
    // Deserialize from memory buffer
    static SerializeResult deserialize_from_buffer(
        const std::vector<uint8_t>& buffer,
        AdapterData& out_data,
        const Config& config = Config::fast()
    );
    
    // Validate file without full deserialization
    static SerializeResult validate(
        const std::filesystem::path& filepath,
        LoRAFileHeader* out_header = nullptr
    );
    
    // Get file info without loading
    static std::optional<AdapterData> peek(
        const std::filesystem::path& filepath
    );
    
    // Upgrade file format
    static SerializeResult upgrade(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path,
        uint16_t target_version = LORA_FORMAT_VERSION_CURRENT
    );

private:
    // Internal helpers
    static uint32_t calculate_crc32(const void* data, size_t size);
    static bool validate_header(const LoRAFileHeader& header);
    static bool write_header(std::ofstream& file, const LoRAFileHeader& header);
    static bool read_header(std::ifstream& file, LoRAFileHeader& header);
    
    // Compression helpers (stubs - implement with zstd/lz4 if available)
    static std::vector<uint8_t> compress_zstd(
        const void* data, size_t size, int level
    );
    static std::vector<uint8_t> decompress_zstd(
        const void* data, size_t compressed_size, size_t original_size
    );
    
    // Alignment helpers
    static size_t align_size(size_t size, size_t alignment);
    static void* align_pointer(void* ptr, size_t alignment);
};

// ============================================================================
// Adapter Cache Manager
// ============================================================================
class AdapterCacheManager {
public:
    static AdapterCacheManager& instance();
    
    // Cache configuration
    struct CacheConfig {
        size_t max_memory_mb = 512;        // Max memory for cached adapters
        size_t max_adapters = 50;          // Max number of cached adapters
        std::chrono::seconds ttl{3600};    // Time-to-live for cached entries
    };
    
    void initialize(const CacheConfig& config);
    
    // Load adapter (from cache or disk)
    std::optional<AdapterData> load(
        const std::string& adapter_name,
        bool bypass_cache = false
    );
    
    // Store adapter in cache
    void store(const std::string& adapter_name, const AdapterData& data);
    
    // Invalidate cache entry
    void invalidate(const std::string& adapter_name);
    
    // Clear entire cache
    void clear();
    
    // Cache statistics
    struct Stats {
        size_t entries_count;
        size_t memory_used_bytes;
        size_t hits;
        size_t misses;
        float hit_rate;
    };
    Stats get_stats() const;

private:
    AdapterCacheManager() = default;
    
    struct CacheEntry {
        AdapterData data;
        std::chrono::system_clock::time_point timestamp;
        size_t access_count;
    };
    
    std::unordered_map<std::string, CacheEntry> m_cache;
    CacheConfig m_config;
    mutable std::mutex m_mutex;
    
    std::atomic<size_t> m_hits{0};
    std::atomic<size_t> m_misses{0};
    
    void evict_if_needed();
    std::filesystem::path get_cache_path(const std::string& name) const;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Quick save/load for common use cases
bool quick_save_adapter(
    const std::string& name,
    const std::vector<float>& A,
    const std::vector<float>& B,
    uint32_t rank,
    uint32_t in_features,
    uint32_t out_features
);

std::optional<AdapterData> quick_load_adapter(const std::string& name);

// List all available adapters
std::vector<std::string> list_available_adapters();

// Delete adapter
bool delete_adapter(const std::string& name);

// Copy adapter
bool copy_adapter(const std::string& source, const std::string& dest);

} // namespace RawrXD

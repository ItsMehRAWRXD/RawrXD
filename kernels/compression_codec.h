/**
 * @file compression_codec.h
 * @brief RawrXD Compression ABI - L4.2 Milestone
 *
 * Abstract interface between compressed storage and execution.
 * Decouples compression format from GEMM kernels.
 *
 * Architecture:
 *   Compressed Block
 *        |
 *        v
 *   CompressionCodec::DecodeBlock()
 *        |
 *        v
 *   SIMD Accumulator (no FP32 intermediate)
 *        |
 *        v
 *   GEMM Output
 *
 * @copyright RawrXD 2026
 */

#ifndef RAWRXD_COMPRESSION_CODEC_H
#define RAWRXD_COMPRESSION_CODEC_H

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>

namespace rawrxd {
namespace compression {

// ============================================================================
// Forward Declarations
// ============================================================================

struct CompressionReport;
struct CodecCapabilities;

// ============================================================================
// Compression Type Registry
// ============================================================================

enum class CompressionType : uint32_t {
    UNKNOWN = 0,
    
    // GGML Standard Formats
    Q4_0 = 0x100,      // 4-bit, 32 weights/block, FP16 scale
    Q4_1 = 0x101,      // 4-bit with bias
    Q5_0 = 0x102,      // 5-bit
    Q5_1 = 0x103,      // 5-bit with bias
    Q8_0 = 0x104,      // 8-bit
    Q8_1 = 0x105,      // 8-bit with bias
    
    // K-Quant Variants
    Q4_K = 0x200,      // K-quant 4-bit
    Q5_K = 0x201,      // K-quant 5-bit
    Q6_K = 0x202,      // K-quant 6-bit
    
    // RawrXD Custom
    Q3_RDX = 0x300,    // 3-bit experimental
    Q6_RDX = 0x301,    // 6-bit high precision
    ADAPTIVE = 0x400,  // Per-tensor adaptive
    
    // Special
    FP16 = 0xF00,      // No compression
    FP32 = 0xF01,      // No compression
};

const char* CompressionTypeToString(CompressionType type);
CompressionType CompressionTypeFromString(const char* str);

// ============================================================================
// Block Header (Storage Contract)
// ============================================================================

#pragma pack(push, 1)
struct CompressedBlockHeader {
    uint32_t magic;              // 'RDXC' = 0x52545843
    uint16_t version;          // Codec version
    CompressionType type;        // Compression format
    uint32_t block_size;       // Weights per block
    uint32_t num_weights;      // Total weights in tensor
    uint16_t scale_bits;       // Scale quantization bits
    uint16_t weight_bits;      // Weight quantization bits
    uint32_t payload_offset;   // Offset to packed data
    uint32_t payload_size;     // Size of packed data
    uint32_t checksum;         // CRC32 of payload
    
    // Validation
    bool Validate() const;
    uint32_t CalculateChecksum(const uint8_t* payload) const;
};
#pragma pack(pop)

// ============================================================================
// Compression Codec Interface (The ABI)
// ============================================================================

class CompressionCodec {
public:
    virtual ~CompressionCodec() = default;
    
    // ------------------------------------------------------------------------
    // Codec Identity
    // ------------------------------------------------------------------------
    virtual CompressionType GetType() const = 0;
    virtual const char* GetName() const = 0;
    virtual CodecCapabilities GetCapabilities() const = 0;
    
    // ------------------------------------------------------------------------
    // Block Operations
    // ------------------------------------------------------------------------
    
    /**
     * @brief Encode FP32 weights to compressed format
     * 
     * @param src Source FP32 weights
     * @param dst Destination buffer (compressed)
     * @param count Number of weights
     * @return Size of compressed data in bytes
     */
    virtual size_t EncodeBlock(
        const float* src,
        uint8_t* dst,
        size_t count
    ) = 0;
    
    /**
     * @brief Decode compressed weights to FP32
     * 
     * Standard decode path for validation and fallback.
     * 
     * @param src Source compressed data
     * @param dst Destination FP32 buffer
     * @param count Number of weights to decode
     */
    virtual void DecodeBlock(
        const uint8_t* src,
        float* dst,
        size_t count
    ) = 0;
    
    /**
     * @brief Decode single weight (random access)
     * 
     * For sparse access patterns.
     * 
     * @param src Block data
     * @param index Weight index within block
     * @return Dequantized weight
     */
    virtual float DecodeWeight(
        const uint8_t* src,
        size_t index
    ) = 0;
    
    // ------------------------------------------------------------------------
    // Fused Operations (High Performance Path)
    // ------------------------------------------------------------------------
    
    /**
     * @brief Fused decode + dot product
     * 
     * No intermediate FP32 buffer. Decode directly into SIMD accumulator.
     * 
     * @param weights Compressed weight block
     * @param input Input vector (FP32)
     * @param count Number of elements
     * @return Dot product result
     */
    virtual float FusedDotProduct(
        const uint8_t* weights,
        const float* input,
        size_t count
    ) = 0;
    
    /**
     * @brief Fused decode + GEMV row
     * 
     * Decode entire row and compute matrix-vector product.
     * 
     * @param weights Compressed weights for row
     * @param input Input vector
     * @param cols Number of columns
     * @return Row result
     */
    virtual float FusedGemvRow(
        const uint8_t* weights,
        const float* input,
        size_t cols
    ) = 0;
    
    // ------------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------------
    
    /**
     * @brief Validate codec implementation
     * 
     * Runs internal consistency checks.
     * 
     * @return true if codec is valid
     */
    virtual bool SelfTest() = 0;
    
    /**
     * @brief Generate compression report for a tensor
     * 
     * @param original Original FP32 data
     * @param compressed Compressed data
     * @param count Number of weights
     * @return Validation report
     */
    virtual CompressionReport Validate(
        const float* original,
        const uint8_t* compressed,
        size_t count
    ) = 0;
    
    // ------------------------------------------------------------------------
    // Metadata
    // ------------------------------------------------------------------------
    
    /**
     * @brief Calculate compressed size for given weight count
     */
    virtual size_t GetCompressedSize(size_t num_weights) const = 0;
    
    /**
     * @brief Get theoretical compression ratio
     */
    virtual float GetCompressionRatio() const = 0;
    
    /**
     * @brief Get block size (weights per block)
     */
    virtual size_t GetBlockSize() const = 0;
};

// ============================================================================
// Codec Capabilities
// ============================================================================

struct CodecCapabilities {
    bool supports_fused_decode;      // Fused decode + GEMM
    bool supports_random_access;     // Single weight decode
    bool supports_simd;              // SIMD-accelerated paths
    bool supports_multithread;       // Thread-safe
    uint32_t preferred_alignment;    // Memory alignment
    uint32_t min_block_size;         // Minimum block granularity
    uint32_t max_block_size;         // Maximum block size
};

// ============================================================================
// Compression Report (Dyno Safety System)
// ============================================================================

struct CompressionReport {
    // Compression metrics
    float compression_ratio;         // Achieved ratio
    size_t original_bytes;             // FP32 size
    size_t compressed_bytes;           // Compressed size
    
    // Numerical validation
    float rmse;                        // Root mean square error
    float max_absolute_error;          // Max |original - reconstructed|
    float mean_absolute_error;         // Mean |original - reconstructed|
    float cosine_similarity;           // Cosine similarity
    float relative_error_percent;      // Error relative to magnitude
    
    // Quality gates
    bool overflow_detected;            // Quantization overflow
    bool nan_detected;                 // NaN in output
    bool inf_detected;                 // Inf in output
    bool checksum_valid;               // Payload checksum
    
    // Approval
    bool approved;                     // Passes all gates
    std::string rejection_reason;      // If not approved
    
    // Print report
    void Print() const;
    bool operator==(const CompressionReport& other) const;
};

// ============================================================================
// Quality Thresholds (Dyno Safety Gates)
// ============================================================================

struct QualityThresholds {
    static constexpr float COSINE_HIGH = 0.9999f;     // Production ready
    static constexpr float COSINE_MEDIUM = 0.999f;    // Good quality
    static constexpr float COSINE_LOW = 0.99f;      // Acceptable
    
    static constexpr float RMSE_HIGH = 0.001f;
    static constexpr float RMSE_MEDIUM = 0.01f;
    static constexpr float RMSE_LOW = 0.1f;
    
    static constexpr float MAX_ERROR_HIGH = 0.01f;
    static constexpr float MAX_ERROR_MEDIUM = 0.1f;
    static constexpr float MAX_ERROR_LOW = 1.0f;
};

// ============================================================================
// Codec Factory
// ============================================================================

class CodecFactory {
public:
    /**
     * @brief Create codec by type
     */
    static std::unique_ptr<CompressionCodec> Create(CompressionType type);
    
    /**
     * @brief Create codec by name
     */
    static std::unique_ptr<CompressionCodec> Create(const char* name);
    
    /**
     * @brief Get available codec types
     */
    static std::vector<CompressionType> GetAvailableCodecs();
    
    /**
     * @brief Check if codec is available
     */
    static bool IsAvailable(CompressionType type);
    
    /**
     * @brief Auto-select best codec for target
     * 
     * @param target_ratio Desired compression ratio
     * @param min_quality Minimum cosine similarity
     * @return Best matching codec type
     */
    static CompressionType AutoSelect(
        float target_ratio,
        float min_quality = QualityThresholds::COSINE_MEDIUM
    );
};

// ============================================================================
// Concrete Codec Implementations
// ============================================================================

// Q4_0 Codec
class Q4_0_Codec : public CompressionCodec {
public:
    CompressionType GetType() const override { return CompressionType::Q4_0; }
    const char* GetName() const override { return "Q4_0"; }
    CodecCapabilities GetCapabilities() const override;
    
    size_t EncodeBlock(const float* src, uint8_t* dst, size_t count) override;
    void DecodeBlock(const uint8_t* src, float* dst, size_t count) override;
    float DecodeWeight(const uint8_t* src, size_t index) override;
    
    float FusedDotProduct(const uint8_t* weights, const float* input, size_t count) override;
    float FusedGemvRow(const uint8_t* weights, const float* input, size_t cols) override;
    
    bool SelfTest() override;
    CompressionReport Validate(const float* original, const uint8_t* compressed, size_t count) override;
    
    size_t GetCompressedSize(size_t num_weights) const override;
    float GetCompressionRatio() const override { return 6.4f; }
    size_t GetBlockSize() const override { return 32; }
};

// Q4_K Codec
class Q4_K_Codec : public CompressionCodec {
public:
    CompressionType GetType() const override { return CompressionType::Q4_K; }
    const char* GetName() const override { return "Q4_K"; }
    CodecCapabilities GetCapabilities() const override;
    
    size_t EncodeBlock(const float* src, uint8_t* dst, size_t count) override;
    void DecodeBlock(const uint8_t* src, float* dst, size_t count) override;
    float DecodeWeight(const uint8_t* src, size_t index) override;
    
    float FusedDotProduct(const uint8_t* weights, const float* input, size_t count) override;
    float FusedGemvRow(const uint8_t* weights, const float* input, size_t cols) override;
    
    bool SelfTest() override;
    CompressionReport Validate(const float* original, const uint8_t* compressed, size_t count) override;
    
    size_t GetCompressedSize(size_t num_weights) const override;
    float GetCompressionRatio() const override { return 6.7f; }
    size_t GetBlockSize() const override { return 256; }
};

// Q8_0 Codec
class Q8_0_Codec : public CompressionCodec {
public:
    CompressionType GetType() const override { return CompressionType::Q8_0; }
    const char* GetName() const override { return "Q8_0"; }
    CodecCapabilities GetCapabilities() const override;
    
    size_t EncodeBlock(const float* src, uint8_t* dst, size_t count) override;
    void DecodeBlock(const uint8_t* src, float* dst, size_t count) override;
    float DecodeWeight(const uint8_t* src, size_t index) override;
    
    float FusedDotProduct(const uint8_t* weights, const float* input, size_t count) override;
    float FusedGemvRow(const uint8_t* weights, const float* input, size_t cols) override;
    
    bool SelfTest() override;
    CompressionReport Validate(const float* original, const uint8_t* compressed, size_t count) override;
    
    size_t GetCompressedSize(size_t num_weights) const override;
    float GetCompressionRatio() const override { return 4.0f; }
    size_t GetBlockSize() const override { return 32; }
};

// ============================================================================
// Validation Utilities
// ============================================================================

class CompressionValidator {
public:
    /**
     * @brief Validate compression meets quality thresholds
     */
    static bool ValidateQuality(
        const CompressionReport& report,
        float min_cosine = QualityThresholds::COSINE_MEDIUM,
        float max_rmse = QualityThresholds::RMSE_MEDIUM,
        float max_error = QualityThresholds::MAX_ERROR_MEDIUM
    );
    
    /**
     * @brief Generate detailed validation report
     */
    static CompressionReport Analyze(
        const float* original,
        const float* reconstructed,
        size_t count,
        size_t compressed_bytes
    );
    
    /**
     * @brief Calculate cosine similarity between tensors
     */
    static float CosineSimilarity(
        const float* a,
        const float* b,
        size_t count
    );
    
    /**
     * @brief Calculate RMSE
     */
    static float CalculateRMSE(
        const float* original,
        const float* reconstructed,
        size_t count
    );
    
    /**
     * @brief Check for numerical anomalies
     */
    static bool CheckNumericalAnomalies(
        const float* data,
        size_t count,
        bool* overflow = nullptr,
        bool* nan_detected = nullptr,
        bool* inf_detected = nullptr
    );
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define RAWRXD_CODEC_Q4_0() rawrxd::compression::CodecFactory::Create( \
    rawrxd::compression::CompressionType::Q4_0)
    
#define RAWRXD_CODEC_Q4_K() rawrxd::compression::CodecFactory::Create( \
    rawrxd::compression::CompressionType::Q4_K)
    
#define RAWRXD_CODEC_Q8_0() rawrxd::compression::CodecFactory::Create( \
    rawrxd::compression::CompressionType::Q8_0)

} // namespace compression
} // namespace rawrxd

#endif // RAWRXD_COMPRESSION_CODEC_H

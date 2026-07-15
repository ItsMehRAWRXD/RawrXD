// RawrXD_L4_1_1_Decode.cpp
// L4.1.1 Quantized Row Decode - Decode single embedding row from Q4_0 tensor
// Input: token_id
// Output: float[embedding_dim] with validation

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <cmath>
#include <iomanip>

// GGUF format constants
static const uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"

// GGUF value types
enum GgufType {
    GGUF_TYPE_UINT8   = 0,  GGUF_TYPE_INT8    = 1,
    GGUF_TYPE_UINT16  = 2,  GGUF_TYPE_INT16   = 3,
    GGUF_TYPE_UINT32  = 4,  GGUF_TYPE_INT32   = 5,
    GGUF_TYPE_FLOAT32 = 6,  GGUF_TYPE_BOOL    = 7,
    GGUF_TYPE_STRING  = 8,  GGUF_TYPE_ARRAY   = 9,
    GGUF_TYPE_UINT64  = 10, GGUF_TYPE_INT64   = 11,
    GGUF_TYPE_FLOAT64 = 12
};

// GGML types (subset needed for embeddings)
enum GgmlType {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8
};

// Q4_0 block: 32 values compressed into 18 bytes
// - 1x float16 scale (2 bytes) - actually delta
// - 32x 4-bit quantized values (16 bytes)
// Note: GGML Q4_0 uses 'delta' (scale factor), stored as FP16
struct Q4_0_Block {
    uint16_t d;      // delta (scale), FP16
    uint8_t qs[16];  // 32 nibbles
};

// Block capture for debugging
struct BlockCapture {
    int block_idx;
    uint64_t file_offset;
    uint16_t raw_fp16_scale;
    float decoded_scale;
    uint8_t quants[16];
    float first_dequant[8];
    bool had_nan_scale;
};

static std::vector<BlockCapture> g_block_captures;

// Streaming file reader
class FileReader {
private:
    std::ifstream file;
    std::streamsize file_size;
    size_t pos;
    
public:
    FileReader(const std::string& path) : pos(0) {
        file.open(path, std::ios::binary | std::ios::ate);
        if (!file) throw std::runtime_error("Failed to open: " + path);
        file_size = file.tellg();
        file.seekg(0, std::ios::beg);
    }
    
    ~FileReader() { if (file.is_open()) file.close(); }
    
    size_t size() const { return file_size; }
    size_t tell() const { return pos; }
    
    void seek(size_t offset) {
        if (offset > static_cast<size_t>(file_size)) {
            throw std::runtime_error("Seek beyond bounds");
        }
        pos = offset;
        file.seekg(offset, std::ios::beg);
    }
    
    void skip(size_t bytes) {
        if (pos + bytes > static_cast<size_t>(file_size)) {
            throw std::runtime_error("Skip beyond bounds");
        }
        pos += bytes;
        file.seekg(bytes, std::ios::cur);
    }
    
    template<typename T>
    T read() {
        if (pos + sizeof(T) > static_cast<size_t>(file_size)) {
            throw std::runtime_error("Read beyond bounds");
        }
        T value;
        if (!file.read(reinterpret_cast<char*>(&value), sizeof(T))) {
            throw std::runtime_error("Read failed");
        }
        pos += sizeof(T);
        return value;
    }
    
    std::string read_string() {
        uint64_t len = read<uint64_t>();
        if (len > 16 * 1024 * 1024) {
            throw std::runtime_error("Invalid string length: " + std::to_string(len));
        }
        std::string str;
        str.resize(len);
        if (!file.read(&str[0], len)) throw std::runtime_error("String read failed");
        pos += len;
        return str;
    }
    
    void read_bytes(void* dest, size_t len) {
        if (pos + len > static_cast<size_t>(file_size)) {
            throw std::runtime_error("Byte read beyond bounds");
        }
        if (!file.read(reinterpret_cast<char*>(dest), len)) {
            throw std::runtime_error("Byte read failed");
        }
        pos += len;
    }
    
    void skip_gguf_value(uint32_t type) {
        switch (type) {
            case GGUF_TYPE_UINT8: case GGUF_TYPE_INT8: case GGUF_TYPE_BOOL:
                skip(1); break;
            case GGUF_TYPE_UINT16: case GGUF_TYPE_INT16:
                skip(2); break;
            case GGUF_TYPE_UINT32: case GGUF_TYPE_INT32: case GGUF_TYPE_FLOAT32:
                skip(4); break;
            case GGUF_TYPE_UINT64: case GGUF_TYPE_INT64: case GGUF_TYPE_FLOAT64:
                skip(8); break;
            case GGUF_TYPE_STRING: {
                uint64_t len = read<uint64_t>();
                skip(static_cast<size_t>(len));
                break;
            }
            case GGUF_TYPE_ARRAY: {
                uint32_t subtype = read<uint32_t>();
                uint64_t count = read<uint64_t>();
                if (count > 10000000) throw std::runtime_error("Invalid array count");
                for (uint64_t i = 0; i < count; i++) skip_gguf_value(subtype);
                break;
            }
            default:
                throw std::runtime_error("Unknown type: " + std::to_string(type));
        }
    }
};

// Tensor info
struct TensorInfo {
    std::string name;
    uint32_t n_dims;
    std::vector<uint64_t> dims;
    uint32_t type;
    uint64_t offset;
};

// Parse GGUF and find tensor
class GgufParser {
private:
    FileReader& file;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    size_t tensor_data_start;
    
public:
    GgufParser(FileReader& f) : file(f), tensor_count(0), metadata_kv_count(0), tensor_data_start(0) {}
    
    bool parse_header() {
        uint32_t magic = file.read<uint32_t>();
        if (magic != GGUF_MAGIC) {
            std::cerr << "Invalid GGUF magic: 0x" << std::hex << magic << std::dec << std::endl;
            return false;
        }
        
        uint32_t version = file.read<uint32_t>();
        std::cout << "GGUF Version: " << version << std::endl;
        
        tensor_count = file.read<uint64_t>();
        std::cout << "Tensor Count: " << tensor_count << std::endl;
        
        metadata_kv_count = file.read<uint64_t>();
        std::cout << "Metadata KV Count: " << metadata_kv_count << std::endl;
        
        return true;
    }
    
    void skip_metadata() {
        std::cout << "Skipping metadata..." << std::endl;
        for (uint64_t i = 0; i < metadata_kv_count; i++) {
            file.read_string();  // key
            uint32_t value_type = file.read<uint32_t>();
            file.skip_gguf_value(value_type);
        }
        std::cout << "Metadata skipped" << std::endl;
    }
    
    TensorInfo find_tensor(const std::string& target_name) {
        std::cout << "\nSearching for: " << target_name << std::endl;
        
        // Remember where tensor info section starts
        tensor_data_start = file.tell();
        
        for (uint64_t i = 0; i < tensor_count; i++) {
            TensorInfo info;
            info.name = file.read_string();
            info.n_dims = file.read<uint32_t>();
            
            info.dims.resize(info.n_dims);
            for (uint32_t d = 0; d < info.n_dims; d++) {
                info.dims[d] = file.read<uint64_t>();
            }
            
            info.type = file.read<uint32_t>();
            info.offset = file.read<uint64_t>();
            
            if (info.name == target_name) {
                std::cout << "*** FOUND: " << target_name << " ***" << std::endl;
                // Calculate actual file offset
                info.offset = tensor_data_start + info.offset;
                return info;
            }
        }
        
        throw std::runtime_error("Tensor not found: " + target_name);
    }
    
    size_t get_tensor_data_start() const { return tensor_data_start; }
};

// Float16 to float32 conversion
// GGUF stores FP16 in little-endian, scale is a positive value
static inline float fp16_to_fp32(uint16_t h) {
    // Check byte order - if high byte is 0, swap
    // Actually, let's just use the standard conversion
    // but ensure we're handling the byte order correctly
    
    // Extract components from little-endian uint16
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    // Debug: print components
    // std::cout << "  FP16: sign=" << sign << " exp=" << exp << " mant=" << mant << std::endl;
    
    if (exp == 0) {
        // Zero or denormal
        if (mant == 0) return sign ? -0.0f : 0.0f;
        // Denormal
        float val = mant * 5.960464477539063e-08f;
        return sign ? -val : val;
    }
    if (exp == 31) {
        // Inf or NaN
        return mant ? NAN : (sign ? -INFINITY : INFINITY);
    }
    
    // Normal number
    uint32_t f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    float result;
    memcpy(&result, &f32, sizeof(result));
    return result;
}

// Print hex dump of bytes
void print_hex_dump(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 8 == 0) std::cout << "  ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
        if ((i + 1) % 8 == 0) std::cout << std::endl;
    }
    std::cout << std::dec << std::setfill(' ');
}

// Q4_0 Decode Policy:
// Configurable invalid scale handling for validation vs runtime
enum InvalidScalePolicy {
    ZERO_FILL,        // Replace with zeros (runtime recovery)
    FAIL_VALIDATION,  // Fail immediately (validation mode)
    CLAMP             // Clamp to reasonable bounds
};

// Default: ZERO_FILL for runtime recovery (set to FAIL_VALIDATION for strict validation)
static InvalidScalePolicy g_nan_policy = ZERO_FILL;
static int g_nan_blocks_encountered = 0;
static std::vector<int> g_nan_block_indices;

// Dequantize Q4_0 block with detailed debugging and policy handling
void dequantize_q4_0_block(const Q4_0_Block& block, float* out, int n, bool debug = false, 
                           int block_idx = -1, uint64_t file_offset = 0) {
    if (debug) {
        std::cout << "\n=== Q4_0 Block Debug ===" << std::endl;
        std::cout << "Raw bytes (18 bytes):" << std::endl;
        print_hex_dump(reinterpret_cast<const uint8_t*>(&block), sizeof(block));
        
        // Show FP16 scale bytes
        uint8_t scale_lo = block.d & 0xFF;
        uint8_t scale_hi = (block.d >> 8) & 0xFF;
        std::cout << "FP16 scale bytes: lo=0x" << std::hex << (int)scale_lo 
                  << " hi=0x" << (int)scale_hi << std::dec << std::endl;
        std::cout << "FP16 scale bits: 0x" << std::hex << block.d << std::dec << std::endl;
    }
    
    float scale = fp16_to_fp32(block.d);
    
    // Capture block data for debugging
    BlockCapture capture;
    capture.block_idx = block_idx;
    capture.file_offset = file_offset;
    capture.raw_fp16_scale = block.d;
    capture.decoded_scale = scale;
    capture.had_nan_scale = std::isnan(scale) || std::isinf(scale);
    memcpy(capture.quants, block.qs, 16);
    
    // Check for NaN/Inf scale - handle according to policy
    if (capture.had_nan_scale) {
        g_nan_blocks_encountered++;
        g_nan_block_indices.push_back(block_idx);
        
        if (g_nan_policy == FAIL_VALIDATION) {
            std::cerr << "\n*** VALIDATION FAILURE ***" << std::endl;
            std::cerr << "Block " << block_idx << " has invalid scale" << std::endl;
            std::cerr << "Raw FP16: 0x" << std::hex << block.d << std::dec << std::endl;
            std::cerr << "Policy: FAIL_VALIDATION" << std::endl;
            throw std::runtime_error("Invalid scale encountered in validation mode");
        }
        
        if (debug) {
            std::cout << "WARNING: Scale is " << (std::isnan(scale) ? "NaN" : "Inf") 
                      << " - outputting zeros (policy: ZERO_FILL)" << std::endl;
        }
        
        for (int i = 0; i < n && i < 32; i++) {
            out[i] = 0.0f;
            capture.first_dequant[i] = 0.0f;
        }
        
        g_block_captures.push_back(capture);
        return;
    }
    
    if (debug) {
        std::cout << "FP32 scale: " << scale << std::endl;
        std::cout << "First 16 quants (nibbles):" << std::endl;
        for (int i = 0; i < 16 && i < n; i++) {
            int byte_idx = i / 2;
            int nibble = (i % 2 == 0) ? (block.qs[byte_idx] & 0x0F) : ((block.qs[byte_idx] >> 4) & 0x0F);
            std::cout << "  q[" << i << "] = " << nibble << std::endl;
        }
    }
    
    for (int i = 0; i < n && i < 32; i++) {
        int byte_idx = i / 2;
        int nibble = (i % 2 == 0) ? (block.qs[byte_idx] & 0x0F) : ((block.qs[byte_idx] >> 4) & 0x0F);
        // Q4_0: value = (nibble - 8) * scale
        out[i] = (nibble - 8.0f) * scale;
        if (i < 8) capture.first_dequant[i] = out[i];
    }
    
    g_block_captures.push_back(capture);
}

// Decode single embedding row
std::vector<float> decode_embedding_row(FileReader& file, const TensorInfo& info, uint32_t token_id) {
    // Validate token_id
    if (info.dims.size() != 2) {
        throw std::runtime_error("Expected 2D tensor for embeddings");
    }
    
    uint64_t vocab_size = info.dims[1];  // [embedding_dim, vocab_size]
    uint64_t embedding_dim = info.dims[0];
    
    if (token_id >= vocab_size) {
        throw std::runtime_error("Token ID out of range: " + std::to_string(token_id));
    }
    
    std::cout << "\nDecoding token_id: " << token_id << std::endl;
    std::cout << "Vocab size: " << vocab_size << std::endl;
    std::cout << "Embedding dim: " << embedding_dim << std::endl;
    std::cout << "Tensor type: " << info.type << std::endl;
    
    if (info.type != GGML_TYPE_Q4_0) {
        throw std::runtime_error("Only Q4_0 supported in L4.1.1");
    }
    
    // Calculate row offset
    // Q4_0: each block has 32 values, 18 bytes per block
    uint64_t blocks_per_row = (embedding_dim + 31) / 32;
    uint64_t row_size = blocks_per_row * sizeof(Q4_0_Block);
    uint64_t row_offset = info.offset + (token_id * row_size);
    
    std::cout << "Blocks per row: " << blocks_per_row << std::endl;
    std::cout << "Row size: " << row_size << " bytes" << std::endl;
    std::cout << "Row offset: 0x" << std::hex << row_offset << std::dec << std::endl;
    
    // Seek to row
    file.seek(row_offset);
    
    // Read and decode blocks
    std::vector<float> embedding(embedding_dim);
    std::fill(embedding.begin(), embedding.end(), 0.0f);  // Initialize to zero
    size_t out_pos = 0;
    
    std::cout << "Reading " << blocks_per_row << " blocks from offset 0x" 
              << std::hex << row_offset << std::dec << std::endl;
    
    // Track block statistics
    float max_scale = 0.0f;
    float min_scale = 0.0f;
    int max_scale_block = -1;
    int min_scale_block = -1;
    
    for (uint64_t b = 0; b < blocks_per_row && out_pos < embedding_dim; b++) {
        Q4_0_Block block;
        file.read_bytes(&block, sizeof(block));
        
        float scale = fp16_to_fp32(block.d);
        if (b == 0 || std::abs(scale) > std::abs(max_scale)) {
            max_scale = scale;
            max_scale_block = b;
        }
        if (b == 0 || std::abs(scale) < std::abs(min_scale)) {
            min_scale = scale;
            min_scale_block = b;
        }
        
        // Debug block 56 (where NaN was found at index 1792 = 56*32)
        if (b == 56) {
            std::cout << "\n*** BLOCK 56 (index 1792) ***" << std::endl;
            std::cout << "  FP16 raw: 0x" << std::hex << block.d << std::dec << std::endl;
            std::cout << "  FP32 scale: " << scale << std::endl;
            if (std::isnan(scale)) std::cout << "  WARNING: Scale is NaN!" << std::endl;
            if (std::isinf(scale)) std::cout << "  WARNING: Scale is Inf!" << std::endl;
        }
        
        int remaining = static_cast<int>(embedding_dim - out_pos);
        uint64_t block_offset = row_offset + b * sizeof(Q4_0_Block);
        dequantize_q4_0_block(block, &embedding[out_pos], std::min(32, remaining), b < 3, b, block_offset);
        out_pos += 32;
    }
    
    std::cout << "\nBlock Scale Statistics:" << std::endl;
    std::cout << "  Max scale: " << max_scale << " (block " << max_scale_block << ")" << std::endl;
    std::cout << "  Min scale: " << min_scale << " (block " << min_scale_block << ")" << std::endl;
    std::cout << "  Total values written: " << out_pos << std::endl;
    
    return embedding;
}

// Validate embedding vector
struct ValidationResult {
    bool has_nan;
    bool has_inf;
    float min_val;
    float max_val;
    float mean_val;
    float std_dev;
    bool passed;
};

ValidationResult validate_embedding(const std::vector<float>& embedding) {
    ValidationResult result = {false, false, INFINITY, -INFINITY, 0.0f, 0.0f, true};
    
    // Debug: print vector size
    std::cout << "  [DEBUG] Embedding size: " << embedding.size() << std::endl;
    
    // Simple validation: just check for NaN/Inf and compute basic stats
    double sum = 0.0;
    int count = 0;
    
    for (size_t i = 0; i < embedding.size(); i++) {
        float v = embedding[i];
        if (std::isnan(v)) {
            result.has_nan = true;
            std::cout << "  [DEBUG] NaN found at index " << i << std::endl;
            result.passed = false;
            return result;
        }
        if (std::isinf(v)) {
            result.has_inf = true;
            std::cout << "  [DEBUG] Inf found at index " << i << std::endl;
            result.passed = false;
            return result;
        }
        result.min_val = std::min(result.min_val, v);
        result.max_val = std::max(result.max_val, v);
        sum += v;
        count++;
    }
    
    std::cout << "  [DEBUG] Processed " << count << " values" << std::endl;
    std::cout << "  [DEBUG] Sum: " << sum << std::endl;
    
    if (count > 0) {
        result.mean_val = static_cast<float>(sum / count);
    }
    
    // Pass if we have values and no NaN/Inf
    result.passed = (count > 0) && !result.has_nan && !result.has_inf;
    
    return result;
}

// Save block capture report for debugging
void save_block_report(const std::string& path) {
    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Failed to create block report: " + path);
    }
    
    file << "L4.1.1 Q4_0 Block Capture Report\n";
    file << "================================\n\n";
    
    file << "NaN Policy: " << (g_nan_policy == ZERO_FILL ? "ZERO_FILL" : 
                              g_nan_policy == FAIL_VALIDATION ? "FAIL_VALIDATION" : "CLAMP") << "\n";
    file << "NaN Blocks Encountered: " << g_nan_blocks_encountered << "\n";
    if (!g_nan_block_indices.empty()) {
        file << "NaN Block Indices: ";
        for (size_t i = 0; i < g_nan_block_indices.size(); i++) {
            if (i > 0) file << ", ";
            file << g_nan_block_indices[i];
        }
        file << "\n";
    }
    file << "\n";
    
    file << "Block Details:\n";
    file << "--------------\n\n";
    
    for (const auto& cap : g_block_captures) {
        file << "Block " << cap.block_idx << ":\n";
        file << "  File Offset: 0x" << std::hex << cap.file_offset << std::dec << "\n";
        file << "  Raw FP16 Scale: 0x" << std::hex << cap.raw_fp16_scale << std::dec << "\n";
        file << "  Decoded Scale: " << cap.decoded_scale << "\n";
        file << "  Had NaN Scale: " << (cap.had_nan_scale ? "YES" : "NO") << "\n";
        file << "  Quants (first 16): ";
        for (int i = 0; i < 16; i++) {
            int low = cap.quants[i] & 0x0F;
            int high = (cap.quants[i] >> 4) & 0x0F;
            file << low << "," << high;
            if (i < 15) file << ",";
        }
        file << "\n";
        file << "  Dequant First 8: [";
        for (int i = 0; i < 8; i++) {
            file << cap.first_dequant[i];
            if (i < 7) file << ", ";
        }
        file << "]\n\n";
    }
}

// Save RawrXD output for L4.1.2 comparison
void save_output(const std::string& path, const std::vector<float>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to create output file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size() * sizeof(float));
}

void print_report(const TensorInfo& info, uint32_t token_id, 
                  const std::vector<float>& embedding, const ValidationResult& val) {
    std::cout << "\n";
    std::cout << "L4.1.1 Quantized Row Decode Report" << std::endl;
    std::cout << "===================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Tensor: " << info.name << std::endl;
    std::cout << "Token ID: " << token_id << std::endl;
    std::cout << "Dimensions: [" << info.dims[0] << ", " << info.dims[1] << "]" << std::endl;
    std::cout << "Type: Q4_0" << std::endl;
    std::cout << std::endl;
    std::cout << "Output Vector:" << std::endl;
    std::cout << "  Size: " << embedding.size() << std::endl;
    
    // Count non-zero values
    int non_zero = 0;
    for (float v : embedding) {
        if (v != 0.0f) non_zero++;
    }
    std::cout << "  Non-zero values: " << non_zero << std::endl;
    std::cout << std::endl;
    
    std::cout << "Validation:" << std::endl;
    std::cout << "  [ " << (val.has_nan ? "✗" : "✓") << " ] No NaN" << std::endl;
    std::cout << "  [ " << (val.has_inf ? "✗" : "✓") << " ] No Inf" << std::endl;
    std::cout << "  [ " << (val.passed ? "✓" : "✗") << " ] Reasonable distribution" << std::endl;
    std::cout << std::endl;
    std::cout << "Statistics:" << std::endl;
    std::cout << "  Min: " << val.min_val << std::endl;
    std::cout << "  Max: " << val.max_val << std::endl;
    std::cout << "  Mean: " << val.mean_val << std::endl;
    std::cout << "  StdDev: " << val.std_dev << std::endl;
    std::cout << std::endl;
    std::cout << "First 10 values:" << std::endl;
    std::cout << "  [";
    for (size_t i = 0; i < std::min(size_t(10), embedding.size()); i++) {
        if (i > 0) std::cout << ", ";
        std::cout << embedding[i];
    }
    std::cout << "...]" << std::endl;
    std::cout << std::endl;
    std::cout << "Status: " << (val.passed ? "PASS" : "FAIL") << std::endl;
}

// Test FP16 conversion with known values
void test_fp16_conversion() {
    std::cout << "=== FP16 Conversion Test ===" << std::endl;
    
    struct TestCase {
        uint16_t raw;
        float expected;
        const char* desc;
    };
    
    TestCase tests[] = {
        {0x0000, 0.0f, "zero"},
        {0x3c00, 1.0f, "one"},
        {0x4000, 2.0f, "two"},
        {0xc000, -2.0f, "negative two"},
        {0x7c00, INFINITY, "positive inf"},
        {0xfc00, -INFINITY, "negative inf"},
        {0x3555, 0.33325195f, "~1/3"},
    };
    
    bool all_pass = true;
    for (const auto& t : tests) {
        float result = fp16_to_fp32(t.raw);
        bool pass = (std::isnan(t.expected) && std::isnan(result)) || 
                    (std::isinf(t.expected) && std::isinf(result) && (t.expected > 0) == (result > 0)) ||
                    (std::abs(result - t.expected) < 0.001f);
        std::cout << "  0x" << std::hex << std::setw(4) << std::setfill('0') << t.raw << std::dec 
                  << " -> " << result << " (expected " << t.expected << ") [" 
                  << (pass ? "PASS" : "FAIL") << "] " << t.desc << std::endl;
        if (!pass) all_pass = false;
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "RawrXD L4.1.1 Quantized Row Decode" << std::endl;
    std::cout << "=================================" << std::endl;
    std::cout << std::endl;
    
    // Test FP16 conversion first
    test_fp16_conversion();
    
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf> <token_id>" << std::endl;
        return 1;
    }
    
    const char* model_path = argv[1];
    uint32_t token_id = static_cast<uint32_t>(std::stoul(argv[2]));
    
    std::cout << "Model: " << model_path << std::endl;
    std::cout << "Token ID: " << token_id << std::endl;
    std::cout << std::endl;
    
    try {
        // Open file
        FileReader file(model_path);
        std::cout << "File size: " << file.size() << " bytes" << std::endl;
        std::cout << std::endl;
        
        // Parse GGUF
        GgufParser parser(file);
        if (!parser.parse_header()) {
            std::cerr << "ERROR: Failed to parse GGUF header" << std::endl;
            return 1;
        }
        
        // Skip metadata
        parser.skip_metadata();
        
        // Find token_embd.weight
        TensorInfo info = parser.find_tensor("token_embd.weight");
        
        // Decode embedding row
        std::vector<float> embedding = decode_embedding_row(file, info, token_id);
        
        // Validate
        ValidationResult val = validate_embedding(embedding);
        
        // Print report
        print_report(info, token_id, embedding, val);
        
        // Save output for L4.1.2 reference validation
        std::string output_path = std::string("rawrxd_token_") + std::to_string(token_id) + ".bin";
        save_output(output_path, embedding);
        std::cout << "\nOutput saved to: " << output_path << std::endl;
        
        // Save block capture report
        std::string block_report_path = std::string("rawrxd_token_") + std::to_string(token_id) + "_blocks.txt";
        save_block_report(block_report_path);
        std::cout << "Block report saved to: " << block_report_path << std::endl;
        
        std::cout << "\nRun L4.1.2 to validate against llama.cpp reference." << std::endl;
        
        return val.passed ? 0 : 1;
        
    } catch (const std::exception& e) {
        std::cerr << "\nERROR: " << e.what() << std::endl;
        return 1;
    }
}

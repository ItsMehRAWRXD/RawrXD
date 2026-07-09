// L4_2_0_TensorRuntime.cpp
// L4.2.0 Tensor Runtime Implementation
// Depends on: L4.1_FROZEN_CONTRACT.md

#include "L4_2_0_TensorRuntime.h"
#include <fstream>
#include <iostream>
#include <cmath>
#include <algorithm>

namespace RawrXD {
namespace L4 {

// ============================================================================
// FP16 Conversion (from L4.1 contract)
// ============================================================================

static inline float FP16ToFP32(uint16_t h) {
    const uint32_t sign = (h >> 15) & 0x1;
    const uint32_t exp = (h >> 10) & 0x1F;
    const uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        // Subnormal
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f * 0.00006103515625f;
        return sign ? -val : val;
    }
    if (exp == 0x1F) {
        // Inf/NaN
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    // Normal
    const uint32_t exp32 = exp + 112;
    const uint32_t mant32 = mant << 13;
    const uint32_t fp32 = (sign << 31) | (exp32 << 23) | mant32;
    
    union { uint32_t i; float f; } conv;
    conv.i = fp32;
    return conv.f;
}

// ============================================================================
// Q4_0 Block Structure (from L4.1 contract)
// ============================================================================

struct Q4_0_Block {
    uint16_t scale;    // FP16 scale
    uint8_t quants[16]; // 32 nibbles packed
};

static_assert(sizeof(Q4_0_Block) == 18, "Q4_0 block must be 18 bytes");

// Dequantize Q4_0 block (L4.1 compliant)
static void DequantizeQ4_0_Block(
    const Q4_0_Block* block,
    float* output,
    int n_values = 32
) {
    float scale = FP16ToFP32(block->scale);
    
    // NaN/Inf policy: ZERO_FILL (L4.1 contract Section 4)
    if (std::isnan(scale) || std::isinf(scale)) {
        for (int i = 0; i < n_values; i++) {
            output[i] = 0.0f;
        }
        return;
    }
    
    for (int i = 0; i < 16 && (i * 2) < n_values; i++) {
        uint8_t byte = block->quants[i];
        int low = (byte & 0x0F) - 8;
        int high = ((byte >> 4) & 0x0F) - 8;
        
        output[i * 2] = low * scale;
        if ((i * 2 + 1) < n_values) {
            output[i * 2 + 1] = high * scale;
        }
    }
}

// ============================================================================
// TensorView Implementation
// ============================================================================

uint64_t TensorView::num_elements() const {
    uint64_t count = 1;
    for (auto d : dims) count *= d;
    return count;
}

uint64_t TensorView::num_rows() const {
    return dims.size() > 1 ? dims[1] : 1;
}

uint64_t TensorView::row_size() const {
    if (type == QuantType::Q4_0) {
        // Q4_0: 18 bytes per block, 32 values per block
        uint64_t blocks_per_row = (dims[0] + 31) / 32;
        return blocks_per_row * 18;
    }
    return dims[0] * sizeof(float); // F32 fallback
}

// ============================================================================
// File Reader (streaming for large files)
// ============================================================================

class FileReader {
private:
    std::ifstream file_;
    size_t file_size_;
    size_t pos_;

public:
    explicit FileReader(const std::string& path) : pos_(0) {
        file_.open(path, std::ios::binary | std::ios::ate);
        if (!file_) {
            throw std::runtime_error("Failed to open: " + path);
        }
        file_size_ = file_.tellg();
        file_.seekg(0, std::ios::beg);
    }
    
    ~FileReader() { if (file_.is_open()) file_.close(); }
    
    size_t size() const { return file_size_; }
    size_t tell() const { return pos_; }
    
    void seek(size_t offset) {
        if (offset > file_size_) {
            throw std::runtime_error("Seek beyond file bounds");
        }
        pos_ = offset;
        file_.seekg(offset, std::ios::beg);
    }
    
    template<typename T>
    T read() {
        if (pos_ + sizeof(T) > file_size_) {
            throw std::runtime_error("Read beyond file bounds");
        }
        T value;
        if (!file_.read(reinterpret_cast<char*>(&value), sizeof(T))) {
            throw std::runtime_error("Failed to read");
        }
        pos_ += sizeof(T);
        return value;
    }
    
    void skip(size_t bytes) {
        if (pos_ + bytes > file_size_) {
            throw std::runtime_error("Skip beyond file bounds");
        }
        file_.seekg(bytes, std::ios::cur);
        pos_ += bytes;
    }
    
    void read_bytes(void* dest, size_t count) {
        if (pos_ + count > file_size_) {
            throw std::runtime_error("Read beyond file bounds");
        }
        if (!file_.read(static_cast<char*>(dest), count)) {
            throw std::runtime_error("Failed to read bytes");
        }
        pos_ += count;
    }
    
    std::string read_string() {
        uint64_t len = read<uint64_t>();
        if (len > 16 * 1024 * 1024) {
            throw std::runtime_error("Invalid string length");
        }
        std::string str(len, '\0');
        read_bytes(&str[0], len);
        return str;
    }
};

// ============================================================================
// TensorRuntime Implementation
// ============================================================================

class TensorRuntime::Impl {
public:
    std::unique_ptr<FileReader> file_;
    std::unordered_map<std::string, TensorView> tensor_registry_;
    uint64_t tensor_data_start_ = 0;
    Stats stats_ = {};
    std::shared_ptr<IKernelDispatch> kernel_dispatch_;
    
    bool initialized_ = false;
    
    // GGUF constants
    static constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"
    static constexpr uint32_t GGUF_VERSION = 3;
    
    bool Initialize(const std::string& path) {
        try {
            file_ = std::make_unique<FileReader>(path);
            ParseGGUF();
            initialized_ = true;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "TensorRuntime init failed: " << e.what() << std::endl;
            return false;
        }
    }
    
    void ParseGGUF() {
        // Header
        uint32_t magic = file_->read<uint32_t>();
        if (magic != GGUF_MAGIC) {
            throw std::runtime_error("Invalid GGUF magic");
        }
        
        uint32_t version = file_->read<uint32_t>();
        if (version != GGUF_VERSION) {
            throw std::runtime_error("Unsupported GGUF version");
        }
        
        uint64_t tensor_count = file_->read<uint64_t>();
        uint64_t metadata_kv_count = file_->read<uint64_t>();
        
        // Skip metadata
        for (uint64_t i = 0; i < metadata_kv_count; i++) {
            SkipMetadataKV();
        }
        
        tensor_data_start_ = file_->tell();
        
        // Parse tensor info
        for (uint64_t i = 0; i < tensor_count; i++) {
            ParseTensorInfo();
        }
    }
    
    void SkipGGUFValue(uint32_t type) {
        switch (type) {
            case 0: case 1: case 7: // UINT8, INT8, BOOL
                file_->skip(1); break;
            case 2: case 3: // UINT16, INT16
                file_->skip(2); break;
            case 4: case 5: case 6: // UINT32, INT32, FLOAT32
                file_->skip(4); break;
            case 8: { // STRING
                uint64_t len = file_->read<uint64_t>();
                file_->skip(static_cast<size_t>(len));
                break;
            }
            case 9: { // ARRAY
                uint32_t subtype = file_->read<uint32_t>();
                uint64_t count = file_->read<uint64_t>();
                if (count > 10000000) throw std::runtime_error("Invalid array count");
                for (uint64_t i = 0; i < count; i++) SkipGGUFValue(subtype);
                break;
            }
            case 10: case 11: // UINT64, INT64
                file_->skip(8); break;
            case 12: // FLOAT64
                file_->skip(8); break;
            default:
                throw std::runtime_error("Unknown GGUF type: " + std::to_string(type));
        }
    }
    
    void SkipMetadataKV() {
        file_->read_string();  // key
        uint32_t type = file_->read<uint32_t>();
        SkipGGUFValue(type);
    }
    
    void SkipArray() {
        uint32_t type = file_->read<uint32_t>();
        uint64_t len = file_->read<uint64_t>();
        
        if (type == 8) { // String array
            for (uint64_t i = 0; i < len; i++) {
                std::string str = file_->read_string();
            }
        }
        // Other array types would need size calculation
    }
    
    void ParseTensorInfo() {
        std::string name = file_->read_string();
        uint32_t n_dims = file_->read<uint32_t>();
        
        TensorView view;
        view.name = name;
        view.dims.resize(n_dims);
        for (uint32_t d = 0; d < n_dims; d++) {
            view.dims[d] = file_->read<uint64_t>();
        }
        
        view.type = static_cast<QuantType>(file_->read<uint32_t>());
        uint64_t rel_offset = file_->read<uint64_t>();
        
        view.data_offset = tensor_data_start_ + rel_offset;
        view.tensor_data_start = tensor_data_start_;
        
        tensor_registry_[name] = view;
    }
    
    bool ReadRow(const TensorView& tensor, uint64_t row_index, float* output) {
        if (!initialized_) return false;
        
        uint64_t row_offset = tensor.data_offset + (row_index * tensor.row_size());
        
        try {
            file_->seek(row_offset);
            
            if (tensor.type == QuantType::Q4_0) {
                // Read and dequantize Q4_0 blocks
                uint64_t blocks_per_row = (tensor.dims[0] + 31) / 32;
                size_t out_pos = 0;
                
                for (uint64_t b = 0; b < blocks_per_row && out_pos < tensor.dims[0]; b++) {
                    Q4_0_Block block;
                    file_->read_bytes(&block, sizeof(block));
                    
                    int remaining = static_cast<int>(tensor.dims[0] - out_pos);
                    DequantizeQ4_0_Block(&block,
                        &output[out_pos],
                        std::min(32, remaining)
                    );
                    out_pos += 32;
                }
                
                stats_.rows_read++;
                stats_.bytes_read += blocks_per_row * 18;
                return true;
            }
            
            return false; // Unsupported type
        } catch (const std::exception& e) {
            std::cerr << "ReadRow failed: " << e.what() << std::endl;
            return false;
        }
    }
};

// ============================================================================
// TensorRuntime Public Interface
// ============================================================================

TensorRuntime::TensorRuntime() : pImpl(std::make_unique<Impl>()) {}
TensorRuntime::~TensorRuntime() = default;

bool TensorRuntime::Initialize(const std::string& gguf_path) {
    return pImpl->Initialize(gguf_path);
}

void TensorRuntime::Shutdown() {
    pImpl->initialized_ = false;
    pImpl->file_.reset();
    pImpl->tensor_registry_.clear();
}

TensorView TensorRuntime::GetTensor(const std::string& name) {
    auto it = pImpl->tensor_registry_.find(name);
    if (it != pImpl->tensor_registry_.end()) {
        return it->second;
    }
    throw std::runtime_error("Tensor not found: " + name);
}

bool TensorRuntime::HasTensor(const std::string& name) const {
    return pImpl->tensor_registry_.count(name) > 0;
}

bool TensorRuntime::ReadRow(
    const TensorView& tensor,
    uint64_t row_index,
    float* output
) {
    return pImpl->ReadRow(tensor, row_index, output);
}

WeightBuffer TensorRuntime::ReadTensor(const TensorView& tensor) {
    WeightBuffer buffer;
    buffer.shape = tensor.dims;
    buffer.data.resize(tensor.num_elements());
    
    // For 2D tensors (like embeddings), read row by row
    if (tensor.dims.size() == 2) {
        uint64_t rows = tensor.dims[1];
        uint64_t cols = tensor.dims[0];
        
        for (uint64_t r = 0; r < rows; r++) {
            if (!ReadRow(tensor, r, &buffer.data[r * cols])) {
                throw std::runtime_error("Failed to read row " + std::to_string(r));
            }
        }
    }
    
    return buffer;
}

std::vector<std::string> TensorRuntime::ListTensors() const {
    std::vector<std::string> names;
    for (const auto& [name, view] : pImpl->tensor_registry_) {
        names.push_back(name);
    }
    return names;
}

ITensorRuntime::Stats TensorRuntime::GetStats() const {
    return pImpl->stats_;
}

void TensorRuntime::SetKernelDispatch(std::shared_ptr<IKernelDispatch> dispatch) {
    pImpl->kernel_dispatch_ = dispatch;
}

bool TensorRuntime::ExecuteGEMV(
    const TensorView& weights,
    const float* input,
    float* output,
    uint64_t row_count
) {
    // TODO: Implement fused GEMV using kernel dispatch
    // For now, fall back to row-by-row read
    
    uint64_t cols = weights.dims[0];
    
    for (uint64_t r = 0; r < row_count; r++) {
        std::vector<float> row(cols);
        if (!ReadRow(weights, r, row.data())) {
            return false;
        }
        
        // Simple dot product
        float sum = 0.0f;
        for (uint64_t c = 0; c < cols; c++) {
            sum += row[c] * input[c];
        }
        output[r] = sum;
    }
    
    return true;
}

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<ITensorRuntime> CreateTensorRuntime() {
    return std::make_unique<TensorRuntime>();
}

} // namespace L4
} // namespace RawrXD

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <variant>

namespace rawrxd {

enum class GGUFType : uint32_t {
    Uint8 = 0, Int8 = 1, Uint16 = 2, Int16 = 3, Uint32 = 4,
    Int32 = 5, Float32 = 6, Uint64 = 7, Int64 = 8, Float64 = 9,
    Bool = 10, String = 11, Array = 12, Uint32Array = 13,
    Int32Array = 14, Float32Array = 15, Uint64Array = 16,
    Int64Array = 17, Float64Array = 18, BoolArray = 19,
    StringArray = 20
};

// Tensor *data* types. This is the ggml type enum, which is a DIFFERENT
// numbering space from GGUFType (the metadata KV enum above). Reusing GGUFType
// for tensor data mis-sizes every quantized tensor, because e.g. ggml Q4_K
// (12) collides with GGUFType::Array and falls through to a 4-byte element.
enum class GGMLType : uint32_t {
    F32  = 0,  F16  = 1,  Q4_0 = 2,  Q4_1 = 3,  Q5_0 = 6,  Q5_1 = 7,
    Q8_0 = 8,  Q8_1 = 9,  Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13,
    Q6_K = 14, Q8_K = 15, IQ2_XXS = 16, IQ2_XS = 17, IQ3_XXS = 18,
    IQ1_S = 19, IQ4_NL = 20, IQ3_S = 21, IQ2_S = 22, IQ4_XS = 23,
    I8 = 24, I16 = 25, I32 = 26, I64 = 27, F64 = 28, IQ1_M = 29,
    BF16 = 30
};

// Bytes occupied by one block of `type`. Block-quantized types report the
// whole super-block, not one element. Returns 0 for unknown types.
size_t GGMLBlockSize(GGMLType type);
size_t GGMLTypeSize(GGMLType type);
const char* GGMLTypeName(GGMLType type);

struct GGUFMetadataValue {
    GGUFType type;
    std::variant<
        uint8_t, int8_t, uint16_t, int16_t, uint32_t, int32_t,
        float, uint64_t, int64_t, double, bool, std::string,
        std::vector<uint32_t>, std::vector<int32_t>, std::vector<float>,
        std::vector<uint64_t>, std::vector<int64_t>, std::vector<double>,
        std::vector<bool>, std::vector<std::string>
    > value;
};

struct GGUFTensorInfo {
    std::string name;
    GGUFType type;                        // retained for legacy callers
    GGMLType ggml_type = GGMLType::F32;  // authoritative element/block encoding
    std::vector<uint64_t> shape;
    uint64_t offset;
    size_t element_size;   // bytes per element (or per block for quantized)
    size_t block_size;     // elements per block (1 for unquantized)
    size_t byte_size;      // total bytes occupied in the data section
    size_t element_count;  // logical element count after dequantization
};

struct GGUFHeader {
    char magic[4];
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
    bool valid = false;
};

struct GGUFModel {
    GGUFHeader header;
    std::map<std::string, GGUFMetadataValue> metadata;
    std::vector<GGUFTensorInfo> tensors;
    std::vector<uint8_t> raw_data;
    size_t data_offset = 0;
};

class GGUFTensorView {
public:
    GGUFTensorView() = default;
    GGUFTensorView(const uint8_t* data, const GGUFTensorInfo& info);

    template<typename T>
    const T* data() const { return reinterpret_cast<const T*>(data_); }

    size_t count() const;
    size_t byte_size() const { return info_.byte_size; }
    size_t block_size() const { return info_.block_size; }
    GGUFType type() const;
    const std::vector<uint64_t>& shape() const;
    std::string name() const;

    // Dequantize the whole tensor into `out` as float32. Handles F32, F16,
    // BF16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0 and the K-quants Q2_K..Q6_K.
    // Returns false if the encoding is unsupported or the buffer is short;
    // `out` is left untouched in that case.
    bool ToFloat32(std::vector<float>& out) const;

    // Dequantize rows [row_begin, row_end) of a 2-D tensor with `cols`
    // columns each. Rows are independent for every supported encoding,
    // because every block size divides the column count.
    bool ToFloat32Rows(std::vector<float>& out, size_t row_begin,
                       size_t row_end, size_t cols) const;

private:
    const uint8_t* data_ = nullptr;
    GGUFTensorInfo info_;
};

// fp16 <-> fp32 helpers (exported for reuse by kernels and tests).
float FP16ToFP32(uint16_t h);
uint16_t FP32ToFP16(float f);

class GGUFTensorWriter {
public:
    void AddTensor(const std::string& name, GGUFType type,
                   const std::vector<uint64_t>& shape,
                   const std::vector<uint8_t>& data);
    bool WriteToFile(const std::string& path,
                     const std::map<std::string, GGUFMetadataValue>& metadata);
private:
    std::vector<GGUFTensorInfo> tensors_;
    std::vector<std::vector<uint8_t>> tensor_data_;
};

class GGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader();

    bool LoadFromFile(const std::string& path);
    bool LoadFromMemory(const std::vector<uint8_t>& buffer);

    bool IsLoaded() const;
    const GGUFModel* GetModel() const;

    std::optional<GGUFMetadataValue> GetMetadata(const std::string& key) const;
    std::optional<GGUFTensorView> GetTensor(const std::string& name) const;
    std::vector<std::string> ListTensors() const;
    std::vector<std::string> ListMetadataKeys() const;

    std::optional<uint32_t> GetUint32Metadata(const std::string& key) const;
    std::optional<float> GetFloat32Metadata(const std::string& key) const;
    std::optional<std::string> GetStringMetadata(const std::string& key) const;
    std::optional<uint64_t> GetUint64Metadata(const std::string& key) const;

    void Unload();

    static bool ValidateMagic(const std::vector<uint8_t>& header_bytes);
    static std::string TypeToString(GGUFType type);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd
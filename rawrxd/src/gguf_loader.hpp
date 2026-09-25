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
    GGUFType type;
    std::vector<uint64_t> shape;
    uint64_t offset;
    size_t element_size;
    size_t byte_size;
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
    GGUFType type() const;
    const std::vector<uint64_t>& shape() const;
    std::string name() const;

private:
    const uint8_t* data_ = nullptr;
    GGUFTensorInfo info_;
};

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
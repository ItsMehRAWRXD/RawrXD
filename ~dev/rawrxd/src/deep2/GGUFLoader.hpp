#pragma once
// Stub: GGUF loader (Deep2 namespace)
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <unordered_map>

namespace Deep2 {
enum class GGMLType : uint32_t {
    GGML_TYPE_F32   = 0,
    GGML_TYPE_F16   = 1,
    GGML_TYPE_Q4_0  = 2,
    GGML_TYPE_Q4_1  = 3,
    GGML_TYPE_Q5_0  = 6,
    GGML_TYPE_Q5_1  = 7,
    GGML_TYPE_Q8_0  = 8,
    GGML_TYPE_Q2_K  = 10,
    GGML_TYPE_Q3_K  = 11,
    GGML_TYPE_Q4_K  = 12,
    GGML_TYPE_Q5_K  = 13,
    GGML_TYPE_Q6_K  = 14,
    GGML_TYPE_Q8_K  = 15,
    GGML_TYPE_BF16  = 30,
};

// Internal GGUF storage (not the runtime WeightTensor)
struct GGUFTensor {
    std::string name;
    GGMLType type = GGMLType::GGML_TYPE_F32;
    std::vector<uint8_t> data;
    std::vector<int64_t> shape;
    size_t numElements() const {
        size_t n = 1;
        for (auto d : shape) n *= static_cast<size_t>(d);
        return n;
    }
};

class GGUFLoader {
public:
    bool load(const std::string& /*path*/) { return true; }
    bool hasTensor(const std::string& name) const {
        return tensors_.find(name) != tensors_.end();
    }
    GGUFTensor* getTensor(const std::string& name) {
        auto it = tensors_.find(name);
        if (it != tensors_.end()) return &it->second;
        return nullptr;
    }
    std::vector<std::string> listTensors() const {
        std::vector<std::string> names;
        for (const auto& kv : tensors_) names.push_back(kv.first);
        return names;
    }
    bool setMetaInt(const std::string& key, int64_t value) {
        meta_int_[key] = value; return true;
    }
    bool setMetaFloat(const std::string& key, double value) {
        meta_float_[key] = value; return true;
    }
    int64_t getMetaInt(const std::string& key, int64_t def = 0) const {
        auto it = meta_int_.find(key);
        return it != meta_int_.end() ? it->second : def;
    }
    double getMetaFloat(const std::string& key, double def = 0.0) const {
        auto it = meta_float_.find(key);
        return it != meta_float_.end() ? it->second : def;
    }
    std::unordered_map<std::string, GGUFTensor> tensors_;
    std::unordered_map<std::string, int64_t> meta_int_;
    std::unordered_map<std::string, double> meta_float_;
};
} // namespace Deep2

struct GGUFLoadResult {
    bool ok = false;
    int mmapBound = 0;
};

inline bool load_gguf(const std::string& path, void* out) { return false; }

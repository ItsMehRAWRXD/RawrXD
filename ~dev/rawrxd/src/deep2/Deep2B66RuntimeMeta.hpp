#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace Deep2 {

struct B66TensorDesc {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t ggmlType = 0;
};

struct B66MetadataSource {
    std::unordered_map<std::string, uint64_t> u64;
    std::unordered_map<std::string, double> f64;
    std::unordered_map<std::string, std::string> str;
    std::vector<B66TensorDesc> tensors;
};

struct B66RuntimeMeta {
    std::string architecture;
    double totalParamsB = 0.0;
    double activeParamsB = 0.0;
    uint32_t layers = 0;
    uint32_t hidden = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t headDim = 0;
    uint32_t intermediate = 0;
    uint32_t experts = 0;
    uint32_t expertsPerToken = 0;
    uint32_t sharedExperts = 0;
    uint32_t context = 0;
    uint32_t qLoraRank = 0;
    uint32_t kvLoraRank = 0;
    uint32_t ropeDim = 0;
    bool useMLA = false;
    bool useSSM = false;
    bool useSlidingWindow = false;
    bool useHybridLinearAttention = false;
};

struct B66Result {
    bool pass = false;
    const char* failure = "UNSET";
    B66RuntimeMeta meta{};
};

class B66RuntimeMetaBinder {
public:
    static B66Result bind(const B66MetadataSource&) noexcept;
};

} // namespace Deep2

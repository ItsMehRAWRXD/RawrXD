#pragma once
#include "Common.hpp"

namespace rawrxd::swarm48 {

struct ModelLoadRequest {
    std::string model_path;
    DeviceId device{};
    std::uint64_t expected_weight_bytes{};
};

struct ResidentModel {
    ModelHandle handle{};
    DeviceId device{};
    std::string model_path;
    std::uint64_t weight_bytes{};
};

struct DecodeSequence {
    AgentId agent{};
    SessionId session{};
    KvHandle kv{};
    std::span<const std::int32_t> input_tokens;
    std::uint32_t position{};
    bool prefill{false};
    std::uint32_t max_new_tokens{1};
};

struct DecodeResult {
    AgentId agent{};
    bool ok{};
    bool finished{};
    std::int32_t token{};
    std::string error;
};

class IInferenceAdapter {
public:
    virtual ~IInferenceAdapter() = default;
    virtual ResidentModel load_shared(const ModelLoadRequest& req) = 0;
    virtual void unload_shared(ModelHandle handle) = 0;
    virtual std::vector<DecodeResult> decode_batch(
        const ResidentModel& model,
        std::span<const DecodeSequence> batch) = 0;
};

} // namespace rawrxd::swarm48

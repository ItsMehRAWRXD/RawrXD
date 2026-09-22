#pragma once
#include "Common.hpp"
#include "SharedModelRegistry.hpp"

namespace rawrxd::swarm48 {

enum class AgentState : std::uint8_t { waiting, runnable, decoding, waiting_tool, completed, failed, cancelled };

struct AgentSpec {
    AgentId id{};
    TeamId team{};
    std::string role;
    DeviceId device{};
    std::string model_path;
    std::uint64_t model_weight_bytes{};
    std::uint32_t priority{100};
    std::uint32_t max_new_tokens{1};
    std::uint64_t kv_bytes_per_token{16u * 1024u};
};

struct AgentSession {
    AgentSpec spec;
    SessionId session{};
    KvHandle kv{};
    AgentState state{AgentState::waiting};
    std::shared_ptr<const ResidentModel> model;
    std::vector<std::int32_t> tokens;
    std::vector<std::int32_t> generated;
    std::uint64_t enqueued_us{};
    std::uint64_t last_run_us{};
    std::uint32_t decode_steps{};
    std::string error;
};

} // namespace rawrxd::swarm48

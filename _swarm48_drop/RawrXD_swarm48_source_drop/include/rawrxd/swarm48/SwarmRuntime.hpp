#pragma once
#include "AgentSession.hpp"
#include "ContinuousBatcher.hpp"
#include "DeviceLeaseManager.hpp"
#include "PagedKVPool.hpp"
#include "ReceiptLedger.hpp"
#include "TeamCoordinator.hpp"

namespace rawrxd::swarm48 {

struct SwarmRuntimeConfig {
    std::uint32_t max_agents{48};
    std::uint32_t max_batch_per_model{16};
    std::uint64_t default_initial_kv_bytes{256u * 1024u};
};

struct TickStats {
    std::uint32_t runnable{};
    std::uint32_t decoded{};
    std::uint32_t completed{};
    std::uint32_t failed{};
    std::uint32_t batches{};
};

class SwarmRuntime {
public:
    SwarmRuntime(IInferenceAdapter& backend, SwarmRuntimeConfig cfg = {});

    void add_device(DeviceBudget budget, KvPoolConfig kv);
    void define_team(TeamDefinition team) { teams_.define(std::move(team)); }
    AgentId add_agent(AgentSpec spec, std::vector<std::int32_t> initial_tokens = {});
    bool set_runnable(AgentId id);
    bool append_input_tokens(AgentId id, std::span<const std::int32_t> tokens);
    void set_waiting_tool(AgentId id);
    void set_device_health(DeviceId device, bool healthy) { leases_.set_health(device, healthy); }
    bool cancel(AgentId id);
    TickStats tick();

    const AgentSession* get(AgentId id) const;
    std::size_t agent_count() const noexcept { return sessions_.size(); }
    std::size_t resident_model_count() const { return models_.resident_count(); }
    std::uint64_t kv_used_bytes(DeviceId device) const;
    ReceiptLedger& receipts() noexcept { return receipts_; }
    SharedModelRegistry& models() noexcept { return models_; }

private:
    AgentSession* mutable_get(AgentId id);

    IInferenceAdapter& backend_;
    SwarmRuntimeConfig cfg_;
    SharedModelRegistry models_;
    DeviceLeaseManager leases_;
    std::unordered_map<DeviceId, std::unique_ptr<PagedKVPool>> kv_;
    std::unordered_map<AgentId, AgentSession> sessions_;
    ContinuousBatcher batcher_;
    TeamCoordinator teams_;
    ReceiptLedger receipts_;
    SessionId next_session_{1};
};

} // namespace rawrxd::swarm48

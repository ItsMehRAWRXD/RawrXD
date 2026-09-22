#include "rawrxd/swarm48/SwarmRuntime.hpp"

namespace rawrxd::swarm48 {

SwarmRuntime::SwarmRuntime(IInferenceAdapter& backend, SwarmRuntimeConfig cfg)
    : backend_(backend), cfg_(cfg), models_(backend) {}

void SwarmRuntime::add_device(DeviceBudget budget, KvPoolConfig kv) {
    const auto id = budget.id;
    leases_.add_device(std::move(budget));
    kv_[id] = std::make_unique<PagedKVPool>(id, kv);
}

AgentId SwarmRuntime::add_agent(AgentSpec spec, std::vector<std::int32_t> initial_tokens) {
    if (sessions_.size() >= cfg_.max_agents) throw std::runtime_error("swarm max_agents exceeded");
    if (!spec.id) {
        AgentId candidate = 1;
        while (sessions_.contains(candidate)) ++candidate;
        spec.id = candidate;
    }
    if (sessions_.contains(spec.id)) throw std::runtime_error("duplicate agent id");
    auto kit = kv_.find(spec.device);
    if (kit == kv_.end()) throw std::runtime_error("agent device is not registered");
    const auto budget = leases_.budget(spec.device);
    if (!budget || !budget->healthy) throw std::runtime_error("agent device is unavailable");
    std::size_t on_device = 0;
    for (const auto& [_, existing] : sessions_) if (existing.spec.device == spec.device) ++on_device;
    if (on_device >= budget->max_logical_agents) throw std::runtime_error("device logical-agent limit exceeded");

    const ModelLoadRequest load{spec.model_path, spec.device, spec.model_weight_bytes};
    if (!models_.contains(load)) {
        const auto fixed = budget->reserve_bytes + kit->second->capacity_bytes();
        const auto available_for_weights = budget->vram_bytes > fixed ? budget->vram_bytes - fixed : 0;
        if (models_.resident_bytes(spec.device) + spec.model_weight_bytes > available_for_weights)
            throw std::runtime_error("device model-residency budget exceeded");
    }
    auto model = models_.acquire(load);
    const auto kvh = kit->second->create(spec.id);
    AgentSession s;
    s.spec = std::move(spec);
    s.session = next_session_++;
    s.kv = kvh;
    s.model = std::move(model);
    s.tokens = std::move(initial_tokens);
    s.enqueued_us = now_us();
    const auto id = s.spec.id;
    sessions_.emplace(id, std::move(s));
    receipts_.emit("agent_create", id, sessions_.at(id).spec.device, sessions_.at(id).spec.role);
    return id;
}

bool SwarmRuntime::set_runnable(AgentId id) {
    auto* s = mutable_get(id); if (!s) return false;
    if (s->state == AgentState::completed || s->state == AgentState::failed || s->state == AgentState::cancelled) return false;
    s->state = AgentState::runnable; s->enqueued_us = now_us(); return true;
}

bool SwarmRuntime::append_input_tokens(AgentId id, std::span<const std::int32_t> tokens) {
    auto* s = mutable_get(id); if (!s) return false;
    s->tokens.insert(s->tokens.end(), tokens.begin(), tokens.end());
    return true;
}

void SwarmRuntime::set_waiting_tool(AgentId id) { if (auto* s = mutable_get(id)) s->state = AgentState::waiting_tool; }

bool SwarmRuntime::cancel(AgentId id) {
    auto* s = mutable_get(id); if (!s) return false;
    s->state = AgentState::cancelled;
    if (auto it = kv_.find(s->spec.device); it != kv_.end()) it->second->release(s->kv);
    receipts_.emit("agent_cancel", id, s->spec.device, "cancelled");
    return true;
}

TickStats SwarmRuntime::tick() {
    TickStats stats{};
    std::vector<AgentSession*> active;
    active.reserve(sessions_.size());
    for (auto& [_, s] : sessions_) {
        if (s.state == AgentState::runnable) ++stats.runnable;
        active.push_back(&s);
    }
    const auto plans = batcher_.plan(active, leases_, cfg_.max_batch_per_model);
    for (const auto& plan : plans) {
        if (!leases_.acquire_decode(plan.device, static_cast<std::uint32_t>(plan.agents.size()))) continue;
        struct Release { DeviceLeaseManager& l; DeviceId d; std::uint32_t n; ~Release(){ l.release_decode(d,n); } } release{leases_, plan.device, static_cast<std::uint32_t>(plan.agents.size())};

        std::vector<DecodeSequence> seqs;
        seqs.reserve(plan.agents.size());
        std::shared_ptr<const ResidentModel> model;
        for (auto id : plan.agents) {
            auto* s = mutable_get(id); if (!s || s->state != AgentState::runnable) continue;
            const auto required = std::max<std::uint64_t>(cfg_.default_initial_kv_bytes,
                static_cast<std::uint64_t>(s->tokens.size() + 1) * s->spec.kv_bytes_per_token);
            auto kit = kv_.find(s->spec.device);
            if (kit == kv_.end() || !kit->second->ensure_bytes(s->kv, required)) {
                s->state = AgentState::failed; s->error = "KV pool exhausted"; ++stats.failed;
                receipts_.emit("agent_fail", id, s->spec.device, s->error);
                continue;
            }
            s->state = AgentState::decoding;
            model = s->model;
            if (s->decode_steps == 0) {
                seqs.push_back(DecodeSequence{id, s->session, s->kv, std::span<const std::int32_t>(s->tokens), 0u, true, 1});
            } else {
                const auto pos = s->tokens.empty() ? 0u : static_cast<std::uint32_t>(s->tokens.size() - 1);
                const auto one = s->tokens.empty() ? std::span<const std::int32_t>{} : std::span<const std::int32_t>(&s->tokens.back(), 1);
                seqs.push_back(DecodeSequence{id, s->session, s->kv, one, pos, false, 1});
            }
        }
        if (seqs.empty() || !model) continue;
        ++stats.batches;
        auto results = backend_.decode_batch(*model, seqs);
        for (const auto& r : results) {
            auto* s = mutable_get(r.agent); if (!s) continue;
            ++s->decode_steps; s->last_run_us = now_us();
            if (!r.ok) {
                s->state = AgentState::failed; s->error = r.error; ++stats.failed;
                receipts_.emit("agent_fail", r.agent, s->spec.device, r.error);
                continue;
            }
            s->generated.push_back(r.token); ++stats.decoded;
            const bool limit = s->generated.size() >= s->spec.max_new_tokens;
            if (r.finished || limit) {
                s->state = AgentState::completed; ++stats.completed;
                receipts_.emit("agent_complete", r.agent, s->spec.device, "decode complete");
            } else {
                s->tokens.push_back(r.token);
                s->state = AgentState::runnable;
            }
        }
        // Fail-safe: every sequence must receive a result.
        for (const auto& q : seqs) {
            auto* s = mutable_get(q.agent);
            if (s && s->state == AgentState::decoding) {
                s->state = AgentState::failed; s->error = "backend omitted decode result"; ++stats.failed;
                receipts_.emit("agent_fail", q.agent, s->spec.device, s->error);
            }
        }
    }
    return stats;
}

const AgentSession* SwarmRuntime::get(AgentId id) const {
    auto it = sessions_.find(id); return it == sessions_.end() ? nullptr : &it->second;
}
AgentSession* SwarmRuntime::mutable_get(AgentId id) {
    auto it = sessions_.find(id); return it == sessions_.end() ? nullptr : &it->second;
}
std::uint64_t SwarmRuntime::kv_used_bytes(DeviceId device) const {
    auto it = kv_.find(device); return it == kv_.end() ? 0 : it->second->used_bytes();
}

} // namespace rawrxd::swarm48

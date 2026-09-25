#include "SwarmIATRegistration.hpp"
#include <mutex>
#include <map>
#include <set>
#include <algorithm>
#include <chrono>

namespace rawrxd::bridge {

class SwarmIATRegistration::Impl {
public:
    mutable std::mutex mutex_;
    std::map<uint32_t, SwarmAgentRegistration> agents_;
    std::map<std::string, std::set<uint32_t>> hook_to_agents_;
    std::map<uint32_t, std::set<std::string>> agent_active_hooks_;
    uint32_t next_agent_id_ = 1;
};

SwarmIATRegistration::SwarmIATRegistration() : impl_(std::make_unique<Impl>()) {}
SwarmIATRegistration::~SwarmIATRegistration() = default;

bool SwarmIATRegistration::RegisterAgent(const SwarmAgentRegistration& reg) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    uint32_t id = (reg.agent_id != 0) ? reg.agent_id : impl_->next_agent_id_++;
    SwarmAgentRegistration r = reg;
    r.agent_id = id;
    r.registration_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    impl_->agents_[id] = r;
    for (const auto& hook : r.hooks) {
        impl_->hook_to_agents_[hook.import_name].insert(id);
    }
    if (reg_cb_) reg_cb_(id, true);
    return true;
}

bool SwarmIATRegistration::UnregisterAgent(uint32_t agent_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->agents_.find(agent_id);
    if (it == impl_->agents_.end()) return false;
    // Remove from hook maps
    for (const auto& hook : it->second.hooks) {
        auto jt = impl_->hook_to_agents_.find(hook.import_name);
        if (jt != impl_->hook_to_agents_.end()) {
            jt->second.erase(agent_id);
            if (jt->second.empty()) impl_->hook_to_agents_.erase(jt);
        }
    }
    impl_->agent_active_hooks_.erase(agent_id);
    impl_->agents_.erase(it);
    if (reg_cb_) reg_cb_(agent_id, false);
    return true;
}

bool SwarmIATRegistration::IsAgentRegistered(uint32_t agent_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->agents_.find(agent_id) != impl_->agents_.end();
}

std::optional<SwarmAgentRegistration> SwarmIATRegistration::GetAgent(uint32_t agent_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->agents_.find(agent_id);
    if (it != impl_->agents_.end()) return it->second;
    return std::nullopt;
}

std::vector<SwarmAgentRegistration> SwarmIATRegistration::GetAllAgents() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<SwarmAgentRegistration> out;
    out.reserve(impl_->agents_.size());
    for (const auto& [id, agent] : impl_->agents_) {
        out.push_back(agent);
    }
    return out;
}

bool SwarmIATRegistration::EnableHook(uint32_t agent_id, const std::string& import_name) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->agents_.find(agent_id);
    if (it == impl_->agents_.end()) return false;
    bool has_hook = false;
    for (const auto& h : it->second.hooks) {
        if (h.import_name == import_name) { has_hook = true; break; }
    }
    if (!has_hook) return false;
    impl_->agent_active_hooks_[agent_id].insert(import_name);
    if (hook_cb_) hook_cb_(agent_id, import_name, true);
    return true;
}

bool SwarmIATRegistration::DisableHook(uint32_t agent_id, const std::string& import_name) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->agent_active_hooks_.find(agent_id);
    if (it == impl_->agent_active_hooks_.end()) return false;
    auto jt = it->second.find(import_name);
    if (jt == it->second.end()) return false;
    it->second.erase(jt);
    if (hook_cb_) hook_cb_(agent_id, import_name, false);
    return true;
}

bool SwarmIATRegistration::IsHookActive(uint32_t agent_id, const std::string& import_name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->agent_active_hooks_.find(agent_id);
    if (it == impl_->agent_active_hooks_.end()) return false;
    return it->second.find(import_name) != it->second.end();
}

SwarmIATRegistration::ConflictResolution SwarmIATRegistration::ResolveHookConflict(
    const std::string& import_name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    ConflictResolution res;
    auto it = impl_->hook_to_agents_.find(import_name);
    if (it == impl_->hook_to_agents_.end() || it->second.size() <= 1) {
        res.reason = "No conflict";
        return res;
    }
    std::vector<uint32_t> candidates(it->second.begin(), it->second.end());
    uint32_t winner = candidates[0];
    int winner_prio = INT_MAX;
    for (uint32_t aid : candidates) {
        auto jt = impl_->agents_.find(aid);
        if (jt == impl_->agents_.end()) continue;
        if (static_cast<int>(jt->second.priority) < winner_prio) {
            winner_prio = static_cast<int>(jt->second.priority);
            winner = aid;
        }
    }
    res.winning_agent_id = winner;
    res.reason = "Priority-based resolution";
    for (uint32_t aid : candidates) {
        if (aid != winner) res.conflicting_agents.push_back(aid);
    }
    return res;
}

bool SwarmIATRegistration::EnableAllHooksForAgent(uint32_t agent_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->agents_.find(agent_id);
    if (it == impl_->agents_.end()) return false;
    for (const auto& h : it->second.hooks) {
        impl_->agent_active_hooks_[agent_id].insert(h.import_name);
        if (hook_cb_) hook_cb_(agent_id, h.import_name, true);
    }
    return true;
}

bool SwarmIATRegistration::DisableAllHooksForAgent(uint32_t agent_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->agent_active_hooks_.find(agent_id);
    if (it == impl_->agent_active_hooks_.end()) return false;
    for (const auto& hook : it->second) {
        if (hook_cb_) hook_cb_(agent_id, hook, false);
    }
    it->second.clear();
    return true;
}

size_t SwarmIATRegistration::GetActiveHookCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t total = 0;
    for (const auto& [id, hooks] : impl_->agent_active_hooks_) {
        total += hooks.size();
    }
    return total;
}

size_t SwarmIATRegistration::GetAgentCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->agents_.size();
}

bool SwarmIATRegistration::ValidateAgentSignature(uint32_t agent_id,
                                                     const std::string& expected_sha256) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->agents_.find(agent_id);
    if (it == impl_->agents_.end()) return false;
    return it->second.signature == expected_sha256;
}

bool SwarmIATRegistration::ValidateAllSignatures() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& [id, agent] : impl_->agents_) {
        if (agent.signature.empty()) return false;
        // Additional: compute SHA256 of binary and compare
    }
    return true;
}

std::vector<uint8_t> SwarmIATRegistration::SerializeRegistry() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<uint8_t> out;
    auto append_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) { out.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    };
    auto append_u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) { out.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
    };
    auto append_str = [&](const std::string& s) {
        append_u64(s.size());
        out.insert(out.end(), s.begin(), s.end());
    };
    append_u32(static_cast<uint32_t>(impl_->agents_.size()));
    for (const auto& [id, agent] : impl_->agents_) {
        append_u32(id);
        append_str(agent.agent_name);
        append_str(agent.agent_version);
        append_str(agent.signature);
        append_u32(agent.priority);
        out.push_back(agent.enabled ? 1 : 0);
        append_u64(agent.registration_timestamp);
        append_u32(static_cast<uint32_t>(agent.hooks.size()));
        for (const auto& h : agent.hooks) {
            append_str(h.module_name);
            append_str(h.import_name);
            append_u64(h.original_rva);
            append_u64(h.hook_rva);
            out.push_back(h.is_ordinal ? 1 : 0);
            append_u32(h.ordinal);
        }
        append_u32(static_cast<uint32_t>(agent.capabilities.size()));
        for (const auto& c : agent.capabilities) append_str(c);
    }
    return out;
}

bool SwarmIATRegistration::DeserializeRegistry(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t off = 0;
    auto read_u32 = [&]() -> uint32_t {
        if (off + 4 > data.size()) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(data[off++]) << (i * 8);
        return v;
    };
    auto read_u64 = [&]() -> uint64_t {
        if (off + 8 > data.size()) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(data[off++]) << (i * 8);
        return v;
    };
    auto read_str = [&]() -> std::string {
        uint64_t len = read_u64();
        if (off + len > data.size()) return "";
        std::string s(reinterpret_cast<const char*>(data.data() + off), len);
        off += len;
        return s;
    };
    uint32_t count = read_u32();
    for (uint32_t i = 0; i < count; ++i) {
        SwarmAgentRegistration reg;
        reg.agent_id = read_u32();
        reg.agent_name = read_str();
        reg.agent_version = read_str();
        reg.signature = read_str();
        reg.priority = read_u32();
        reg.enabled = (off < data.size() && data[off++] != 0);
        reg.registration_timestamp = read_u64();
        uint32_t hook_count = read_u32();
        for (uint32_t j = 0; j < hook_count; ++j) {
            IATHookDescriptor h;
            h.module_name = read_str();
            h.import_name = read_str();
            h.original_rva = read_u64();
            h.hook_rva = read_u64();
            h.is_ordinal = (off < data.size() && data[off++] != 0);
            h.ordinal = read_u32();
            reg.hooks.push_back(std::move(h));
        }
        uint32_t cap_count = read_u32();
        for (uint32_t j = 0; j < cap_count; ++j) {
            reg.capabilities.push_back(read_str());
        }
        impl_->agents_[reg.agent_id] = std::move(reg);
    }
    return true;
}

} // namespace rawrxd::bridge

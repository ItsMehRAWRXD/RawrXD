#include "CapabilityProfile.hpp"
#include <sstream>
#include <mutex>

namespace rawrxd::command {

class CapabilityProfile::Impl {
public:
    mutable std::mutex mutex_;
    std::map<std::string, Capability> caps_;
};

CapabilityProfile::CapabilityProfile() : impl_(std::make_unique<Impl>()) {}
CapabilityProfile::~CapabilityProfile() = default;

bool CapabilityProfile::RegisterCapability(const Capability& cap) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->caps_[cap.name] = cap;
    return true;
}

bool CapabilityProfile::UnregisterCapability(const std::string& name) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->caps_.erase(name) > 0;
}

void CapabilityProfile::ClearCapabilities() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->caps_.clear();
}

bool CapabilityProfile::HasCapability(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->caps_.count(name) > 0;
}

std::optional<Capability> CapabilityProfile::GetCapability(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->caps_.find(name);
    if (it != impl_->caps_.end()) return it->second;
    return std::nullopt;
}

std::vector<Capability> CapabilityProfile::GetAllCapabilities() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<Capability> out;
    for (const auto& [_, cap] : impl_->caps_) out.push_back(cap);
    return out;
}

std::vector<Capability> CapabilityProfile::GetCapabilitiesByPermission(const std::string& perm) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<Capability> out;
    for (const auto& [_, cap] : impl_->caps_) {
        for (const auto& p : cap.permissions) {
            if (p == perm) { out.push_back(cap); break; }
        }
    }
    return out;
}

bool CapabilityProfile::HasAllPermissions(const std::vector<std::string>& perms) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::map<std::string, int> perm_counts;
    for (const auto& [_, cap] : impl_->caps_) {
        for (const auto& p : cap.permissions) perm_counts[p]++;
    }
    for (const auto& p : perms) {
        if (perm_counts[p] == 0) return false;
    }
    return true;
}

bool CapabilityProfile::HasAnyPermission(const std::vector<std::string>& perms) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::map<std::string, int> perm_counts;
    for (const auto& [_, cap] : impl_->caps_) {
        for (const auto& p : cap.permissions) perm_counts[p]++;
    }
    for (const auto& p : perms) {
        if (perm_counts[p] > 0) return true;
    }
    return false;
}

std::string CapabilityProfile::ToJSON() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ostringstream oss;
    oss << "[\n";
    size_t idx = 0;
    for (const auto& [_, cap] : impl_->caps_) {
        oss << "  {\n";
        oss << "    \"name\": \"" << cap.name << "\",\n";
        oss << "    \"version\": \"" << cap.version << "\",\n";
        oss << "    \"requires_auth\": " << (cap.requires_auth ? "true" : "false") << ",\n";
        oss << "    \"permissions\": [";
        for (size_t i = 0; i < cap.permissions.size(); ++i) {
            oss << "\"" << cap.permissions[i] << "\"";
            if (i + 1 < cap.permissions.size()) oss << ", ";
        }
        oss << "]\n  }";
        if (++idx < impl_->caps_.size()) oss << ",";
        oss << "\n";
    }
    oss << "]\n";
    return oss.str();
}

bool CapabilityProfile::FromJSON(const std::string& /*json*/) {
    // TODO: parse JSON and populate capabilities
    return false;
}

bool CapabilityProfile::IsSupersetOf(const CapabilityProfile& other) const {
    auto theirs = other.GetAllCapabilities();
    for (const auto& cap : theirs) {
        if (!HasCapability(cap.name)) return false;
    }
    return true;
}

} // namespace rawrxd::command

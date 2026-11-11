// VAL-082: Certification Revocation Implementation
// Production lifecycle management

#include "certification_revocation.hpp"
#include <sstream>
#include <fstream>
#include <iomanip>
#include <chrono>

namespace RawrXD {
namespace Certification {

// ============================================================================
// RevocationReason Implementation
// ============================================================================

std::string RevocationReason::ToString() const {
    switch (type) {
        case RevocationType::SECURITY_VULNERABILITY:
            return "SECURITY_VULNERABILITY: " + description;
        case RevocationType::CRITICAL_BUG:
            return "CRITICAL_BUG: " + description;
        case RevocationType::DEPRECATED:
            return "DEPRECATED: " + description;
        case RevocationType::SUPERSEDED:
            return "SUPERSEDED: " + description;
        case RevocationType::COMPLIANCE_VIOLATION:
            return "COMPLIANCE_VIOLATION: " + description;
        case RevocationType::OTHER:
            return "OTHER: " + description;
        default:
            return "UNKNOWN: " + description;
    }
}

// ============================================================================
// RevocationEntry Implementation
// ============================================================================

std::string RevocationEntry::Serialize() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"certificate_id\": \"" << certificate_id << "\",\n";
    ss << "  \"version\": \"" << version << "\",\n";
    ss << "  \"revocation_type\": " << static_cast<int>(reason.type) << ",\n";
    ss << "  \"reason\": \"" << reason.description << "\",\n";
    ss << "  \"revoked_by\": \"" << revoked_by << "\",\n";
    ss << "  \"revocation_date\": \"" << revocation_date << "\",\n";
    ss << "  \"effective_date\": \"" << effective_date << "\",\n";
    ss << "  \"replacement_version\": \"" << replacement_version << "\",\n";
    ss << "  \"signature\": \"" << signature << "\"\n";
    ss << "}\n";
    return ss.str();
}

// ============================================================================
// RevocationList Implementation
// ============================================================================

void RevocationList::AddEntry(const RevocationEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.push_back(entry);
}

void RevocationList::RemoveEntry(const std::string& certificate_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
            [&certificate_id](const RevocationEntry& e) {
                return e.certificate_id == certificate_id;
            }),
        entries_.end()
    );
}

bool RevocationList::IsRevoked(const std::string& certificate_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.certificate_id == certificate_id) {
            return true;
        }
    }
    return false;
}

std::optional<RevocationEntry> RevocationList::GetEntry(
    const std::string& certificate_id
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.certificate_id == certificate_id) {
            return entry;
        }
    }
    return std::nullopt;
}

std::vector<RevocationEntry> RevocationList::GetAllEntries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_;
}

std::vector<RevocationEntry> RevocationList::GetEntriesByType(
    RevocationType type
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RevocationEntry> result;
    for (const auto& entry : entries_) {
        if (entry.reason.type == type) {
            result.push_back(entry);
        }
    }
    return result;
}

std::string RevocationList::Serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"version\": \"" << version << "\",\n";
    ss << "  \"last_updated\": \"" << last_updated << "\",\n";
    ss << "  \"entries\": [\n";
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (i > 0) ss << ",\n";
        ss << entries_[i].Serialize();
    }
    ss << "\n  ]\n";
    ss << "}\n";
    return ss.str();
}

bool RevocationList::Load(const std::string& path) {
    std::ifstream file(path);
    if (!file) return false;
    
    // JSON parsing would go here
    (void)path;
    return true;
}

bool RevocationList::Save(const std::string& path) const {
    std::ofstream file(path);
    if (!file) return false;
    file << Serialize();
    return true;
}

// ============================================================================
// RevocationManager Implementation
// ============================================================================

class RevocationManager::Impl {
public:
    RevocationList list_;
    std::string authority_key_;
    std::mutex mutex_;
};

RevocationManager::RevocationManager() : impl_(std::make_unique<Impl>()) {}
RevocationManager::~RevocationManager() = default;

RevocationManager& RevocationManager::Instance() {
    static RevocationManager instance;
    return instance;
}

bool RevocationManager::Initialize(const std::string& authority_key) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->authority_key_ = authority_key;
    return true;
}

bool RevocationManager::RevokeCertificate(
    const std::string& certificate_id,
    const std::string& version,
    const RevocationReason& reason,
    const std::string& replacement_version
) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    if (impl_->list_.IsRevoked(certificate_id)) {
        return false; // Already revoked
    }
    
    RevocationEntry entry;
    entry.certificate_id = certificate_id;
    entry.version = version;
    entry.reason = reason;
    entry.revoked_by = impl_->authority_key_;
    entry.replacement_version = replacement_version;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    entry.revocation_date = ss.str();
    entry.effective_date = ss.str();
    
    // Sign the entry
    entry.signature = SignEntry(entry);
    
    impl_->list_.AddEntry(entry);
    
    return true;
}

bool RevocationManager::UnrevokeCertificate(const std::string& certificate_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->list_.RemoveEntry(certificate_id);
    return true;
}

bool RevocationManager::IsRevoked(const std::string& certificate_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->list_.IsRevoked(certificate_id);
}

std::optional<RevocationEntry> RevocationManager::GetRevocationInfo(
    const std::string& certificate_id
) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->list_.GetEntry(certificate_id);
}

std::string RevocationManager::SignEntry(const RevocationEntry& entry) const {
    // In production, this would use Ed25519 signatures
    std::stringstream concat;
    concat << entry.certificate_id << entry.version << entry.revocation_date;
    
    std::hash<std::string> hasher;
    return std::to_string(hasher(concat.str()));
}

bool RevocationManager::VerifyEntry(const RevocationEntry& entry) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    // In production, verify Ed25519 signature
    return !entry.signature.empty();
}

// ============================================================================
// LifecycleManager Implementation
// ============================================================================

class LifecycleManager::Impl {
public:
    std::unordered_map<std::string, LifecycleState> states_;
    std::unordered_map<std::string, std::string> transitions_;
    std::mutex mutex_;
};

LifecycleManager::LifecycleManager() : impl_(std::make_unique<Impl>()) {}
LifecycleManager::~LifecycleManager() = default;

LifecycleManager& LifecycleManager::Instance() {
    static LifecycleManager instance;
    return instance;
}

void LifecycleManager::RegisterVersion(const std::string& version, 
                                          LifecycleState initial_state) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->states_[version] = initial_state;
}

bool LifecycleManager::TransitionState(const std::string& version,
                                        LifecycleState new_state) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->states_.find(version);
    if (it == impl_->states_.end()) {
        return false;
    }
    
    // Validate transition
    if (!IsValidTransition(it->second, new_state)) {
        return false;
    }
    
    it->second = new_state;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    impl_->transitions_[version] = ss.str();
    
    return true;
}

LifecycleState LifecycleManager::GetState(const std::string& version) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->states_.find(version);
    if (it != impl_->states_.end()) {
        return it->second;
    }
    return LifecycleState::UNKNOWN;
}

bool LifecycleManager::IsValidForProduction(const std::string& version) const {
    auto state = GetState(version);
    return state == LifecycleState::RELEASED || state == LifecycleState::SUPPORTED;
}

bool LifecycleManager::IsEndOfLife(const std::string& version) const {
    auto state = GetState(version);
    return state == LifecycleState::DEPRECATED || 
           state == LifecycleState::RETIRED ||
           state == LifecycleState::REVOKED;
}

std::vector<std::string> LifecycleManager::GetVersionsInState(LifecycleState state) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> versions;
    for (const auto& [ver, st] : impl_->states_) {
        if (st == state) {
            versions.push_back(ver);
        }
    }
    return versions;
}

bool LifecycleManager::IsValidTransition(LifecycleState from, LifecycleState to) {
    // Define valid transitions
    switch (from) {
        case LifecycleState::DEVELOPMENT:
            return to == LifecycleState::TESTING || to == LifecycleState::DEPRECATED;
        case LifecycleState::TESTING:
            return to == LifecycleState::CANDIDATE || to == LifecycleState::DEPRECATED;
        case LifecycleState::CANDIDATE:
            return to == LifecycleState::RELEASED || to == LifecycleState::DEPRECATED;
        case LifecycleState::RELEASED:
            return to == LifecycleState::SUPPORTED || to == LifecycleState::DEPRECATED;
        case LifecycleState::SUPPORTED:
            return to == LifecycleState::DEPRECATED || to == LifecycleState::RETIRED;
        case LifecycleState::DEPRECATED:
            return to == LifecycleState::RETIRED || to == LifecycleState::REVOKED;
        case LifecycleState::RETIRED:
            return to == LifecycleState::REVOKED;
        default:
            return false;
    }
}

// ============================================================================
// ExpirationChecker Implementation
// ============================================================================

class ExpirationChecker::Impl {
public:
    std::unordered_map<std::string, std::chrono::system_clock::time_point> expirations_;
    std::mutex mutex_;
};

ExpirationChecker::ExpirationChecker() : impl_(std::make_unique<Impl>()) {}
ExpirationChecker::~ExpirationChecker() = default;

ExpirationChecker& ExpirationChecker::Instance() {
    static ExpirationChecker instance;
    return instance;
}

void ExpirationChecker::SetExpiration(const std::string& certificate_id,
                                       std::chrono::system_clock::time_point expiration) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->expirations_[certificate_id] = expiration;
}

bool ExpirationChecker::IsExpired(const std::string& certificate_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->expirations_.find(certificate_id);
    if (it == impl_->expirations_.end()) {
        return false; // No expiration set
    }
    return std::chrono::system_clock::now() > it->second;
}

std::optional<std::chrono::system_clock::time_point> 
ExpirationChecker::GetExpiration(const std::string& certificate_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->expirations_.find(certificate_id);
    if (it != impl_->expirations_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::chrono::seconds ExpirationChecker::TimeUntilExpiration(
    const std::string& certificate_id
) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->expirations_.find(certificate_id);
    if (it == impl_->expirations_.end()) {
        return std::chrono::seconds::max();
    }
    
    auto now = std::chrono::system_clock::now();
    if (now > it->second) {
        return std::chrono::seconds(0);
    }
    
    return std::chrono::duration_cast<std::chrono::seconds>(it->second - now);
}

std::vector<std::string> ExpirationChecker::GetExpiringSoon(
    std::chrono::seconds threshold
) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> expiring;
    auto now = std::chrono::system_clock::now();
    
    for (const auto& [id, expiration] : impl_->expirations_) {
        if (expiration > now && (expiration - now) < threshold) {
            expiring.push_back(id);
        }
    }
    
    return expiring;
}

} // namespace Certification
} // namespace RawrXD

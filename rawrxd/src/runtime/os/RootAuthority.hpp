// ============================================================================
// RootAuthority.hpp — Sole owner of state admission, authorization, and commit
// No other component may admit state transitions. Bypasses are counted.
// ============================================================================
#pragma once
#include <string>
#include <atomic>
#include <mutex>
#include <vector>
#include <unordered_map>

namespace rawrxd::authority {

enum class Verdict : uint8_t { Allow = 0, Deny = 1, Defer = 2 };

struct AdmissionRequest {
    std::string entity;          // what wants to be admitted
    std::string capability;      // which capability
    std::string caller;          // who is requesting
    std::string reason;
};

struct AuthorizationRequest {
    std::string entity;
    std::string action;
    std::string resource;
    std::string caller;
};

struct CommitRequest {
    std::string entity;
    std::string stateTransition;  // "State₀ → State₁"
    std::string evidence;
    std::string caller;
};

struct AuthorityMetrics {
    std::atomic<uint64_t> admissions{0};
    std::atomic<uint64_t> admissionsAllowed{0};
    std::atomic<uint64_t> admissionsDenied{0};
    std::atomic<uint64_t> authorizations{0};
    std::atomic<uint64_t> authorizationsAllowed{0};
    std::atomic<uint64_t> authorizationsDenied{0};
    std::atomic<uint64_t> commits{0};
    std::atomic<uint64_t> commitsAllowed{0};
    std::atomic<uint64_t> commitsDenied{0};
    std::atomic<uint64_t> bypassAttempts{0};
    std::atomic<uint64_t> unauthorizedCommits{0};
};

class RootAuthority {
public:
    static RootAuthority& Instance();

    // --- Admission: can an entity enter the runtime? ---
    Verdict admit(const AdmissionRequest& req);
    bool isAdmitted(const std::string& entity) const;

    // --- Authorization: can an entity perform an action? ---
    Verdict authorize(const AuthorizationRequest& req);
    bool isAuthorized(const std::string& entity, const std::string& action) const;

    // --- Commit: can a state transition be committed? ---
    Verdict commit(const CommitRequest& req);

    // --- Bypass detection (fail-closed gate) ---
    void recordBypass(const std::string& detail);
    void recordUnauthorizedCommit(const std::string& detail);
    bool gatePass() const;

    // --- Metrics ---
    const AuthorityMetrics& metrics() const { return metrics_; }

    // --- Reset (for testing) ---
    void reset();

    // --- Policy: set allowed entities/capabilities ---
    void allowEntity(const std::string& entity);
    void allowCapability(const std::string& capability);
    void allowAction(const std::string& action);

private:
    RootAuthority() = default;
    ~RootAuthority() = default;
    RootAuthority(const RootAuthority&) = delete;
    RootAuthority& operator=(const RootAuthority&) = delete;

    mutable std::mutex mutex_;
    AuthorityMetrics metrics_;
    std::unordered_map<std::string, bool> admittedEntities_;
    std::unordered_map<std::string, bool> authorizedActions_;
    std::unordered_map<std::string, bool> allowedEntities_;
    std::unordered_map<std::string, bool> allowedCapabilities_;
    std::unordered_map<std::string, bool> allowedActions_;
    std::vector<std::string> commitHistory_;
};

} // namespace rawrxd::authority
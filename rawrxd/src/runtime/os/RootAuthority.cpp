// ============================================================================
// RootAuthority.cpp — Sole owner of state admission, authorization, commit
// ============================================================================
#include "RootAuthority.hpp"

namespace rawrxd::authority {

RootAuthority& RootAuthority::Instance() {
    static RootAuthority inst;
    return inst;
}

void RootAuthority::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.admissions.store(0, std::memory_order_relaxed);
    metrics_.admissionsAllowed.store(0, std::memory_order_relaxed);
    metrics_.admissionsDenied.store(0, std::memory_order_relaxed);
    metrics_.authorizations.store(0, std::memory_order_relaxed);
    metrics_.authorizationsAllowed.store(0, std::memory_order_relaxed);
    metrics_.authorizationsDenied.store(0, std::memory_order_relaxed);
    metrics_.commits.store(0, std::memory_order_relaxed);
    metrics_.commitsAllowed.store(0, std::memory_order_relaxed);
    metrics_.commitsDenied.store(0, std::memory_order_relaxed);
    metrics_.bypassAttempts.store(0, std::memory_order_relaxed);
    metrics_.unauthorizedCommits.store(0, std::memory_order_relaxed);
    admittedEntities_.clear();
    authorizedActions_.clear();
    allowedEntities_.clear();
    allowedCapabilities_.clear();
    allowedActions_.clear();
    commitHistory_.clear();
}

void RootAuthority::allowEntity(const std::string& entity) {
    std::lock_guard<std::mutex> lock(mutex_);
    allowedEntities_[entity] = true;
}

void RootAuthority::allowCapability(const std::string& capability) {
    std::lock_guard<std::mutex> lock(mutex_);
    allowedCapabilities_[capability] = true;
}

void RootAuthority::allowAction(const std::string& action) {
    std::lock_guard<std::mutex> lock(mutex_);
    allowedActions_[action] = true;
}

Verdict RootAuthority::admit(const AdmissionRequest& req) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.admissions.fetch_add(1, std::memory_order_relaxed);

    // Fail-closed: if entity is not in the allowed list, deny
    bool entityOk = allowedEntities_.empty() || allowedEntities_.count(req.entity) > 0;
    bool capOk = allowedCapabilities_.empty() || allowedCapabilities_.count(req.capability) > 0;

    if (entityOk && capOk) {
        admittedEntities_[req.entity] = true;
        metrics_.admissionsAllowed.fetch_add(1, std::memory_order_relaxed);
        return Verdict::Allow;
    }
    metrics_.admissionsDenied.fetch_add(1, std::memory_order_relaxed);
    return Verdict::Deny;
}

bool RootAuthority::isAdmitted(const std::string& entity) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return admittedEntities_.count(entity) > 0;
}

Verdict RootAuthority::authorize(const AuthorizationRequest& req) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.authorizations.fetch_add(1, std::memory_order_relaxed);

    // Must be admitted first
    if (admittedEntities_.find(req.entity) == admittedEntities_.end()) {
        metrics_.authorizationsDenied.fetch_add(1, std::memory_order_relaxed);
        return Verdict::Deny;
    }

    // Check action is allowed
    bool actionOk = allowedActions_.empty() || allowedActions_.count(req.action) > 0;
    if (actionOk) {
        authorizedActions_[req.entity + ":" + req.action] = true;
        metrics_.authorizationsAllowed.fetch_add(1, std::memory_order_relaxed);
        return Verdict::Allow;
    }
    metrics_.authorizationsDenied.fetch_add(1, std::memory_order_relaxed);
    return Verdict::Deny;
}

bool RootAuthority::isAuthorized(const std::string& entity, const std::string& action) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return authorizedActions_.count(entity + ":" + action) > 0;
}

Verdict RootAuthority::commit(const CommitRequest& req) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.commits.fetch_add(1, std::memory_order_relaxed);

    // Must be admitted
    if (admittedEntities_.find(req.entity) == admittedEntities_.end()) {
        metrics_.commitsDenied.fetch_add(1, std::memory_order_relaxed);
        return Verdict::Deny;
    }

    // Must have evidence (fail-closed: empty evidence = deny)
    if (req.evidence.empty()) {
        metrics_.commitsDenied.fetch_add(1, std::memory_order_relaxed);
        return Verdict::Deny;
    }

    commitHistory_.push_back(req.entity + " | " + req.stateTransition + " | " + req.evidence);
    metrics_.commitsAllowed.fetch_add(1, std::memory_order_relaxed);
    return Verdict::Allow;
}

void RootAuthority::recordBypass(const std::string& detail) {
    metrics_.bypassAttempts.fetch_add(1, std::memory_order_relaxed);
}

void RootAuthority::recordUnauthorizedCommit(const std::string& detail) {
    metrics_.unauthorizedCommits.fetch_add(1, std::memory_order_relaxed);
}

bool RootAuthority::gatePass() const {
    return metrics_.bypassAttempts.load() == 0 &&
           metrics_.unauthorizedCommits.load() == 0;
}

} // namespace rawrxd::authority
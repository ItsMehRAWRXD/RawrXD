// =============================================================================
// SharedAgentWorkRegistry.hpp — Cross-session SEARCH/READ/EDIT/BUILD leases
// =============================================================================
// ABOVE the frozen Deep2 streamer. Not part of token sampling.
// Enforces canonical_repo=F:\~dev\rawrxd (rejects G:\rawrxd for cert work).
// =============================================================================
#pragma once

#include "AgentEventStream.hpp"
#include "ProjectState.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace RawrXD::Agents {

struct AgentWorkLease {
    uint64_t sessionId = 0;
    uint64_t agentId = 0;
    enum class Kind { Search, Read, Edit, Build, Test } kind = Kind::Search;
    std::string resource;
    std::string query;
    uint64_t startedAtMs = 0;
    uint64_t heartbeatMs = 0;
};

struct WorkKey {
    AgentWorkLease::Kind kind = AgentWorkLease::Kind::Search;
    std::string normalizedResource;
    std::string normalizedQuery;
    bool operator==(const WorkKey& o) const {
        return kind == o.kind &&
               normalizedResource == o.normalizedResource &&
               normalizedQuery == o.normalizedQuery;
    }
    bool operator<(const WorkKey& o) const {
        if (kind != o.kind) return static_cast<int>(kind) < static_cast<int>(o.kind);
        if (normalizedResource != o.normalizedResource)
            return normalizedResource < o.normalizedResource;
        return normalizedQuery < o.normalizedQuery;
    }
};

enum class AcquireResult { Acquired, JoinedExisting, ConflictingWrite, StaleRepo };

struct AcquireOutcome {
    AcquireResult status = AcquireResult::Acquired;
    AgentWorkLease owner{};
    std::string sharedPayload;
    bool resultReady = false;
};

struct PublishedWorkResult {
    bool ready = false;
    std::string payload;
    uint64_t matchCount = 0;
    uint64_t completedAtMs = 0;
};

class SharedAgentWorkRegistry {
public:
    static constexpr uint64_t kLeaseTimeoutMs = 30'000;

    static SharedAgentWorkRegistry& instance() {
        static SharedAgentWorkRegistry s;
        return s;
    }

    static std::string normalizeResource(std::string path) {
        for (char& c : path) {
            if (c == '/') c = '\\';
        }
        if (path.size() >= 2 && path[1] == ':' && path[0] >= 'A' && path[0] <= 'Z') {
            path[0] = static_cast<char>(path[0] - 'A' + 'a');
        }
        while (!path.empty() && (path.back() == '\\' || path.back() == '/')) path.pop_back();
        return path;
    }

    static std::string normalizeQuery(std::string q) {
        while (!q.empty() && (q.front() == ' ' || q.front() == '\t')) q.erase(q.begin());
        while (!q.empty() && (q.back() == ' ' || q.back() == '\t')) q.pop_back();
        return q;
    }

    static WorkKey makeKey(AgentWorkLease::Kind kind,
                           const std::string& resource,
                           const std::string& query) {
        return WorkKey{kind, normalizeResource(resource), normalizeQuery(query)};
    }

    AcquireOutcome acquireOrJoin(const WorkKey& key, uint64_t sessionId, uint64_t agentId) {
        // Reject stale G:\rawrxd for certification-phase work.
        if (!ProjectState::instance().isCanonicalPath(key.normalizedResource)) {
            AgentEventStream::instance().emit(AgentEvent{
                AgentEventType::StaleRepoRejected,
                "Rejecting G:\\rawrxd — canonical_repo=F:\\~dev\\rawrxd",
                0, 0, sessionId, agentId,
                key.normalizedResource, key.normalizedQuery, 0, 0});
            return AcquireOutcome{AcquireResult::StaleRepo, {}, {}, false};
        }

        std::lock_guard<std::mutex> lock(m_mu);
        reclaimExpiredLocked();

        if (key.kind == AgentWorkLease::Kind::Edit ||
            key.kind == AgentWorkLease::Kind::Build) {
            for (const auto& [k, entry] : m_active) {
                if (k.normalizedResource == key.normalizedResource) {
                    AgentEventStream::instance().emit(AgentEvent{
                        AgentEventType::ConflictingWrite,
                        "Conflicting write lease",
                        entry.lease.sessionId, entry.lease.agentId,
                        sessionId, agentId,
                        key.normalizedResource, key.normalizedQuery, 0, 0});
                    return AcquireOutcome{AcquireResult::ConflictingWrite, entry.lease, {}, false};
                }
            }
        }

        auto it = m_active.find(key);
        if (it != m_active.end()) {
            AgentEventStream::instance().emit(AgentEvent{
                AgentEventType::WorkAlreadyInProgress,
                "Another parallel agent session is already searching these files. "
                "Joining its search instead of duplicating work.",
                it->second.lease.sessionId, it->second.lease.agentId,
                sessionId, agentId,
                key.normalizedResource, key.normalizedQuery, 0, 0});
            AgentEventStream::instance().emit(AgentEvent{
                AgentEventType::JoinedExistingSearch, "",
                it->second.lease.sessionId, it->second.lease.agentId,
                sessionId, agentId,
                key.normalizedResource, key.normalizedQuery, 0, 0});
            AcquireOutcome out;
            out.status = AcquireResult::JoinedExisting;
            out.owner = it->second.lease;
            if (it->second.result.ready) {
                out.resultReady = true;
                out.sharedPayload = it->second.result.payload;
            }
            return out;
        }

        auto cacheIt = m_resultCache.find(key);
        if (cacheIt != m_resultCache.end() && cacheIt->second.ready &&
            key.kind == AgentWorkLease::Kind::Search) {
            AcquireOutcome out;
            out.status = AcquireResult::JoinedExisting;
            out.resultReady = true;
            out.sharedPayload = cacheIt->second.payload;
            out.owner.kind = key.kind;
            out.owner.resource = key.normalizedResource;
            out.owner.query = key.normalizedQuery;
            return out;
        }

        const uint64_t now = nowMs();
        ActiveEntry entry;
        entry.lease.sessionId = sessionId;
        entry.lease.agentId = agentId;
        entry.lease.kind = key.kind;
        entry.lease.resource = key.normalizedResource;
        entry.lease.query = key.normalizedQuery;
        entry.lease.startedAtMs = now;
        entry.lease.heartbeatMs = now;
        m_active.emplace(key, std::move(entry));

        AgentEventStream::instance().emit(AgentEvent{
            AgentEventType::LeaseAcquired, "lease acquired",
            sessionId, agentId, sessionId, agentId,
            key.normalizedResource, key.normalizedQuery, 0, 0});

        return AcquireOutcome{AcquireResult::Acquired, m_active[key].lease, {}, false};
    }

    void heartbeat(const WorkKey& key, uint64_t sessionId) {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_active.find(key);
        if (it != m_active.end() && it->second.lease.sessionId == sessionId) {
            it->second.lease.heartbeatMs = nowMs();
        }
    }

    void publishResult(const WorkKey& key, const std::string& payload, uint64_t matchCount = 0) {
        {
            std::lock_guard<std::mutex> lock(m_mu);
            PublishedWorkResult r;
            r.ready = true;
            r.payload = payload;
            r.matchCount = matchCount;
            r.completedAtMs = nowMs();
            m_resultCache[key] = r;
            auto it = m_active.find(key);
            if (it != m_active.end()) it->second.result = r;
        }
        m_cv.notify_all();
        AgentEventStream::instance().emit(AgentEvent{
            AgentEventType::SharedResultReceived, "",
            0, 0, 0, 0,
            key.normalizedResource, key.normalizedQuery, matchCount, 0});
    }

    std::string waitForResult(const WorkKey& key, uint64_t timeoutMs = 60'000) {
        std::unique_lock<std::mutex> lock(m_mu);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (true) {
            auto cacheIt = m_resultCache.find(key);
            if (cacheIt != m_resultCache.end() && cacheIt->second.ready) {
                return cacheIt->second.payload;
            }
            auto activeIt = m_active.find(key);
            if (activeIt != m_active.end() && activeIt->second.result.ready) {
                return activeIt->second.result.payload;
            }
            if (activeIt == m_active.end() &&
                (cacheIt == m_resultCache.end() || !cacheIt->second.ready)) {
                return {};
            }
            if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) return {};
        }
    }

    void complete(const WorkKey& key) {
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_active.erase(key);
        }
        m_cv.notify_all();
    }

private:
    struct ActiveEntry {
        AgentWorkLease lease;
        PublishedWorkResult result;
    };

    static uint64_t nowMs() {
        using namespace std::chrono;
        return static_cast<uint64_t>(
            duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    }

    void reclaimExpiredLocked() {
        const uint64_t now = nowMs();
        std::vector<WorkKey> stale;
        for (const auto& [key, entry] : m_active) {
            if (now - entry.lease.heartbeatMs > kLeaseTimeoutMs) stale.push_back(key);
        }
        for (const auto& key : stale) {
            auto it = m_active.find(key);
            if (it == m_active.end()) continue;
            AgentEventStream::instance().emit(AgentEvent{
                AgentEventType::LeaseReclaimed, "lease timeout",
                it->second.lease.sessionId, it->second.lease.agentId,
                0, 0, key.normalizedResource, key.normalizedQuery, 0, 0});
            m_active.erase(it);
        }
        if (!stale.empty()) m_cv.notify_all();
    }

    std::mutex m_mu;
    std::condition_variable m_cv;
    std::map<WorkKey, ActiveEntry> m_active;
    std::map<WorkKey, PublishedWorkResult> m_resultCache;
};

} // namespace RawrXD::Agents

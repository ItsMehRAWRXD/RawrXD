#include "HexMagResidencyAuthority.hpp"

#include <algorithm>
#include <sstream>
#include <unordered_set>

namespace RawrXD::HexMag {

bool ResidencyReceipt::pass() const noexcept {
    return prefetchSuccess > 0 && evictSuccess > 0 && reloadSuccess > 0 &&
           reloadBytes > 0 && staleResidencyViolations == 0 && callbackFailures == 0;
}

std::string ResidencyReceipt::text() const {
    std::ostringstream o;
    o << "=== RAWRXD_HEXMAG_RESIDENCY_E2E_001 ===\n";
    o << "PREFETCH_ATTEMPTS=" << prefetchAttempts << "\n";
    o << "PREFETCH_SUCCESS=" << prefetchSuccess << "\n";
    o << "EVICT_ATTEMPTS=" << evictAttempts << "\n";
    o << "EVICT_SUCCESS=" << evictSuccess << "\n";
    o << "RELOAD_ATTEMPTS=" << reloadAttempts << "\n";
    o << "RELOAD_SUCCESS=" << reloadSuccess << "\n";
    o << "RELOAD_BYTES=" << reloadBytes << "\n";
    o << "STALE_RESIDENCY_VIOLATIONS=" << staleResidencyViolations << "\n";
    o << "CALLBACK_FAILURES=" << callbackFailures << "\n";
    o << "VERDICT=" << (pass() ? "PASS" : "FAIL") << "\n";
    return o.str();
}

ResidencyAuthority::ResidencyAuthority(ResidencyCallbacks callbacks)
    : callbacks_(callbacks) {}

bool ResidencyAuthority::prefetch(std::string key, std::uint64_t bytes) {
    ++receipt_.prefetchAttempts;
    if (key.empty() || bytes == 0 || !callbacks_.prefetch || !callbacks_.isResident) {
        ++receipt_.callbackFailures;
        return false;
    }
    if (!callbacks_.prefetch(callbacks_.user, key, bytes)) {
        ++receipt_.callbackFailures;
        return false;
    }
    if (!callbacks_.isResident(callbacks_.user, key)) {
        ++receipt_.staleResidencyViolations;
        return false;
    }
    auto& item = items_[key];
    item.key = std::move(key);
    item.bytes = bytes;
    item.lastUseTick = ++tick_;
    item.resident = true;
    ++receipt_.prefetchSuccess;
    return true;
}

bool ResidencyAuthority::touch(std::string_view key) {
    auto it = items_.find(std::string(key));
    if (it == items_.end()) return false;
    it->second.lastUseTick = ++tick_;
    if (callbacks_.isResident) {
        const bool actual = callbacks_.isResident(callbacks_.user, key);
        if (actual != it->second.resident) {
            ++receipt_.staleResidencyViolations;
            it->second.resident = actual;
        }
    }
    return it->second.resident;
}

bool ResidencyAuthority::evict(std::string_view key) {
    ++receipt_.evictAttempts;
    auto it = items_.find(std::string(key));
    if (it == items_.end() || !it->second.resident || !callbacks_.evict || !callbacks_.isResident) {
        ++receipt_.callbackFailures;
        return false;
    }
    if (!callbacks_.evict(callbacks_.user, key)) {
        ++receipt_.callbackFailures;
        return false;
    }
    if (callbacks_.isResident(callbacks_.user, key)) {
        ++receipt_.staleResidencyViolations;
        return false;
    }
    it->second.resident = false;
    it->second.everEvicted = true;
    it->second.lastUseTick = ++tick_;
    ++receipt_.evictSuccess;
    return true;
}

bool ResidencyAuthority::reload(std::string_view key) {
    ++receipt_.reloadAttempts;
    auto it = items_.find(std::string(key));
    if (it == items_.end() || it->second.resident || !it->second.everEvicted ||
        !callbacks_.reload || !callbacks_.isResident) {
        ++receipt_.callbackFailures;
        return false;
    }
    std::uint64_t bytesReloaded = 0;
    if (!callbacks_.reload(callbacks_.user, key, &bytesReloaded)) {
        ++receipt_.callbackFailures;
        return false;
    }
    if (!callbacks_.isResident(callbacks_.user, key) || bytesReloaded == 0) {
        ++receipt_.staleResidencyViolations;
        return false;
    }
    it->second.resident = true;
    it->second.everReloaded = true;
    it->second.lastUseTick = ++tick_;
    ++receipt_.reloadSuccess;
    receipt_.reloadBytes += bytesReloaded;
    return true;
}

std::uint64_t ResidencyAuthority::residentBytes() const noexcept {
    std::uint64_t bytes = 0;
    for (const auto& [_, item] : items_) if (item.resident) bytes += item.bytes;
    return bytes;
}

std::size_t ResidencyAuthority::trimToBudget(
    std::uint64_t budgetBytes,
    const std::vector<std::string>& pinnedKeys) {

    std::unordered_set<std::string> pinned(pinnedKeys.begin(), pinnedKeys.end());
    std::vector<ResidencyItem*> candidates;
    for (auto& [key, item] : items_) {
        if (item.resident && !pinned.contains(key)) candidates.push_back(&item);
    }
    std::sort(candidates.begin(), candidates.end(), [](const ResidencyItem* a, const ResidencyItem* b) {
        return a->lastUseTick < b->lastUseTick;
    });

    std::size_t evicted = 0;
    for (auto* item : candidates) {
        if (residentBytes() <= budgetBytes) break;
        if (evict(item->key)) ++evicted;
    }
    return evicted;
}

} // namespace RawrXD::HexMag

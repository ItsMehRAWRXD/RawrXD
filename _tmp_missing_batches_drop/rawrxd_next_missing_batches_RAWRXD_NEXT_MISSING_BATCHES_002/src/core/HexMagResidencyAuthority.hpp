#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace RawrXD::HexMag {

struct ResidencyCallbacks final {
    void* user{};
    bool (*prefetch)(void* user, std::string_view key, std::uint64_t bytes){};
    bool (*evict)(void* user, std::string_view key){};
    bool (*reload)(void* user, std::string_view key, std::uint64_t* bytesReloaded){};
    bool (*isResident)(void* user, std::string_view key){};
};

struct ResidencyItem final {
    std::string key{};
    std::uint64_t bytes{};
    std::uint64_t lastUseTick{};
    bool resident{};
    bool everEvicted{};
    bool everReloaded{};
};

struct ResidencyReceipt final {
    std::uint64_t prefetchAttempts{};
    std::uint64_t prefetchSuccess{};
    std::uint64_t evictAttempts{};
    std::uint64_t evictSuccess{};
    std::uint64_t reloadAttempts{};
    std::uint64_t reloadSuccess{};
    std::uint64_t reloadBytes{};
    std::uint64_t staleResidencyViolations{};
    std::uint64_t callbackFailures{};

    [[nodiscard]] bool pass() const noexcept;
    [[nodiscard]] std::string text() const;
};

class ResidencyAuthority final {
public:
    explicit ResidencyAuthority(ResidencyCallbacks callbacks);

    bool prefetch(std::string key, std::uint64_t bytes);
    bool touch(std::string_view key);
    bool evict(std::string_view key);
    bool reload(std::string_view key);

    // Evicts the least-recently-used resident items until residentBytes <= budget.
    // Items named in pinnedKeys are never evicted by this call.
    std::size_t trimToBudget(
        std::uint64_t budgetBytes,
        const std::vector<std::string>& pinnedKeys = {});

    [[nodiscard]] std::uint64_t residentBytes() const noexcept;
    [[nodiscard]] const ResidencyReceipt& receipt() const noexcept { return receipt_; }
    [[nodiscard]] const std::unordered_map<std::string, ResidencyItem>& items() const noexcept { return items_; }

private:
    ResidencyCallbacks callbacks_{};
    std::unordered_map<std::string, ResidencyItem> items_{};
    ResidencyReceipt receipt_{};
    std::uint64_t tick_{};
};

} // namespace RawrXD::HexMag

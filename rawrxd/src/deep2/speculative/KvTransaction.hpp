#pragma once
#include <cstddef>
#include <cstdint>

namespace rawrxd::deep2::spec {

struct KvSnapshot final {
    std::size_t tokenCount{};
    std::uint64_t generation{};
    std::uint64_t opaque0{};
    std::uint64_t opaque1{};
};

struct KvAuthority final {
    void* user{};
    bool (*capture)(void* user, KvSnapshot* out){};
    bool (*restore)(void* user, const KvSnapshot* snapshot){};
    bool (*seal)(void* user, const KvSnapshot* snapshot, std::size_t committedTokens){};
};

class KvTransaction final {
public:
    bool begin(const KvAuthority& authority) noexcept;
    bool rollback(const KvAuthority& authority) noexcept;
    bool commit(const KvAuthority& authority, std::size_t committedTokens) noexcept;

    [[nodiscard]] bool active() const noexcept { return active_; }
    [[nodiscard]] const KvSnapshot& snapshot() const noexcept { return snapshot_; }

private:
    KvSnapshot snapshot_{};
    bool active_{false};
};

} // namespace rawrxd::deep2::spec

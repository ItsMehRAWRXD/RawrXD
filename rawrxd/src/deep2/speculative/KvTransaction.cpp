#include "KvTransaction.hpp"

namespace rawrxd::deep2::spec {

bool KvTransaction::begin(const KvAuthority& authority) noexcept {
    if (active_ || !authority.capture) return false;
    KvSnapshot snap{};
    if (!authority.capture(authority.user, &snap)) return false;
    snapshot_ = snap;
    active_ = true;
    return true;
}

bool KvTransaction::rollback(const KvAuthority& authority) noexcept {
    if (!active_ || !authority.restore) return false;
    if (!authority.restore(authority.user, &snapshot_)) return false;
    active_ = false;
    return true;
}

bool KvTransaction::commit(
    const KvAuthority& authority,
    std::size_t committedTokens) noexcept {
    if (!active_) return false;
    if (authority.seal && !authority.seal(authority.user, &snapshot_, committedTokens)) {
        return false;
    }
    active_ = false;
    return true;
}

} // namespace rawrxd::deep2::spec

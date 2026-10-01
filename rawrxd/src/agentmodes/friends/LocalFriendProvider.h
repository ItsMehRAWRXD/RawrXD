// LocalFriendProvider.h — RAWRXD_PHONE_A_FRIEND_001
// A friend backed by a second local model through the real Deep2 engine.
//
// NOTE ON INDEPENDENCE: this provider runs inside RawrXD's own process and
// model family. It therefore provides NO independent signal. A consensus drawn
// only from local providers is reported as such by PhoneAFriendAuthority
// rather than being presented as corroboration.
#pragma once

#include "agentmodes/friends/FriendTypes.h"

namespace rawrxd { namespace friendx {

class LocalFriendProvider final : public IFriendProvider {
public:
    explicit LocalFriendProvider(std::string modelPath, uint32_t maxTokens = 512);

    const char* name() const override { return "local"; }
    FriendProviderKind kind() const override { return FriendProviderKind::LocalModel; }

    bool available() const override { return !modelPath_.empty(); }
    std::string unavailableReason() const override;

    FriendResponse ask(const FriendRequest& request) override;

    const std::string& modelPath() const { return modelPath_; }

private:
    std::string modelPath_;
    uint32_t    maxTokens_;
    // Engine construction is deferred to ask() so that a missing model does
    // not cost anything at construction time.
    std::shared_ptr<void> engine_;
};

}} // namespace rawrxd::friendx

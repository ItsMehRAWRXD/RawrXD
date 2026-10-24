#pragma once

#include "K2KVCache.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

namespace Deep2 {

// Lifecycle-only bridge for the normal Deep2 MLA path.  It owns request
// position/cache state but does not issue a certification witness by itself.
// Callers must provide real outputs from MlaAttentionComplete and submit those
// stats to MlaCertAuthority separately.
class Deep2MlaLifecycleAdapter final {
public:
    struct Geometry {
        std::size_t layers = 0;
        std::size_t maxSequence = 0;
        std::size_t cacheDimension = 0;
        std::size_t heads = 0;
        std::size_t qkNope = 0;
        std::size_t qkRope = 0;
        std::size_t value = 0;
    };

    bool Configure(const Geometry& g, std::string& error);
    void ResetRequest() noexcept;
    void CancelRequest() noexcept;
    bool BeginToken(std::uint32_t absolutePosition, std::string& error) noexcept;
    bool WriteLayer(std::size_t layer, const float* key, const float* value,
                    std::string& error) noexcept;
    bool CommitToken(std::string& error) noexcept;
    bool ValidatePosition(std::uint32_t position, std::string& error) const noexcept;

    const Geometry& geometry() const noexcept { return geometry_; }
    std::uint32_t position() const noexcept { return position_; }
    bool configured() const noexcept { return configured_; }
    bool tokenOpen() const noexcept { return tokenOpen_; }
    const rawrxd::deep2::K2KVCache& cache() const noexcept { return cache_; }
    rawrxd::deep2::K2KVCache& cache() noexcept { return cache_; }

private:
    Geometry geometry_{};
    rawrxd::deep2::K2KVCache cache_{};
    std::uint32_t position_ = 0;
    bool configured_ = false;
    bool tokenOpen_ = false;
};

} // namespace Deep2

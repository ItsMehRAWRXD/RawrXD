#include "Deep2MlaLifecycleAdapter.hpp"
#include <limits>

namespace Deep2 {

bool Deep2MlaLifecycleAdapter::Configure(const Geometry& g, std::string& error) {
    error.clear();
    if (!g.layers || !g.maxSequence || !g.cacheDimension || !g.heads ||
        !g.qkNope || !g.qkRope || !g.value) { error = "invalid MLA geometry"; return false; }
    if (g.maxSequence > std::numeric_limits<std::uint32_t>::max()) { error = "sequence exceeds position range"; return false; }
    try { cache_.Reset(g.layers, g.maxSequence, g.cacheDimension); }
    catch (const std::exception& e) { error = e.what(); configured_ = false; return false; }
    geometry_ = g; position_ = 0; tokenOpen_ = false; configured_ = true; return true;
}

void Deep2MlaLifecycleAdapter::ResetRequest() noexcept { if (configured_) cache_.Clear(); position_ = 0; tokenOpen_ = false; }
void Deep2MlaLifecycleAdapter::CancelRequest() noexcept { ResetRequest(); }

bool Deep2MlaLifecycleAdapter::ValidatePosition(std::uint32_t p, std::string& error) const noexcept {
    error.clear();
    if (!configured_) { error = "MLA adapter not configured"; return false; }
    if (p != position_) { error = "non-contiguous MLA position"; return false; }
    if (p >= geometry_.maxSequence) { error = "MLA position exceeds context"; return false; }
    return true;
}

bool Deep2MlaLifecycleAdapter::BeginToken(std::uint32_t p, std::string& error) noexcept {
    if (!ValidatePosition(p, error)) return false;
    if (tokenOpen_) { error = "MLA token already open"; return false; }
    tokenOpen_ = true; return true;
}

bool Deep2MlaLifecycleAdapter::WriteLayer(std::size_t layer, const float* key, const float* value, std::string& error) noexcept {
    error.clear();
    if (!tokenOpen_) { error = "MLA token not open"; return false; }
    if (!key || !value) { error = "null MLA cache input"; return false; }
    if (layer >= geometry_.layers) { error = "MLA layer out of range"; return false; }
    try { cache_.Write(layer, key, value); }
    catch (const std::exception& e) { error = e.what(); return false; }
    return true;
}

bool Deep2MlaLifecycleAdapter::CommitToken(std::string& error) noexcept {
    error.clear();
    if (!tokenOpen_) { error = "MLA token not open"; return false; }
    try { cache_.CommitPosition(); }
    catch (const std::exception& e) { error = e.what(); return false; }
    ++position_; tokenOpen_ = false; return true;
}

} // namespace Deep2

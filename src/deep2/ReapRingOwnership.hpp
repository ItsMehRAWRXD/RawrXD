#pragma once
#include <cstddef>

namespace Deep2 { namespace Submit {

// Call under the owning backend's API mutex. A completed but unconsumed
// result still owns its slot; fence signal alone does not permit reuse.
template<class Slot, std::size_t N>
bool MayResetRing(const Slot (&slots)[N], bool teardownAuthorized) noexcept {
    if (teardownAuthorized) return true;
    for (const auto& slot : slots) if (slot.inFlight) return false;
    return true;
}

template<class Slot, std::size_t N>
bool FindFreeRingSlot(const Slot (&slots)[N], unsigned& cursor,
                      unsigned& selected) noexcept {
    static_assert(N > 0, "nonempty ring required");
    const std::size_t start = cursor % N;
    for (std::size_t offset = 0; offset < N; ++offset) {
        const auto i = (start + offset) % N;
        if (!slots[i].inFlight) {
            selected = static_cast<unsigned>(i);
            cursor = static_cast<unsigned>((i + 1) % N);
            return true;
        }
    }
    return false;
}

} } // namespace Deep2::Submit

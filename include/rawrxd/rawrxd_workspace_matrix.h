#pragma once
#include <cstdint>
#include <cstddef>

namespace rawrxd::ui {
    struct SovereignWorkspaceController {
        static constexpr std::size_t requiredArenaBytes() { return 1024 * 1024; }
    };
}
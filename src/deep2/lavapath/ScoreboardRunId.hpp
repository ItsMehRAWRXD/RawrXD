#pragma once
/* ScoreboardRunId — RAWRXD_P3_RUN_ID for seal binding. ≤99. */
#include <cstdlib>
#include <cstdio>

namespace Deep2 {
namespace scoreboard {

inline const char* P3RunIdOrEmpty() noexcept {
    const char* e = std::getenv("RAWRXD_P3_RUN_ID");
    return (e && e[0]) ? e : "";
}

inline void EmitRunId(FILE* f) noexcept {
    if (!f)
        return;
    const char* id = P3RunIdOrEmpty();
    if (id[0])
        std::fprintf(f, "RUN_ID=%s\n", id);
}

} /* namespace scoreboard */
} /* namespace Deep2 */

#pragma once
/* ScoreboardProductState — ProductSb storage only (break include cycles). ≤99. */
#include "OpenModelIndex.hpp"
#include "WindowPool.hpp"
#include "TensorScoreboard.hpp"
#include "ScoreboardExecutionEngine.hpp"

namespace Deep2 {
namespace scoreboard {

struct ProductScoreboardState {
    OpenModelIndex index{};
    WindowPool ramPool{};
    TensorScoreboard sb{};
    ScoreboardExecutionEngine eng{};
};

inline ProductScoreboardState& ProductSb() {
    static ProductScoreboardState s;
    return s;
}

} /* namespace scoreboard */
} /* namespace Deep2 */

#pragma once
/* ScoreboardJoinAllTip — join-all await tip. LIVE=0. ≤99. */
#include "ScoreboardLayerWalk.hpp"

namespace Deep2 {
namespace scoreboard {

/* Re-export LayerWalk's template so callers that only include this
   header still get the full TryJoinAllTip(SlotArrayT&, thread&, atomic). */
using Deep2::scoreboard::TryJoinAllTip;

} /* namespace scoreboard */
} /* namespace Deep2 */

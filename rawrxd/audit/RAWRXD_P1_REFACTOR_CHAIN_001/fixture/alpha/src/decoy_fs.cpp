// DECOY FILE -- file-system rename, not symbol rename.
//
// This is the exact false positive that was recorded against the first
// census: `RenameSymbol` matched five hits, all of them std::filesystem::rename
// moving files in EditTransaction.cpp. A symbol-rename implementation that
// greps for the token "rename" would rewrite this call site. It must not.
#include "calc_engine.h"

#include <filesystem>

namespace alpha {

void resetWidgetCacheSlot() {
    std::filesystem::rename("cache_slot_old", "cache_slot_new");
}

}  // namespace alpha

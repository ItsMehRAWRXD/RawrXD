#pragma once
#include "SemanticSafe.hpp"
namespace Deep2 {
inline void Deep2SemanticSafeModeApply() { SemanticSafeApply(); }
inline bool Deep2SemanticSafeModeActive() {
    const char* e = getenv("RAWRXD_SEMANTIC_SAFE");
    return e && e[0] == '1';
}
} // namespace Deep2

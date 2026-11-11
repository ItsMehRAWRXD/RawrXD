#pragma once
// Was: #include "../../include/nlohmann/json.hpp"
// That path does not exist in this worktree, so every target pulling in
// <nlohmann/json.hpp> through src/ failed with
//   fatal error C1083: Cannot open include file: '../../include/nlohmann/json.hpp'
// The vendored copy that IS present here is 3rdparty/nlohmann/json.hpp.
// Resolve to it relative to this file so the shim stays position-independent.
#if __has_include("../../3rdparty/nlohmann/json.hpp")
#include "../../3rdparty/nlohmann/json.hpp"   // IWYU pragma: export
#elif __has_include("../../include/nlohmann/json.hpp")
#include "../../include/nlohmann/json.hpp"    // IWYU pragma: export
#else
#error "nlohmann/json.hpp not found next to this shim"
#endif

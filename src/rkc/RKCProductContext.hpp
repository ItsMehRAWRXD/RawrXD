// RKCProductContext.hpp — ScreenPilot product assemble path (shared)
#pragma once
#include "RKCSession.hpp"
#include <cstddef>
#include <string>

namespace RawrXD {
namespace RKC {

struct ProductAssembleInput {
    std::string query;
    std::string modelPath;
    std::string selection;   // editor selection; only used for patch intent
    std::size_t byteBudget = 12288;
    bool probeOllama = true;
};

struct ProductAssembleResult {
    SessionResult session;
    std::string assembled;   // actual model input
    bool wantsPatch = false;
    bool includedSelection = false;
};

// Same authority chain as Win32IDE::assembleCommandInferenceContext.
ProductAssembleResult AssembleProductContext(const ProductAssembleInput& in);

} // namespace RKC
} // namespace RawrXD

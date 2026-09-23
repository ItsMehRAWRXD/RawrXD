#pragma once
#include <string>

namespace RawrXD::IDE {

struct InferenceGateResult {
    bool modelFound     = false;
    bool modelLoaded    = false;
    bool tokenizerReady = false;
    bool forwardPassOk  = false;
    bool logitsFinite   = false;
    int  tokenCount     = 0;
    int  generatedToken = -1;
    std::string modelPath;
    std::string diagnostics;
};

InferenceGateResult runLocalInferenceGate();

} // namespace RawrXD::IDE

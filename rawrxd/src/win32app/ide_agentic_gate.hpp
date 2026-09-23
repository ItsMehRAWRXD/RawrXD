#pragma once
#include <string>

namespace RawrXD::IDE {

struct AgenticGateResult {
    bool streamerBuilt      = false;
    bool engineInitOk       = false;
    bool modelLoadedOk      = false;
    bool channelOpened      = false;
    bool generationStarted  = false;
    bool tokensReceived     = false;
    bool toolRequestSeen    = false;
    bool toolInvoked        = false;
    bool toolResultReturned = false;

    // Extended cert fields for model-stream capture and two-phase tool loop
    bool        modelStreamStarted   = false;
    uint64_t    streamedTokenCount   = 0;
    std::string streamedText;
    bool        toolRequestParsed    = false;
    bool        toolAuthorityInvoked = false;
    bool        toolExecuted         = false;
    bool        toolResultInjected   = false;
    bool        continuationStarted  = false;
    uint64_t    postToolTokenCount   = 0;
    std::string rawToolRequest;
    std::string toolName;
    std::string toolResultReturnedByBridge;
    bool        nonceMatched         = false;

    int  tokenCount         = 0;
    std::string promptUsed;
    std::string firstTokenText;
    std::string diagnostics;
    std::string failStage;
    int  failCode           = 0;
};

AgenticGateResult runAgenticGate();

} // namespace RawrXD::IDE

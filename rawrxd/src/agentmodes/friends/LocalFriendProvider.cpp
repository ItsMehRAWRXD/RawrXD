// LocalFriendProvider.cpp — RAWRXD_PHONE_A_FRIEND_001
#include "agentmodes/friends/LocalFriendProvider.h"

#include "deep2/Deep2Engine.h"

#include <cstdio>

namespace rawrxd { namespace friendx {

LocalFriendProvider::LocalFriendProvider(std::string modelPath, uint32_t maxTokens)
    : modelPath_(std::move(modelPath)), maxTokens_(maxTokens) {}

std::string LocalFriendProvider::unavailableReason() const {
    if (modelPath_.empty()) return "no local model path configured for the friend provider";
    return "";
}

FriendResponse LocalFriendProvider::ask(const FriendRequest& request) {
    FriendResponse resp;
    resp.provider  = name();
    resp.model     = modelPath_;
    resp.turn      = request.action == FriendAction::Ask ? 1u : 0u;
    resp.turnLimit = request.maxTurns;
    resp.transport = "deep2_local_engine";

    if (!available()) {
        resp.success = false;
        resp.unavailableReason = unavailableReason();
        return resp;
    }

    // Build the prompt the same way a human would brief a second opinion:
    // objective, then evidence, then the question, then an explicit note that
    // the local system keeps the final decision.
    std::string prompt;
    prompt += "You are advising another engineering system. It retains final authority.\n";
    prompt += "Objective: " + request.objective + "\n";
    if (!request.context.empty())   prompt += "Context: " + request.context + "\n";
    if (!request.evidence.empty()) prompt += "Observed evidence:\n" + request.evidence + "\n";
    if (request.action == FriendAction::Challenge) {
        prompt += "Challenge the conclusion above. Name the weakest assumption.\n";
    } else if (request.action == FriendAction::Verify) {
        prompt += "State whether the evidence is sufficient to prove the claim.\n";
    }
    prompt += "Question: " + request.question + "\n";
    prompt += "Answer plainly, then list your uncertainties.\n";

    auto engine = std::make_shared<Deep2::Deep2Engine>();
    Deep2::EngineConfig config;
    config.maxSeqLen  = 4096;
    config.numThreads = 0;  // auto

    if (!engine->initialize(config)) {
        resp.success = false;
        resp.unavailableReason = "Deep2Engine::initialize returned false";
        return resp;
    }
    engine->enableVulkan(false);

    Deep2::ModelLoadDiag diag{};
    if (!engine->loadModel(modelPath_, &diag)) {
        resp.success = false;
        resp.unavailableReason = "loadModel failed at " + diag.stageName + ": " + diag.message;
        return resp;
    }

    Deep2::GenerationOptions opts;
    opts.maxTokens  = maxTokens_;
    opts.temperature = 0.0f;   // deterministic advice, so repeats are comparable
    opts.topK        = 1;
    opts.topP        = 1.0f;
    opts.seed        = 1;

    std::string text;
    auto callback = [&text](int32_t, const std::string& token) -> bool {
        text += token;
        return true;  // keep generating
    };

    const Deep2::GenerationResult result = engine->generateStream(prompt, opts, callback);
    if (!result.completed) {
        resp.success = false;
        resp.unavailableReason = "generation incomplete";
        if (!result.failureDetail.empty()) resp.unavailableReason += ": " + result.failureDetail;
        return resp;
    }

    resp.success = true;
    resp.answer  = text;
    resp.conversationId = request.conversationId;
    // The raw answer is parsed by PhoneAFriendAuthority; a provider does not
    // get to grade its own advice.
    return resp;
}

}} // namespace rawrxd::friendx

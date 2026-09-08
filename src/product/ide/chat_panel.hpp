#pragma once
/* Chat panel adapter — ProductRun only. ≤99 lines. */
#include "../../deep2/lavapath/ProductRun.hpp"
#include "history.hpp"
#include <string>

namespace rawr::product {

struct ChatPanel {
    Deep2::Deep2Engine* engine = nullptr;
    ConversationHistory hist;
    std::string streamed;
    const char* modelAlias = nullptr;

    bool SendChat(const char* prompt) {
        streamed.clear();
        if (!prompt || !prompt[0] || !modelAlias || !modelAlias[0]) return false;
        hist.append("user", prompt);
        product_run::Request req{};
        req.modelAlias = modelAlias;
        req.prompt = prompt;
        req.maxTokens = 64;
        req.engine = engine;
        req.keepOpen = engine ? 1 : 0;
        req.onPiece = [this](const std::string& p) {
            streamed += p;
            return true;
        };
        auto rc = product_run::ProductRun(req);
        if (streamed.empty()) streamed = rc.text;
        hist.append("assistant", streamed);
        return rc.productPass != 0 && !streamed.empty();
    }
};

} // namespace rawr::product

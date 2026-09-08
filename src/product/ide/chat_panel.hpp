#pragma once
#include "../../deep2/lavapath/ProductRuntime.hpp"
#include "history.hpp"
#include <string>
namespace rawr::product {

struct ChatPanel {
    product_run::ProductRuntime* rt = nullptr;
    ConversationHistory hist;
    std::string streamed;
    void appendToken(const std::string& tok) { streamed += tok; }
    bool SendChat(const char* prompt) {
        streamed.clear();
        if (!rt || !prompt || !prompt[0]) return false;
        hist.append("user", prompt);
        Deep2::GenerationOptions opts{};
        opts.maxTokens = 256;
        opts.temperature = 0.0f;
        std::string acc;
        rt->engine.generateStream(prompt, opts, [&](int32_t, const std::string& p) {
            appendToken(p);
            acc += p;
            return (uint32_t)acc.size() < 1024u;
        });
        hist.append("assistant", streamed);
        return !streamed.empty();
    }
};

} // namespace rawr::product

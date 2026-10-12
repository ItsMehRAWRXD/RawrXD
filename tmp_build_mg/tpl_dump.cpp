// prompt_dump - replicate RawrXDCore_RunInference's exact
// prompt construction (chat template render + native
// tokenize) and print the resulting token sequence.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <GGUFLoader.hpp>
#include "ChatTemplate.hpp"
#include "ModelGenieRuntime.h"

int main(int argc, char* argv[])
{
    const char* gguf = argc > 1 ? argv[1]
        : "F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    const char* userText = argc > 2 ? argv[2] : "Hello, world!";

    Deep2::GGUFLoader loader;
    if (!loader.load(gguf)) {
        std::fprintf(stderr, "GGUF load failed\n");
        return 1;
    }
    const std::string tmpl =
        loader.getMetaString("tokenizer.chat_template", "");

    mg_model_t* m = nullptr;
    mg_model_config_t cfg{};
    cfg.max_seq_len = 1024;
    cfg.use_kv_cache = true;
    if (mg_model_load(gguf, &cfg, &m) != MG_SUCCESS || !m) {
        std::fprintf(stderr, "mg_model_load failed\n");
        return 2;
    }

    const uint32_t bos = mg_model_bos_token_id(m);
    const uint32_t eos = mg_model_eos_token_id(m);
    char bosText[256] = {}, eosText[256] = {};
    mg_model_token_text(m, bos, bosText, sizeof(bosText));
    mg_model_token_text(m, eos, eosText, sizeof(eosText));

    // Render exactly like RunInference: one user turn,
    // assistant generation prefix.
    RawrXD::ChatTemplateVars vars;
    vars.bosToken = bosText;
    vars.eosToken = eosText;
    vars.addGenerationPrompt = true;
    vars.messages.push_back({"user", userText});
    std::string rendered;
    const bool ok = RawrXD::RenderChatTemplate(tmpl, vars, rendered);
    std::printf("render_ok = %d\n", ok);
    std::printf("rendered = <<<\n%s\n>>>\n", rendered.c_str());

    // Tokenize exactly like RunInference: the template
    // renders {{ bos_token }} as the BOS token's string
    // form; emit the BOS id directly and encode the rest.
    std::vector<uint32_t> tokens;
    const char* enc = rendered.c_str();
    bool prependBos = true;
    if (ok) {
        const size_t bosLen =
            std::char_traits<char>::length(bosText);
        if (bos != 0 && bosLen > 0 &&
            rendered.size() >= bosLen &&
            rendered.compare(0, bosLen, bosText) == 0) {
            tokens.push_back(bos);
            enc = rendered.c_str() + bosLen;
            prependBos = false;
        }
    }

    size_t n = 0;
    const mg_error_t capRc = mg_model_tokenize(m, enc, nullptr, &n);
    if ((capRc != MG_SUCCESS && capRc != MG_ERROR_INVALID_ARGUMENT) ||
        n == 0) {
        std::fprintf(stderr, "tokenize capacity failed: %d\n",
                     (int)capRc);
        mg_model_free(m);
        return 3;
    }
    const size_t base = tokens.size();
    tokens.resize(base + n);
    size_t fill = n;
    if (mg_model_tokenize(m, enc, tokens.data() + base,
                              &fill) != MG_SUCCESS ||
        fill != n) {
        std::fprintf(stderr, "tokenize fill failed\n");
        mg_model_free(m);
        return 4;
    }
    if (prependBos && bos != 0) {
        tokens.insert(tokens.begin(), bos);
    }

    std::printf("prompt token count = %zu\n", tokens.size());
    std::printf("prompt ids: [");
    for (size_t i = 0; i < tokens.size(); ++i) {
        std::printf("%s%u", i ? ", " : "", tokens[i]);
    }
    std::printf("]\n");
    std::printf("prompt pieces:\n");
    for (uint32_t t : tokens) {
        char buf[64] = {};
        mg_model_token_text(m, t, buf, sizeof(buf));
        std::printf("  %u -> \"%s\"\n", t, buf);
    }
    std::fflush(stdout);

    mg_model_free(m);
    return 0;
}

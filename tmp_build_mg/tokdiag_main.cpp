// tokdiag_main - tokenizer diagnostic against the fresh RawrXDCore.dll
// (mg_model_tokenize / mg_model_token_text via the DLL's exports).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "ModelGenieRuntime.h"

int main(int argc, char* argv[])
{
    const char* gguf = argc > 1 ? argv[1]
        : "F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    const char* text = argc > 2 ? argv[2] : "Human: Hello, world!";

    mg_model_t* m = nullptr;
    mg_model_config_t cfg{};
    cfg.max_seq_len = 1024;
    cfg.use_kv_cache = true;
    const mg_error_t rc = mg_model_load(gguf, &cfg, &m);
    if (rc != MG_SUCCESS || !m) {
        std::fprintf(stderr, "mg_model_load failed: %d\n", (int)rc);
        return 1;
    }

    // Capacity probe: a too-small/absent buffer reports the required
    // size via MG_ERROR_INVALID_ARGUMENT (by contract).
    size_t n = 0;
    const mg_error_t capRc = mg_model_tokenize(m, text, nullptr, &n);
    if ((capRc != MG_SUCCESS && capRc != MG_ERROR_INVALID_ARGUMENT) ||
        n == 0) {
        std::fprintf(stderr, "tokenize capacity probe failed: %d\n",
                     (int)capRc);
        mg_model_free(m);
        return 2;
    }
    std::vector<uint32_t> ids(n, 0);
    size_t fill = n;
    if (mg_model_tokenize(m, text, ids.data(), &fill) != MG_SUCCESS ||
        fill != n) {
        std::fprintf(stderr, "tokenize fill failed\n");
        mg_model_free(m);
        return 3;
    }

    const uint32_t bos = mg_model_bos_token_id(m);
    const uint32_t eos = mg_model_eos_token_id(m);
    char bosText[64] = {}, eosText[64] = {};
    mg_model_token_text(m, bos, bosText, sizeof(bosText));
    mg_model_token_text(m, eos, eosText, sizeof(eosText));

    std::printf("text      = \"%s\"\n", text);
    std::printf("count     = %zu\n", n);
    std::printf("bos       = %u (\"%s\")\n", bos, bosText);
    std::printf("eos       = %u (\"%s\")\n", eos, eosText);
    std::string roundtrip;
    for (size_t i = 0; i < n; ++i) {
        char buf[64] = {};
        mg_model_token_text(m, ids[i], buf, sizeof(buf));
        std::printf("  [%3zu] id=%-6u text=\"%s\"\n", i, ids[i], buf);
        roundtrip += buf;
    }
    std::printf("roundtrip = \"%s\"\n", roundtrip.c_str());

    // Vocab forensics: how is whitespace represented? Search the
    // entire vocab for a literal space, the SentencePiece metaspace
    // marker (U+2581) and the GPT-2-style BPE space marker
    // "Ġ" (U+0120).
    const std::string kMeta("\xE2\x96\x81");  // U+2581 ▁
    const std::string kGpt2Space("\xC4\xA0"); // U+0120 Ġ
    int spaceId = -1, metaId = -1, gpt2Id = -1;
    int metaCount = 0, gpt2Count = 0;
    const uint32_t vocabSize = mg_model_vocab_size(m);
    for (uint32_t id = 0; id < vocabSize; ++id) {
        char buf[64] = {};
        if (!mg_model_token_text(m, id, buf, sizeof(buf)))
            continue;
        const std::string piece(buf);
        if (piece == " " && spaceId < 0) spaceId = (int)id;
        if (piece.find(kMeta) != std::string::npos) {
            if (metaId < 0) metaId = (int)id;
            metaCount++;
        }
        if (piece.find(kGpt2Space) != std::string::npos) {
            if (gpt2Id < 0) gpt2Id = (int)id;
            gpt2Count++;
        }
    }
    std::printf("vocab size                = %u\n", vocabSize);
    std::printf("literal-space token id    = %d\n", spaceId);
    std::printf("metaspace(U+2581) first id= %d (tokens containing it: %d)\n",
                metaId, metaCount);
    std::printf("BPE-space(U+0120) first id= %d (tokens containing it: %d)\n",
                gpt2Id, gpt2Count);
    std::printf("vocab head (0..40):\n");
    for (uint32_t id = 0; id <= 40; ++id) {
        char buf[64] = {};
        mg_model_token_text(m, id, buf, sizeof(buf));
        std::printf("  [%3u] \"%s\"\n", id, buf);
    }
    std::fflush(stdout);

    mg_model_free(m);
    return 0;
}

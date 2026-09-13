// deep2_k2_semantic_seal_cert.cpp — K2_SEMANTIC_SEAL_001
// Independent correctness: q_b=12288, vocab/tokenizer, chat template.
// Does NOT imply wall ownership or residency.
#include "ChatTemplate.hpp"
#include "Deep2Engine.h"
#include "K2GlobalTensorIndex.hpp"
#include "KimiK2Config.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

static void Sync(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#endif
}

int main() {
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\K2_SEMANTIC_SEAL_001", nullptr);
#endif
    std::string dir =
        (std::getenv("DEEP2_K2_SHARD_DIR") && std::getenv("DEEP2_K2_SHARD_DIR")[0])
            ? std::getenv("DEEP2_K2_SHARD_DIR")
            : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    printf("K2_SEMANTIC_SEAL_001\n");
    printf("LAW=independent correctness; not wall ownership\n");
    printf("MODEL=%s\n", dir.c_str());
    if (!fs::is_directory(dir)) {
        printf("K2_SEMANTIC_SEAL_001=SKIP\n");
        _exit(0);
    }

    Sync("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    Sync("DEEP2_REAL_K2_GENERATE", "1");

    Deep2Engine eng;
    EngineConfig cfg{};
    cfg.hiddenDim = 7168;
    cfg.numLayers = 61;
    cfg.numHeads = 64;
    cfg.numKVHeads = 1;
    cfg.vocabSize = 163840;
    cfg.useMLA = true;
    cfg.maxSeqLen = 64;
    if (!eng.initialize(cfg) || !eng.openK2ShardDirectory(dir)) {
        printf("K2_SEMANTIC_SEAL_001=FAIL open\n");
        _exit(2);
    }

    const auto& k2 = eng.k2ShardConfig();
    const uint32_t qHead = k2.qkNopeHeadDim + k2.qkRopeHeadDim;
    const uint32_t qBExpect = k2.numHeads * qHead; // 64*(128+64)=12288
    printf("CFG family=%d arch=%s hidden=%u layers=%u heads=%u kv=%u\n",
           (int)k2.family, k2.architecture.c_str(), k2.hiddenDim, k2.numLayers,
           k2.numHeads, k2.numKVHeads);
    printf("CFG qLora=%u kvLora=%u nope=%u rope=%u v=%u vocab=%u\n",
           k2.qLoraRank, k2.kvLoraRank, k2.qkNopeHeadDim, k2.qkRopeHeadDim,
           k2.vHeadDim, k2.vocabSize);
    printf("CFG q_b_cols_expect=%u (=heads*(nope+rope))\n", qBExpect);

    uint64_t qB0 = 0, qB1 = 0, qBCols = 0;
    bool qBOk = false;
    if (const auto* idx = eng.k2TensorIndex()) {
        if (auto ref = idx->Find("blk.0.attn_q_b.weight")) {
            if (ref->shape.size() >= 2) {
                qB0 = ref->shape[0];
                qB1 = ref->shape[1];
                qBCols = (std::max)(qB0, qB1);
                qBOk = (qBCols == 12288ull) && (qBExpect == 12288u);
            }
            printf("TENSOR blk.0.attn_q_b.weight shape=[%llu,%llu] max=%llu "
                   "ggml=%u\n",
                   (unsigned long long)qB0, (unsigned long long)qB1,
                   (unsigned long long)qBCols, ref->ggmlType);
        } else {
            printf("TENSOR blk.0.attn_q_b.weight MISSING\n");
        }
    }

    bool vocabOk = (k2.vocabSize == 163840u);
    bool mlaOk = (k2.qLoraRank == 1536u) && (k2.kvLoraRank == 512u) &&
                 (k2.qkNopeHeadDim == 128u) && (k2.qkRopeHeadDim == 64u) &&
                 (k2.numHeads == 64u);
    bool tokOk = false;
    // Tokenizer presence: token_embd rows == vocab (tiktoken/BPE payload in GGUF).
    if (const auto* idx = eng.k2TensorIndex()) {
        if (auto emb = idx->Find("token_embd.weight")) {
            uint64_t rows = emb->shape.empty() ? 0 : emb->shape[0];
            uint64_t cols = emb->shape.size() > 1 ? emb->shape[1] : 0;
            const uint64_t vmax = (std::max)(rows, cols);
            tokOk = (vmax == 163840ull);
            printf("TOKEN_EMBD shape=[%llu,%llu] vocab_axis=%llu\n",
                   (unsigned long long)rows, (unsigned long long)cols,
                   (unsigned long long)vmax);
        }
    }

    ChatTemplate tmpl;
    bool chatOk = false;
    std::string firstShard;
    for (auto& e : fs::directory_iterator(dir)) {
        if (e.path().extension() == ".gguf") {
            firstShard = e.path().string();
            break;
        }
    }
    if (!firstShard.empty() && tmpl.initFromGGUF(firstShard)) {
        chatOk = tmpl.isInitialized() &&
                 tmpl.getType() != ChatTemplateType::UNKNOWN;
        printf("CHAT_TEMPLATE type=%s ok=%d\n", tmpl.getTypeName(),
               chatOk ? 1 : 0);
        auto formatted = tmpl.formatSingle("ping", "You are a local decode assistant.");
        printf("CHAT_FORMAT_BYTES=%zu\n", formatted.size());
        chatOk = chatOk && !formatted.empty();
    } else {
        // Fallback: architecture detect only.
        auto t = ChatTemplate::detectFromModel(k2.architecture, k2.modelType);
        chatOk = (t != ChatTemplateType::UNKNOWN);
        printf("CHAT_TEMPLATE detect_only type=%d ok=%d\n", (int)t,
               chatOk ? 1 : 0);
    }

    printf("\nSEAL_QB=%d SEAL_VOCAB=%d SEAL_MLA_DIMS=%d SEAL_TOKENIZER=%d "
           "SEAL_CHAT=%d\n",
           qBOk ? 1 : 0, vocabOk ? 1 : 0, mlaOk ? 1 : 0, tokOk ? 1 : 0,
           chatOk ? 1 : 0);
    const bool pass = qBOk && vocabOk && mlaOk && tokOk && chatOk;
    printf("K2_SEMANTIC_SEAL_001=%s\n", pass ? "PASS" : "FAIL");

    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\K2_SEMANTIC_SEAL_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "q_b_cols=%llu expect=12288 qbOk=%d vocabOk=%d mlaOk=%d "
                   "tokOk=%d chatOk=%d\n",
                (unsigned long long)qBCols, qBOk ? 1 : 0, vocabOk ? 1 : 0,
                mlaOk ? 1 : 0, tokOk ? 1 : 0, chatOk ? 1 : 0);
        fprintf(f, "K2_SEMANTIC_SEAL_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}

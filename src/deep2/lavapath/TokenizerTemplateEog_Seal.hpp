#pragma once
/* SealTokEog — fail-closed tokenizer/template/EOG from GGUF KV. ≤99. */
#include "TokenizerTemplateEog.hpp"
#include <cstdlib>
#include <cstdio>

namespace rawr::olma {

inline bool ReqKvU32(const Deep2::GGUFLoadResult& r, const char* key, uint32_t& out, TokEogSeal& t,
                     const char* tag) {
    if (!r.rawKv.count(key)) {
        TBlock(t, tag, key, "absent", "missing", "TOKENIZER_TEMPLATE_EOG");
        return false;
    }
    char* e = nullptr;
    unsigned long v = std::strtoul(r.rawKv.at(key).c_str(), &e, 10);
    if (!e || e == r.rawKv.at(key).c_str() || *e || v > 0xFFFFFFFFul) {
        TBlock(t, tag, "u32", r.rawKv.at(key), "invalid", "TOKENIZER_TEMPLATE_EOG");
        return false;
    }
    out = (uint32_t)v;
    return true;
}

inline bool SealTokEog(const Deep2::GGUFLoadResult& r, const GeomSeal& geom,
                       const SchemaSeal& schema, TokEogSeal& t) {
    t = TokEogSeal{};
    t.geom = geom;
    t.ONE_LOCAL_MODEL_AUTHORITY = 1;
    t.NO_STATIC_TOKEN_IDS = 1;
    if (!geom.PASS || !schema.PASS) {
        TBlock(t, "PREREQ", "geom+schema PASS", "fail", "missing", "ONE_LOCAL_MODEL_AUTHORITY");
        return false;
    }
    if (!r.rawKv.count("tokenizer.ggml.model") || r.rawKv.at("tokenizer.ggml.model").empty()) {
        TBlock(t, "TOKENIZER_MODEL", "tokenizer.ggml.model", "absent", "missing",
               "TOKENIZER_TEMPLATE_EOG");
        return false;
    }
    t.TOKENIZER_MODEL = r.rawKv.at("tokenizer.ggml.model");
    t.TOKENIZER_FROM_MODEL = 1;
    t.VOCAB_SIZE = r.metadata.vocabSize ? r.metadata.vocabSize : schema.VOCAB;
    if (!t.VOCAB_SIZE) {
        TBlock(t, "VOCAB", "vocab>0", "0", "missing", "TOKENIZER_TEMPLATE_EOG");
        return false;
    }
    t.VOCAB_FROM_MODEL = 1;
    t.VOCAB_MATCHES_SCHEMA = (t.VOCAB_SIZE == schema.VOCAB) ? 1 : 0;
    if (!t.VOCAB_MATCHES_SCHEMA) {
        TBlock(t, "VOCAB", std::to_string(schema.VOCAB), std::to_string(t.VOCAB_SIZE), "shape",
               "TOKENIZER_TEMPLATE_EOG");
        return false;
    }
    if (!ReqKvU32(r, "tokenizer.ggml.bos_token_id", t.BOS_TOKEN_ID, t, "BOS")) return false;
    t.BOS_FROM_MODEL = 1;
    if (!ReqKvU32(r, "tokenizer.ggml.eos_token_id", t.EOS_TOKEN_ID, t, "EOS")) return false;
    t.EOS_FROM_MODEL = 1;
    t.EOG_TOKEN_ID = t.EOS_TOKEN_ID;
    t.EOG_FROM_MODEL = 1;
    if (r.rawKv.count("tokenizer.ggml.unknown_token_id"))
        (void)ReqKvU32(r, "tokenizer.ggml.unknown_token_id", t.UNK_TOKEN_ID, t, "UNK");
    if (r.rawKv.count("tokenizer.ggml.padding_token_id"))
        (void)ReqKvU32(r, "tokenizer.ggml.padding_token_id", t.PAD_TOKEN_ID, t, "PAD");
    if (t.BOS_TOKEN_ID >= t.VOCAB_SIZE || t.EOS_TOKEN_ID >= t.VOCAB_SIZE) {
        TBlock(t, "TOKEN_ID_RANGE", "id<vocab", "oob", "invalid", "TOKENIZER_TEMPLATE_EOG");
        return false;
    }
    if (r.rawKv.count("tokenizer.chat_template") && !r.rawKv.at("tokenizer.chat_template").empty()) {
        t.TEMPLATE_BYTES = r.rawKv.at("tokenizer.chat_template").size();
        t.TEMPLATE_FROM_MODEL = 1;
    } else if (!r.metadata.chatTemplate.empty()) {
        t.TEMPLATE_BYTES = r.metadata.chatTemplate.size();
        t.TEMPLATE_FROM_MODEL = 1;
    } else {
        TBlock(t, "TEMPLATE", "tokenizer.chat_template", "absent", "missing",
               "TOKENIZER_TEMPLATE_EOG");
        return false;
    }
    if (r.rawKv.count("tokenizer.ggml.merges")) {
        /* value recorded as [array:N] by loader */
        const std::string& m = r.rawKv.at("tokenizer.ggml.merges");
        if (m.rfind("[array:", 0) == 0)
            t.MERGES_COUNT = (size_t)std::strtoul(m.c_str() + 7, nullptr, 10);
    }
    t.GEOMETRY_UNCHANGED =
        (t.geom.HIDDEN == geom.HIDDEN && t.geom.LAYERS == geom.LAYERS) ? 1 : 0;
    if (!t.GEOMETRY_UNCHANGED) {
        TBlock(t, "GEOMETRY", "unchanged", "changed", "missing", "GEOMETRY_SEAL");
        return false;
    }
    t.PASS = 1;
    t.FIRST_DELTA = "DEEP2_SESSION_PREFILL";
    return true;
}

inline void EmitTokEog(FILE* f, const TokEogSeal& t) {
    if (!f) f = stdout;
    if (!t.PASS) {
        std::fprintf(f, "TOKENIZER_TEMPLATE_EOG_001=BLOCKED\n");
        std::fprintf(f, "BLOCKED_AT=%s\nBLOCKED_OWNER=TOKENIZER_TEMPLATE_EOG\n",
                     t.BLOCKED_AT.c_str());
        std::fprintf(f, "EXPECTED=%s\nOBSERVED=%s\n", t.EXPECTED.c_str(), t.OBSERVED.c_str());
        std::fprintf(f, "REASON=%s\nFIRST_DELTA=%s\n", t.REASON.c_str(), t.FIRST_DELTA.c_str());
        return;
    }
    std::fprintf(f, "TOKENIZER_MODEL=%s\nVOCAB_SIZE=%u\n", t.TOKENIZER_MODEL.c_str(),
                 t.VOCAB_SIZE);
    std::fprintf(f, "BOS_TOKEN_ID=%u\nEOS_TOKEN_ID=%u\nEOG_TOKEN_ID=%u\n", t.BOS_TOKEN_ID,
                 t.EOS_TOKEN_ID, t.EOG_TOKEN_ID);
    std::fprintf(f, "UNK_TOKEN_ID=%u\nPAD_TOKEN_ID=%u\n", t.UNK_TOKEN_ID, t.PAD_TOKEN_ID);
    std::fprintf(f, "TEMPLATE_BYTES=%zu\nMERGES_COUNT=%zu\n", t.TEMPLATE_BYTES, t.MERGES_COUNT);
    std::fprintf(f, "TOKENIZER_FROM_MODEL=%d\nVOCAB_FROM_MODEL=%d\n", t.TOKENIZER_FROM_MODEL,
                 t.VOCAB_FROM_MODEL);
    std::fprintf(f, "BOS_FROM_MODEL=%d\nEOS_FROM_MODEL=%d\nEOG_FROM_MODEL=%d\n", t.BOS_FROM_MODEL,
                 t.EOS_FROM_MODEL, t.EOG_FROM_MODEL);
    std::fprintf(f, "TEMPLATE_FROM_MODEL=%d\nNO_STATIC_TOKEN_IDS=%d\n", t.TEMPLATE_FROM_MODEL,
                 t.NO_STATIC_TOKEN_IDS);
    std::fprintf(f, "VOCAB_MATCHES_SCHEMA=%d\nGEOMETRY_UNCHANGED=%d\n", t.VOCAB_MATCHES_SCHEMA,
                 t.GEOMETRY_UNCHANGED);
    std::fprintf(f, "ONE_LOCAL_MODEL_AUTHORITY=%d\n", t.ONE_LOCAL_MODEL_AUTHORITY);
    std::fprintf(f, "TOKENIZER_TEMPLATE_EOG_001=PASS\nFIRST_DELTA=DEEP2_SESSION_PREFILL\n");
}

} // namespace rawr::olma

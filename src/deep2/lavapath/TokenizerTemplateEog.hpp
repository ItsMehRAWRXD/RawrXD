#pragma once
/* TOKENIZER / TEMPLATE / EOG contract from opened GGUF only. ≤99. */
#include "LocalModelAuthority.hpp"
#include "TensorNameTypeBinding.hpp"
#include <cstdint>
#include <string>

namespace rawr::olma {

struct TokEogSeal {
    int PASS = 0;
    int TOKENIZER_FROM_MODEL = 0;
    int VOCAB_FROM_MODEL = 0;
    int BOS_FROM_MODEL = 0;
    int EOS_FROM_MODEL = 0;
    int EOG_FROM_MODEL = 0;
    int TEMPLATE_FROM_MODEL = 0;
    int NO_STATIC_TOKEN_IDS = 1;
    int VOCAB_MATCHES_SCHEMA = 0;
    int GEOMETRY_UNCHANGED = 0;
    int ONE_LOCAL_MODEL_AUTHORITY = 1;
    std::string TOKENIZER_MODEL;
    uint32_t VOCAB_SIZE = 0;
    uint32_t BOS_TOKEN_ID = 0;
    uint32_t EOS_TOKEN_ID = 0;
    uint32_t UNK_TOKEN_ID = 0;
    uint32_t PAD_TOKEN_ID = 0;
    uint32_t EOG_TOKEN_ID = 0; /* == EOS for stop */
    size_t TEMPLATE_BYTES = 0;
    size_t MERGES_COUNT = 0;
    std::string BLOCKED_AT, EXPECTED, OBSERVED, REASON, FIRST_DELTA;
    GeomSeal geom{};
};

inline void TBlock(TokEogSeal& t, const char* at, const std::string& exp, const std::string& obs,
                   const char* reason, const char* delta) {
    t.PASS = 0;
    t.BLOCKED_AT = at;
    t.EXPECTED = exp;
    t.OBSERVED = obs;
    t.REASON = reason;
    t.FIRST_DELTA = delta;
}

bool SealTokEog(const Deep2::GGUFLoadResult& r, const GeomSeal& geom, const SchemaSeal& schema,
                TokEogSeal& t);
void EmitTokEog(FILE* f, const TokEogSeal& t);

} // namespace rawr::olma

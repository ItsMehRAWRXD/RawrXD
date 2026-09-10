// Deep2SessionPrefill.hpp — session weight load + real prefill seal. ≤99.
#pragma once
#include "LocalModelAuthority_Bundle.hpp"
#include <cstdint>
#include <string>

namespace rawr::olma {

struct PrefillSeal {
    int PASS = 0;
    int AUTHORITY_LADDER_COMPLETE = 0;
    int SESSION_WEIGHT_LOAD = 0;
    int REAL_PREFILL = 0;
    int DEEP2_SESSION = 0;
    int TOKENS_PRODUCED = 0;
    int FIRST_TOKEN = 0;
    int GEOMETRY_UNCHANGED = 1;
    int ONE_LOCAL_MODEL_AUTHORITY = 1;
    uint32_t PREFILL_TOKENS = 0;
    uint32_t DECODE_TOKENS = 0;
    std::string BLOCKED_AT, REASON, FIRST_DELTA, MODEL_PATH;
    AuthorityBundle auth{};
};

inline void PBlock(PrefillSeal& p, const char* at, const char* why, const char* delta) {
    p.PASS = 0;
    p.BLOCKED_AT = at;
    p.REASON = why;
    p.FIRST_DELTA = delta;
}

} // namespace rawr::olma

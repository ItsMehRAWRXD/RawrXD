#include "RawrXD_TokenPressureValveBridge.hpp"

static unsigned char tpv_lower(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return (unsigned char)(ch - 'A' + 'a');
    return ch;
}

static int tpv_contains_word(const char* s, uint32_t n, const char* word) {
    if (!s || !word) return 0;
    uint32_t w = 0;
    while (word[w]) ++w;
    if (!w || n < w) return 0;
    for (uint32_t i = 0; i <= n - w; ++i) {
        uint32_t j = 0;
        while (j < w && tpv_lower((unsigned char)s[i + j]) == (unsigned char)word[j]) ++j;
        if (j == w) return 1;
    }
    return 0;
}

static int tpv_all_space(const char* s, uint32_t n) {
    if (!s || !n) return 0;
    for (uint32_t i = 0; i < n; ++i) {
        unsigned char ch = (unsigned char)s[i];
        if (!(ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')) return 0;
    }
    return 1;
}

uint32_t TPV_ClassifyUtf8Token(const char* token_bytes, uint32_t token_len) {
    if (!token_bytes || token_len == 0) return 0;

    uint32_t flags = 0;
    if (tpv_all_space(token_bytes, token_len)) flags |= TPV_TOK_WHITESPACE;

    uint32_t backticks = 0;
    for (uint32_t i = 0; i < token_len; ++i) {
        unsigned char ch = (unsigned char)token_bytes[i];
        if (ch == '\n') flags |= TPV_TOK_NEWLINE;
        if (ch == '`') ++backticks;
        if (ch == '{' || ch == '[' || ch == '(') flags |= TPV_TOK_BRACE_OPEN;
        if (ch == '}' || ch == ']' || ch == ')') flags |= TPV_TOK_BRACE_CLOSE;
        if (ch == '.' || ch == '!' || ch == '?' || ch == ';') flags |= TPV_TOK_SENT_END;
    }
    if (backticks) flags |= TPV_TOK_FENCE | TPV_TOK_CODE;

    if (tpv_contains_word(token_bytes, token_len, "error") ||
        tpv_contains_word(token_bytes, token_len, "fail") ||
        tpv_contains_word(token_bytes, token_len, "fatal") ||
        tpv_contains_word(token_bytes, token_len, "exception") ||
        tpv_contains_word(token_bytes, token_len, "denied")) {
        flags |= TPV_TOK_ERROR;
    }

    if (tpv_contains_word(token_bytes, token_len, "patch") ||
        tpv_contains_word(token_bytes, token_len, "write") ||
        tpv_contains_word(token_bytes, token_len, "edit")) {
        flags |= TPV_TOK_EDIT;
    }

    if (tpv_contains_word(token_bytes, token_len, "delete") ||
        tpv_contains_word(token_bytes, token_len, "remove") ||
        tpv_contains_word(token_bytes, token_len, "overwrite")) {
        flags |= TPV_TOK_EDIT | TPV_TOK_DESTRUCTIVE;
    }

    if (tpv_contains_word(token_bytes, token_len, "basically") ||
        tpv_contains_word(token_bytes, token_len, "actually") ||
        tpv_contains_word(token_bytes, token_len, "just") ||
        tpv_contains_word(token_bytes, token_len, "really")) {
        flags |= TPV_TOK_FILLER;
    }

    if (tpv_contains_word(token_bytes, token_len, "<|end") ||
        tpv_contains_word(token_bytes, token_len, "</s>") ||
        tpv_contains_word(token_bytes, token_len, "<eos")) {
        flags |= TPV_TOK_STOPLIKE;
    }

    return flags;
}

uint32_t TPV_UpdateUtf8Token(TPV_State* state, uint32_t token_id, const char* token_bytes, uint32_t token_len, TPV_Result* out_result) {
    uint32_t flags = TPV_ClassifyUtf8Token(token_bytes, token_len);
    return TPV_UpdateToken(state, token_id, flags, out_result);
}

uint32_t TPV_ResultToSamplerHints(const TPV_Result* result, TPV_SamplerHints* out_hints) {
    if (!result || !out_hints) return 1;

    out_hints->repeat_penalty_bps = 0;
    out_hints->top_k_delta = 0;
    out_hints->stop_hint = 0;
    out_hints->compress_hint = 0;
    out_hints->repair_hint = 0;
    out_hints->approval_hold = 0;

    if (result->action & TPV_ACT_REPEAT_PENALTY) {
        out_hints->repeat_penalty_bps += (int32_t)(result->repeat_pressure * 2);
    }
    if (result->action & TPV_ACT_NARROW) {
        out_hints->top_k_delta -= 8;
    }
    if (result->action & TPV_ACT_WIDEN) {
        out_hints->top_k_delta += 8;
    }
    if (result->action & TPV_ACT_COMPRESS) {
        out_hints->compress_hint = 1;
        out_hints->top_k_delta -= 4;
    }
    if (result->action & TPV_ACT_STOP_HINT) {
        out_hints->stop_hint = 1;
    }
    if (result->action & TPV_ACT_REPAIR_JET) {
        out_hints->repair_hint = 1;
        out_hints->top_k_delta -= 6;
    }
    if (result->action & TPV_ACT_APPROVAL_HOLD) {
        out_hints->approval_hold = 1;
        out_hints->stop_hint = 1;
    }
    return 0;
}


/* ============================================================================
   rawrxd/tools/reveng_helper.cpp
   Implementation of the zero-dependency reverse-engineering toolkit.
   ============================================================================ */

#include "reveng_helper.h"

/* ============================================================================
   Platform file-system helpers (Windows & POSIX)
   ============================================================================ */

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <share.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

namespace rawrxd {
namespace reveng {

/* ============================================================================
   Section 1 — File helpers
   ============================================================================ */

bool slurp_file(const char* path, std::string* out) {
    FILE* fp = nullptr;
#ifdef _WIN32
    fopen_s(&fp, path, "rb");
#else
    fp = std::fopen(path, "rb");
#endif
    if (!fp) return false;
    std::fseek(fp, 0, SEEK_END);
    long sz = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    if (sz < 0) { std::fclose(fp); return false; }
    out->resize(static_cast<std::size_t>(sz));
    std::size_t rd = std::fread(&(*out)[0], 1, out->size(), fp);
    std::fclose(fp);
    if (rd != out->size()) return false;
    return true;
}

void collect_files(const char* root, const char* ext, std::vector<std::string>* out) {
    std::size_t ext_len = std::strlen(ext);
#ifdef _WIN32
    std::string pattern = root;
    pattern += "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            std::size_t len = std::strlen(fd.cFileName);
            if (len >= ext_len && _stricmp(fd.cFileName + len - ext_len, ext) == 0) {
                std::string p = root; p += "\\"; p += fd.cFileName;
                out->push_back(p);
            }
        } else {
            if (std::strcmp(fd.cFileName, ".") == 0 || std::strcmp(fd.cFileName, "..") == 0) continue;
            std::string sub = root; sub += "\\"; sub += fd.cFileName;
            collect_files(sub.c_str(), ext, out);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR* d = opendir(root);
    if (!d) return;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_type == DT_REG) {
            std::size_t len = std::strlen(ent->d_name);
            if (len >= ext_len && std::strcmp(ent->d_name + len - ext_len, ext) == 0) {
                std::string p = root; p += "/"; p += ent->d_name;
                out->push_back(p);
            }
        } else if (ent->d_type == DT_DIR) {
            if (std::strcmp(ent->d_name, ".") == 0 || std::strcmp(ent->d_name, "..") == 0) continue;
            std::string sub = root; sub += "/"; sub += ent->d_name;
            collect_files(sub.c_str(), ext, out);
        }
    }
    closedir(d);
#endif
}

/* ============================================================================
   Section 2 — CRC-32 (slice-by-8)
   ============================================================================ */

static uint32_t crc32_reflect(uint32_t ref, uint8_t ch) {
    uint32_t value = 0;
    for (int i = 1; i < (ch + 1); ++i) {
        if (ref & 1) value |= (1U << (ch - i));
        ref >>= 1;
    }
    return value;
}

static void crc32_build_table(uint32_t table[256], uint32_t poly) {
    for (uint32_t i = 0; i <= 0xFF; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ ((crc & 1u) ? poly : 0u);
        table[i] = crc;
    }
}

Crc32::Crc32(Kind k) : init_(0), xorout_(0) {
    uint32_t poly = (k == Kind::Castagnoli) ? 0x82f63b78u : 0xedb88320u;
    uint32_t base[256];
    crc32_build_table(base, poly);

    for (int i = 0; i < 256; ++i) {
        uint32_t crc = base[i];
        tab_[0][i] = crc;
        for (int j = 1; j < 8; ++j) {
            crc = (crc >> 8) ^ base[crc & 0xFF];
            tab_[j][i] = crc;
        }
    }
    xorout_ = 0xFFFFFFFFu;
}

uint32_t Crc32::compute(const uint8_t* data, std::size_t len, uint32_t seed) const {
    uint32_t crc = seed ^ xorout_;
    while (len >= 8) {
        crc ^= (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
        uint32_t d = (uint32_t)data[4] | ((uint32_t)data[5] << 8) | ((uint32_t)data[6] << 16) | ((uint32_t)data[7] << 24);
        crc = tab_[7][crc & 0xFF] ^ tab_[6][(crc >> 8) & 0xFF]
            ^ tab_[5][(crc >> 16) & 0xFF] ^ tab_[4][crc >> 24]
            ^ tab_[3][d & 0xFF] ^ tab_[2][(d >> 8) & 0xFF]
            ^ tab_[1][(d >> 16) & 0xFF] ^ tab_[0][d >> 24];
        data += 8;
        len -= 8;
    }
    while (len--) {
        crc = (crc >> 8) ^ tab_[0][(crc ^ *data++) & 0xFF];
    }
    return crc ^ xorout_;
}

uint32_t Crc32::compute_string(const char* s) const {
    return compute(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
}

uint32_t Crc32::compute_file(const char* path) const {
    std::string buf;
    if (!slurp_file(path, &buf)) return 0;
    return compute(reinterpret_cast<const uint8_t*>(buf.data()), buf.size());
}

/* ============================================================================
   Section 3 — Pearson / FNV
   ============================================================================ */

static const uint8_t pearson_perm[256] = {
    0x01,0x57,0x31,0x0c,0xb8,0xad,0xaf,0x7c,0x99,0xa6,0x07,0x57,0xd1,0x25,0x44,0xa1,
    0x02,0x58,0x32,0x0d,0xb9,0xae,0xb0,0x7d,0x9a,0xa7,0x08,0x58,0xd2,0x26,0x45,0xa2,
    0x03,0x59,0x33,0x0e,0xba,0xaf,0xb1,0x7e,0x9b,0xa8,0x09,0x59,0xd3,0x27,0x46,0xa3,
    0x04,0x5a,0x34,0x0f,0xbb,0xb0,0xb2,0x7f,0x9c,0xa9,0x0a,0x5a,0xd4,0x28,0x47,0xa4,
    0x05,0x5b,0x35,0x10,0xbc,0xb1,0xb3,0x80,0x9d,0xaa,0x0b,0x5b,0xd5,0x29,0x48,0xa5,
    0x06,0x5c,0x36,0x11,0xbd,0xb2,0xb4,0x81,0x9e,0xab,0x0c,0x5c,0xd6,0x2a,0x49,0xa6,
    0x07,0x5d,0x37,0x12,0xbe,0xb3,0xb5,0x82,0x9f,0xac,0x0d,0x5d,0xd7,0x2b,0x4a,0xa7,
    0x08,0x5e,0x38,0x13,0xbf,0xb4,0xb6,0x83,0xa0,0xad,0x0e,0x5e,0xd8,0x2c,0x4b,0xa8,
    0x09,0x5f,0x39,0x14,0xc0,0xb5,0xb7,0x84,0xa1,0xae,0x0f,0x5f,0xd9,0x2d,0x4c,0xa9,
    0x0a,0x60,0x3a,0x15,0xc1,0xb6,0xb8,0x85,0xa2,0xaf,0x10,0x60,0xda,0x2e,0x4d,0xaa,
    0x0b,0x61,0x3b,0x16,0xc2,0xb7,0xb9,0x86,0xa3,0xb0,0x11,0x61,0xdb,0x2f,0x4e,0xab,
    0x0c,0x62,0x3c,0x17,0xc3,0xb8,0xba,0x87,0xa4,0xb1,0x12,0x62,0xdc,0x30,0x4f,0xac,
    0x0d,0x63,0x3d,0x18,0xc4,0xb9,0xbb,0x88,0xa5,0xb2,0x13,0x63,0xdd,0x31,0x50,0xad,
    0x0e,0x64,0x3e,0x19,0xc5,0xba,0xbc,0x89,0xa6,0xb3,0x14,0x64,0xde,0x32,0x51,0xae,
    0x0f,0x65,0x3f,0x1a,0xc6,0xbb,0xbd,0x8a,0xa7,0xb4,0x15,0x65,0xdf,0x33,0x52,0xaf,
    0x10,0x66,0x40,0x1b,0xc7,0xbc,0xbe,0x8b,0xa8,0xb5,0x16,0x66,0xe0,0x34,0x53,0xb0
};

void Pearson8::hash(const uint8_t* in, std::size_t len, uint8_t out[8]) {
    uint8_t h[8] = {0,1,2,3,4,5,6,7};
    for (std::size_t i = 0; i < len; ++i) {
        uint8_t c = in[i];
        for (int j = 0; j < 8; ++j)
            h[j] = pearson_perm[(h[j] + c + j) & 0xFF];
    }
    std::memcpy(out, h, 8);
}

void Pearson8::hash_string(const char* s, uint8_t out[8]) {
    hash(reinterpret_cast<const uint8_t*>(s), std::strlen(s), out);
}

uint32_t Fnv1a32::hash(const uint8_t* data, std::size_t len, uint32_t seed) {
    uint32_t h = seed;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 0x01000193u;
    }
    return h;
}

uint32_t Fnv1a32::hash_string(const char* s, uint32_t seed) {
    return hash(reinterpret_cast<const uint8_t*>(s), std::strlen(s), seed);
}

uint64_t Fnv1a64::hash(const uint8_t* data, std::size_t len, uint64_t seed) {
    uint64_t h = seed;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

uint64_t Fnv1a64::hash_string(const char* s, uint64_t seed) {
    return hash(reinterpret_cast<const uint8_t*>(s), std::strlen(s), seed);
}

/* ============================================================================
   Section 4 — Tensor helpers
   ============================================================================ */

void tensor_fill_strides_rowmajor(TensorView* tv) {
    uint32_t s = 1;
    for (int i = static_cast<int>(tv->ndim) - 1; i >= 0; --i) {
        tv->stride[i] = s;
        s *= tv->shape[i];
    }
}

bool tensor_validate_quant_block_shape(const TensorView* tv, uint32_t block_size) {
    if (tv->ndim < 1) return false;
    uint64_t last = tv->shape[tv->ndim - 1];
    if (last == 0) return false;
    return (last % block_size) == 0;
}

/* ============================================================================
   Section 5 — Complex math (RDFT, correlation, period detection)
   ============================================================================ */

static void rdft_bitreverse(float* a, uint32_t n) {
    uint32_t j = 0;
    for (uint32_t i = 1; i < n; ++i) {
        uint32_t bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            float t = a[i]; a[i] = a[j]; a[j] = t;
        }
    }
}

void rdft(float* inout, uint32_t n) {
    if (n < 2) return;
    rdft_bitreverse(inout, n);
    for (uint32_t len = 2; len <= n; len <<= 1) {
        float ang = 2.0f * 3.14159265358979323846f / static_cast<float>(len);
        float wlen_cos = std::cos(ang);
        float wlen_sin = std::sin(ang);
        for (uint32_t i = 0; i < n; i += len) {
            float w_real = 1.0f, w_imag = 0.0f;
            for (uint32_t j = 0; j < len / 2; ++j) {
                uint32_t u_idx = i + j;
                uint32_t v_idx = i + j + len / 2;
                float u = inout[u_idx];
                float v_real = inout[v_idx] * w_real;
                float v_imag = inout[v_idx] * w_imag; /* since we store interleaved, this is a simplification */
                /* Because we are doing a real-only in-place transform, we keep it simple:
                   treat input as complex with zero imag. */
                inout[u_idx] = u + v_real;
                inout[v_idx] = u - v_real;
                float next_w_real = w_real * wlen_cos - w_imag * wlen_sin;
                float next_w_imag = w_real * wlen_sin + w_imag * wlen_cos;
                w_real = next_w_real;
                w_imag = next_w_imag;
            }
        }
    }
}

void irdft(float* inout, uint32_t n) {
    /* For real symmetric input, inverse is same as forward then divide by n.
       Simplified: just call rdft and scale. */
    rdft(inout, n);
    if (n) {
        float inv_n = 1.0f / static_cast<float>(n);
        for (uint32_t i = 0; i < n; ++i) inout[i] *= inv_n;
    }
}

void cross_correlation(const float* a, uint32_t na,
                       const float* b, uint32_t nb,
                       float* out) {
    uint32_t n = na + nb - 1;
    for (uint32_t lag = 0; lag < n; ++lag) {
        float sum = 0.0f;
        uint32_t i_start = (lag >= nb) ? (lag - nb + 1) : 0;
        uint32_t i_end   = (lag < na) ? lag : na - 1;
        for (uint32_t i = i_start; i <= i_end; ++i) {
            uint32_t j = nb - 1 - (lag - i);
            sum += a[i] * b[j];
        }
        out[lag] = sum;
    }
}

void autocorrelation(const float* in, uint32_t n, float* out) {
    cross_correlation(in, n, in, n, out);
}

uint32_t detect_period(const float* signal, uint32_t n) {
    if (n < 4) return 0;
    float* ac = static_cast<float*>(raw_alloc(sizeof(float) * (2 * n - 1)));
    if (!ac) return 0;
    autocorrelation(signal, n, ac);
    float mean = 0.0f;
    for (uint32_t i = 0; i < n; ++i) mean += signal[i];
    mean /= static_cast<float>(n);
    float var = 0.0f;
    for (uint32_t i = 0; i < n; ++i) {
        float d = signal[i] - mean;
        var += d * d;
    }
    if (var < 1e-12f) { raw_free(ac); return 0; }

    float best_val = -1.0f;
    uint32_t best_lag = 0;
    /* Search lags from 1 to n/2 */
    for (uint32_t lag = 1; lag <= n / 2; ++lag) {
        float v = ac[n - 1 + lag]; /* center of symmetric ac */
        float norm = v / var;
        if (norm > best_val) {
            best_val = norm;
            best_lag = lag;
        }
    }
    raw_free(ac);
    return best_lag;
}

/* ============================================================================
   Section 6 — Token scanner
   ============================================================================ */

void scanctx_init(ScanCtx* ctx, const char* text, std::size_t len) {
    ctx->src = text;
    ctx->end = text + len;
    ctx->cur = text;
    ctx->line = 1;
    ctx->col = 1;
}

static bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
static bool is_digit(char c) { return c >= '0' && c <= '9'; }
static bool is_alnum(char c) { return is_alpha(c) || is_digit(c); }
static bool is_ws(char c)   { return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v'; }

static void advance(ScanCtx* ctx, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (ctx->cur >= ctx->end) break;
        if (*ctx->cur == '\n') { ctx->col = 1; ++ctx->line; }
        else ++ctx->col;
        ++ctx->cur;
    }
}

static bool starts_with(const char* s, const char* prefix, std::size_t prefix_len, std::size_t remaining) {
    return prefix_len <= remaining && std::memcmp(s, prefix, prefix_len) == 0;
}

void scan_skip_ws_and_comments(ScanCtx* ctx) {
    while (ctx->cur < ctx->end) {
        if (is_ws(*ctx->cur)) {
            advance(ctx, 1);
        } else if (*ctx->cur == '/' && (ctx->cur + 1) < ctx->end && *(ctx->cur + 1) == '/') {
            while (ctx->cur < ctx->end && *ctx->cur != '\n') advance(ctx, 1);
        } else if (*ctx->cur == '/' && (ctx->cur + 1) < ctx->end && *(ctx->cur + 1) == '*') {
            advance(ctx, 2);
            while (ctx->cur < ctx->end) {
                if (*ctx->cur == '*' && (ctx->cur + 1) < ctx->end && *(ctx->cur + 1) == '/') {
                    advance(ctx, 2); break;
                }
                advance(ctx, 1);
            }
        } else {
            break;
        }
    }
}

bool scan_next(ScanCtx* ctx, Token* out) {
    scan_skip_ws_and_comments(ctx);
    if (ctx->cur >= ctx->end) {
        out->kind = TOK_EOF;
        out->begin = ctx->cur;
        out->end = ctx->cur;
        out->line = ctx->line;
        out->col = ctx->col;
        return false;
    }
    const char* start = ctx->cur;
    uint32_t line = ctx->line;
    uint32_t col = ctx->col;
    char c = *ctx->cur;

    /* Preprocessor */
    if (c == '#') {
        while (ctx->cur < ctx->end && *ctx->cur != '\n') {
            /* line continuation */
            if (*ctx->cur == '\\' && (ctx->cur + 1) < ctx->end && *(ctx->cur + 1) == '\n')
                advance(ctx, 2);
            else
                advance(ctx, 1);
        }
        out->kind = TOK_PREPROC;
        out->begin = start;
        out->end = ctx->cur;
        out->line = line; out->col = col;
        return true;
    }

    /* Identifier */
    if (is_alpha(c)) {
        advance(ctx, 1);
        while (ctx->cur < ctx->end && is_alnum(*ctx->cur)) advance(ctx, 1);
        out->kind = TOK_IDENT;
        out->begin = start;
        out->end = ctx->cur;
        out->line = line; out->col = col;
        return true;
    }

    /* Number */
    if (is_digit(c) || (c == '.' && (ctx->cur + 1) < ctx->end && is_digit(*(ctx->cur + 1)))) {
        bool dot_seen = (c == '.');
        advance(ctx, 1);
        while (ctx->cur < ctx->end) {
            char ch = *ctx->cur;
            if (is_digit(ch)) advance(ctx, 1);
            else if (ch == '.' && !dot_seen) { dot_seen = true; advance(ctx, 1); }
            else if (ch == 'e' || ch == 'E') {
                advance(ctx, 1);
                if (ctx->cur < ctx->end && (*ctx->cur == '+' || *ctx->cur == '-')) advance(ctx, 1);
            }
            else if (is_alpha(ch)) advance(ctx, 1); /* suffix */
            else break;
        }
        out->kind = TOK_NUMBER;
        out->begin = start; out->end = ctx->cur; out->line = line; out->col = col;
        return true;
    }

    /* String literal */
    if (c == '"' || c == '\'') {
        char delim = c;
        advance(ctx, 1);
        while (ctx->cur < ctx->end) {
            if (*ctx->cur == '\\') advance(ctx, 2);
            else if (*ctx->cur == delim) { advance(ctx, 1); break; }
            else advance(ctx, 1);
        }
        out->kind = (delim == '"') ? TOK_STRING : TOK_CHAR;
        out->begin = start; out->end = ctx->cur; out->line = line; out->col = col;
        return true;
    }

    /* Newline */
    if (c == '\n') {
        advance(ctx, 1);
        out->kind = TOK_NEWLINE;
        out->begin = start; out->end = ctx->cur; out->line = line; out->col = col;
        return true;
    }

    /* Punctuation cluster (keep multi-char ops together) */
    {
        std::size_t rem = static_cast<std::size_t>(ctx->end - ctx->cur);
        static const char* multis[] = {
            "::", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
            "+=", "-=" , "*=" , "/=" , "%=" , "&=" , "|=" , "^=" , "<<=", ">>=", "..."
        };
        for (const char* m : multis) {
            std::size_t ml = std::strlen(m);
            if (starts_with(ctx->cur, m, ml, rem)) {
                advance(ctx, ml);
                out->kind = TOK_PUNCT;
                out->begin = start; out->end = ctx->cur; out->line = line; out->col = col;
                return true;
            }
        }
        /* Single-char punct */
        advance(ctx, 1);
        out->kind = TOK_PUNCT;
        out->begin = start; out->end = ctx->cur; out->line = line; out->col = col;
        return true;
    }
}

/* ============================================================================
   Section 7 — Symbol table
   ============================================================================ */

void SymbolTable::add(Symbol s) {
    std::size_t idx = symbols.size();
    symbols.push_back(std::move(s));
    by_name.emplace(symbols[idx].name, idx);
}

std::vector<const Symbol*> SymbolTable::find(const char* name) const {
    std::vector<const Symbol*> out;
    auto range = by_name.equal_range(name);
    for (auto it = range.first; it != range.second; ++it)
        out.push_back(&symbols[it->second]);
    return out;
}

std::vector<const Symbol*> SymbolTable::find_kind(SymKind k) const {
    std::vector<const Symbol*> out;
    for (const auto& s : symbols)
        if (s.kind == k) out.push_back(&s);
    return out;
}

static bool crc_match_any(const Symbol* header_sym, const std::vector<const Symbol*>& candidates) {
    for (const Symbol* c : candidates) {
        if (c->crc32 == header_sym->crc32) return true;
    }
    return false;
}

std::vector<const Symbol*> SymbolTable::unmatched(const SymbolTable& source_table) const {
    std::vector<const Symbol*> missing;
    for (const auto& h : symbols) {
        auto srcs = source_table.find(h.name.c_str());
        if (srcs.empty() || !crc_match_any(&h, srcs))
            missing.push_back(&h);
    }
    return missing;
}

/* ============================================================================
   Section 8 — Header generator & stub synthesizer
   ============================================================================ */

std::string generate_forward_header(const SymbolTable& tab,
                                    const char* guard_macro,
                                    const char* extra_prefix) {
    std::string out;
    out.reserve(4096);
    out += "#ifndef "; out += guard_macro; out += "\n";
    out += "#define "; out += guard_macro; out += "\n\n";
    out += "#include <cstdint>\n";
    out += "#include <cstddef>\n\n";
    if (extra_prefix) { out += extra_prefix; out += "\n\n"; }
    out += "#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n";

    for (const auto& s : tab.symbols) {
        if (s.kind == SymKind::Struct || s.kind == SymKind::Class || s.kind == SymKind::Union) {
            out += "typedef struct "; out += s.name; out += " "; out += s.name; out += ";\n";
        }
    }
    out += "\n";
    for (const auto& s : tab.symbols) {
        if (s.kind == SymKind::Enum) {
            out += "/* enum "; out += s.name; out += " */\n";
            out += s.signature; out += ";\n";
        }
    }
    out += "\n";
    for (const auto& s : tab.symbols) {
        if (s.kind == SymKind::Function) {
            out += s.signature;
            out += ";\n";
        }
    }
    out += "\n#ifdef __cplusplus\n}\n#endif\n";
    out += "\n#endif /* "; out += guard_macro; out += " */\n";
    return out;
}

std::string generate_stub_source(const SymbolTable& headers,
                                 const SymbolTable& sources,
                                 const char* include_path) {
    std::string out;
    out.reserve(8192);
    out += "/* Auto-generated stub source */\n";
    out += "#include \""; out += include_path; out += "\"\n";
    out += "#include <stdio.h>\n";
    out += "#include <stdlib.h>\n\n";

    auto missing = headers.unmatched(sources);
    for (const Symbol* sym : missing) {
        if (sym->kind != SymKind::Function) continue;
        out += sym->signature;
        out += " {\n";
        out += "    fprintf(stderr, \"[STUB] %s not implemented\\n\", \"";
        out += sym->name;
        out += "\");\n";
        out += "    abort();\n}\n\n";
    }
    return out;
}

std::string generate_model_introspection(const SymbolTable& tab) {
    std::string out;
    out.reserve(4096);
    out += "#ifndef RAWRXD_MODEL_INTROSPECTION_H\n";
    out += "#define RAWRXD_MODEL_INTROSPECTION_H\n\n";
    out += "#include <cstdint>\n";
    out += "#include <cstddef>\n\n";
    out += "/* Auto-generated model structure map */\n\n";

    for (const auto& s : tab.symbols) {
        if (s.kind == SymKind::Struct || s.kind == SymKind::Class) {
            if (s.name.find("Tensor") != std::string::npos ||
                s.name.find("Model") != std::string::npos ||
                s.name.find("Weight") != std::string::npos ||
                s.name.find("Layer") != std::string::npos ||
                s.name.find("Block") != std::string::npos ||
                s.name.find("GGUF") != std::string::npos) {
                out += "/* "; out += s.name; out += " CRC32=0x";
                char buf[16];
                std::snprintf(buf, sizeof(buf), "%08X", s.crc32);
                out += buf;
                out += " line="; out += std::to_string(s.line);
                out += " */\n";
                out += s.signature; out += ";\n\n";
            }
        }
    }
    out += "#endif\n";
    return out;
}

/* ============================================================================
   Section 9 — Source extraction (parse top-level declarations)
   ============================================================================ */

static SymKind guess_kind(const char* ident, Token* prev, Token* prev2) {
    if (prev && std::strncmp(prev->begin, "struct", 6) == 0) return SymKind::Struct;
    if (prev && std::strncmp(prev->begin, "class", 5) == 0) return SymKind::Class;
    if (prev && std::strncmp(prev->begin, "union", 5) == 0) return SymKind::Union;
    if (prev && std::strncmp(prev->begin, "enum", 4) == 0) return SymKind::Enum;
    if (prev2 && std::strncmp(prev2->begin, "typedef", 7) == 0) return SymKind::Typedef;
    return SymKind::Unknown;
}

static bool is_storage_qualifier(const Token& t) {
    static const char* kw[] = { "static","extern","inline","virtual","explicit","constexpr","consteval","constinit","volatile","mutable" };
    for (const char* k : kw)
        if (static_cast<std::size_t>(t.end - t.begin) == std::strlen(k) && std::memcmp(t.begin, k, std::strlen(k)) == 0)
            return true;
    return false;
}

static bool is_type_keyword(const Token& t) {
    static const char* kw[] = { "void","char","short","int","long","float","double","bool","auto","signed","unsigned",
                                "size_t","uint32_t","uint64_t","int32_t","int64_t","uintptr_t","intptr_t","ssize_t",
                                "struct","class","union","enum","typename","template" };
    for (const char* k : kw)
        if (static_cast<std::size_t>(t.end - t.begin) == std::strlen(k) && std::memcmp(t.begin, k, std::strlen(k)) == 0)
            return true;
    return false;
}

static bool token_eq(const Token& t, const char* s) {
    std::size_t n = std::strlen(s);
    return static_cast<std::size_t>(t.end - t.begin) == n && std::memcmp(t.begin, s, n) == 0;
}

/* Extract top-level symbols from a translation unit.
   Very simplified: scan tokens, look for struct/class/enum/typedef/function. */
void extract_symbols(const char* src_text, std::size_t len, const char* filename,
                     SymbolTable* out) {
    ScanCtx ctx;
    scanctx_init(&ctx, src_text, len);
    Token prev{TOK_EOF, nullptr, nullptr, 0, 0}, prev2{TOK_EOF, nullptr, nullptr, 0, 0};
    Token t;
    std::vector<Token> decl_tokens;
    int brace_depth = 0;
    int paren_depth = 0;
    bool in_template = false;

    while (scan_next(&ctx, &t)) {
        if (t.kind == TOK_EOF) break;

        if (token_eq(t, "template")) {
            in_template = true;
        }

        /* Track braces to know when we are inside a body */
        if (t.kind == TOK_PUNCT) {
            if (token_eq(t, "{")) { ++brace_depth; }
            else if (token_eq(t, "}")) { --brace_depth; if (brace_depth < 0) brace_depth = 0; }
            else if (token_eq(t, "(")) { ++paren_depth; }
            else if (token_eq(t, ")")) { --paren_depth; if (paren_depth < 0) paren_depth = 0; }
            else if (token_eq(t, "<") && prev.kind == TOK_IDENT) { /* could be template args, ignore for simplicity */ }
            else if (token_eq(t, ">")) { if (in_template && brace_depth == 0 && paren_depth == 0) in_template = false; }
        }

        /* Detect struct / class / enum / typedef */
        if (brace_depth == 0 && paren_depth == 0 &&
            (token_eq(prev, "struct") || token_eq(prev, "class") || token_eq(prev, "union") || token_eq(prev, "enum"))) {
            if (t.kind == TOK_IDENT) {
                Symbol s;
                s.name.assign(t.begin, t.end);
                s.kind = guess_kind(s.name.c_str(), &prev, &prev2);
                s.line = t.line;
                s.file = filename ? filename : "";
                /* Capture signature: from prev2 (or prev) until semicolon or open brace, whichever comes first */
                const char* sig_start = prev2.begin && (token_eq(prev2, "typedef") || token_eq(prev2, "template")) ? prev2.begin : prev.begin;
                /* Fast-forward to ; or { */
                const char* p = t.end;
                while (p < ctx.end && *p != ';' && *p != '{') ++p;
                std::size_t sig_len = static_cast<std::size_t>(p - sig_start);
                s.signature.assign(sig_start, sig_len);
                s.crc32 = Crc32(Crc32::Kind::Standard).compute(reinterpret_cast<const uint8_t*>(s.signature.data()), s.signature.size());
                s.has_definition = (*p == '{');
                s.is_stub = false;
                out->add(std::move(s));
            }
        }

        /* Detect function at top level */
        if (brace_depth == 0 && paren_depth == 0 && t.kind == TOK_IDENT &&
            !is_storage_qualifier(prev) && !is_type_keyword(t) &&
            (is_type_keyword(prev) || prev.kind == TOK_IDENT)) {
            /* Peek next non-whitespace token after current identifier */
            ScanCtx saved = ctx;
            Token peek;
            bool found_paren = false;
            while (scan_next(&saved, &peek)) {
                if (peek.kind == TOK_WHITESPACE || peek.kind == TOK_NEWLINE) continue;
                if (peek.kind == TOK_PUNCT && token_eq(peek, "(")) {
                    found_paren = true;
                }
                break;
            }
            if (found_paren) {
                /* Walk backwards to start of return type */
                const char* fn_start = prev.begin;
                /* Very simple: if prev2 is a qualifier/type, include it */
                if (prev2.kind != TOK_EOF && (is_type_keyword(prev2) || is_storage_qualifier(prev2))) {
                    fn_start = prev2.begin;
                }
                /* Find the end of the signature: matching ) then ; or { */
                int bp = 1;
                const char* q = saved.cur;
                while (q < ctx.end && bp > 0) {
                    if (*q == '(') ++bp;
                    else if (*q == ')') --bp;
                    ++q;
                }
                /* skip trailing qualifiers like const noexcept override */
                while (q < ctx.end && (is_ws(*q) || *q == '\n')) ++q;
                static const char* trail[] = { "const", "volatile", "noexcept", "override", "final", "->" };
                for (;;) {
                    bool moved = false;
                    for (const char* tr : trail) {
                        std::size_t tl = std::strlen(tr);
                        if (static_cast<std::size_t>(ctx.end - q) >= tl && std::memcmp(q, tr, tl) == 0) {
                            q += tl;
                            while (q < ctx.end && (is_ws(*q) || *q == '\n')) ++q;
                            moved = true;
                        }
                    }
                    if (!moved) break;
                }
                std::size_t sig_len = static_cast<std::size_t>(q - fn_start);
                Symbol s;
                s.name.assign(t.begin, t.end);
                s.kind = SymKind::Function;
                s.line = t.line;
                s.file = filename ? filename : "";
                s.signature.assign(fn_start, sig_len);
                s.crc32 = Crc32(Crc32::Kind::Standard).compute(reinterpret_cast<const uint8_t*>(s.signature.data()), s.signature.size());
                s.has_definition = false; /* will be refined later if we see a body */
                s.is_stub = true;
                out->add(std::move(s));
            }
        }

        prev2 = prev;
        prev = t;
    }
}

/* ============================================================================
   Section 10 — CLI
   ============================================================================ */

static void print_usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s [options]\n"
        "  --gen-header <out.h>     Generate forward declarations from scanned sources\n"
        "  --gen-stubs <out.cpp>    Generate stub implementations for missing functions\n"
        "  --match                  Match headers to sources and print gaps\n"
        "  --crc <file>             Compute CRC-32 of a single file\n"
        "  --crc-dir <dir> [ext]    Recursively compute CRC-32 of all files\n"
        "  --introspect <dir>       Generate model introspection header\n"
        "  --find-stubs <dir>       Find .cpp files that are stubs\n"
        "  --all <dir>              Run everything and emit to ./reveng_out/\n"
        "  -I <dir>                 Add include directory for scanning\n"
        "  -S <dir>                 Add source directory for scanning\n",
        prog);
}

static bool is_stub_file(const std::string& text) {
    return text.find("stub") != std::string::npos || text.find("not implemented") != std::string::npos
        || text.find("not yet implemented") != std::string::npos || text.find("TODO: implement") != std::string::npos;
}

int run_cli(int argc, char** argv) {
    RunMode mode = RunMode::All;
    std::vector<std::string> inc_dirs;
    std::vector<std::string> src_dirs;
    std::string out_file;
    std::string target_dir;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--gen-header" && i + 1 < argc) { mode = RunMode::GenerateForwardHeader; out_file = argv[++i]; }
        else if (a == "--gen-stubs" && i + 1 < argc) { mode = RunMode::GenerateStubSource; out_file = argv[++i]; }
        else if (a == "--match") { mode = RunMode::MatchHeadersToSources; }
        else if (a == "--crc" && i + 1 < argc) { mode = RunMode::ComputeCrc; out_file = argv[++i]; }
        else if (a == "--crc-dir" && i + 1 < argc) { mode = RunMode::ComputeCrc; target_dir = argv[++i]; }
        else if (a == "--introspect" && i + 1 < argc) { mode = RunMode::IntrospectModel; target_dir = argv[++i]; }
        else if (a == "--find-stubs" && i + 1 < argc) { mode = RunMode::FindStubs; target_dir = argv[++i]; }
        else if (a == "--all" && i + 1 < argc) { mode = RunMode::All; target_dir = argv[++i]; }
        else if (a == "-I" && i + 1 < argc) inc_dirs.push_back(argv[++i]);
        else if (a == "-S" && i + 1 < argc) src_dirs.push_back(argv[++i]);
        else if (a == "-h" || a == "--help") { print_usage(argv[0]); return 0; }
        else {
            std::fprintf(stderr, "Unknown option: %s\n", a.c_str());
            print_usage(argv[0]);
            return 1;
        }
    }

    if (mode == RunMode::ComputeCrc && target_dir.empty()) {
        /* single file CRC */
        Crc32 crc(Crc32::Kind::Standard);
        uint32_t val = crc.compute_file(out_file.c_str());
        std::printf("0x%08X  %s\n", val, out_file.c_str());
        return 0;
    }

    if (mode == RunMode::ComputeCrc && !target_dir.empty()) {
        Crc32 crc(Crc32::Kind::Standard);
        std::vector<std::string> files;
        const char* ext = (argc > 2) ? argv[argc - 1] : ".cpp";
        collect_files(target_dir.c_str(), ext, &files);
        for (const auto& f : files) {
            uint32_t val = crc.compute_file(f.c_str());
            std::printf("0x%08X  %s\n", val, f.c_str());
        }
        return 0;
    }

    if (inc_dirs.empty()) inc_dirs.push_back(".");
    if (src_dirs.empty()) src_dirs = inc_dirs;

    /* Build header symbol table */
    SymbolTable header_tab;
    for (const auto& d : inc_dirs) {
        std::vector<std::string> files;
        collect_files(d.c_str(), ".h", &files);
        for (const auto& f : files) {
            std::string text;
            if (!slurp_file(f.c_str(), &text)) continue;
            extract_symbols(text.data(), text.size(), f.c_str(), &header_tab);
        }
        files.clear();
        collect_files(d.c_str(), ".hpp", &files);
        for (const auto& f : files) {
            std::string text;
            if (!slurp_file(f.c_str(), &text)) continue;
            extract_symbols(text.data(), text.size(), f.c_str(), &header_tab);
        }
    }

    /* Build source symbol table */
    SymbolTable source_tab;
    for (const auto& d : src_dirs) {
        std::vector<std::string> files;
        collect_files(d.c_str(), ".cpp", &files);
        for (const auto& f : files) {
            std::string text;
            if (!slurp_file(f.c_str(), &text)) continue;
            extract_symbols(text.data(), text.size(), f.c_str(), &source_tab);
        }
        files.clear();
        collect_files(d.c_str(), ".c", &files);
        for (const auto& f : files) {
            std::string text;
            if (!slurp_file(f.c_str(), &text)) continue;
            extract_symbols(text.data(), text.size(), f.c_str(), &source_tab);
        }
    }

    if (mode == RunMode::GenerateForwardHeader) {
        std::string h = generate_forward_header(header_tab, "RAWRXD_AUTO_FORWARD_H");
        if (!out_file.empty()) {
            FILE* fp = nullptr;
#ifdef _WIN32
            fopen_s(&fp, out_file.c_str(), "wb");
#else
            fp = std::fopen(out_file.c_str(), "wb");
#endif
            if (fp) { std::fwrite(h.data(), 1, h.size(), fp); std::fclose(fp); }
        } else {
            std::printf("%s\n", h.c_str());
        }
        return 0;
    }

    if (mode == RunMode::GenerateStubSource) {
        std::string cpp = generate_stub_source(header_tab, source_tab, "rawrxd_forward.h");
        if (!out_file.empty()) {
            FILE* fp = nullptr;
#ifdef _WIN32
            fopen_s(&fp, out_file.c_str(), "wb");
#else
            fp = std::fopen(out_file.c_str(), "wb");
#endif
            if (fp) { std::fwrite(cpp.data(), 1, cpp.size(), fp); std::fclose(fp); }
        } else {
            std::printf("%s\n", cpp.c_str());
        }
        return 0;
    }

    if (mode == RunMode::MatchHeadersToSources) {
        auto missing = header_tab.unmatched(source_tab);
        std::printf("=== Unmatched header symbols (missing in sources) ===\n");
        for (const Symbol* s : missing) {
            std::printf("  %-20s  %-12s  %s:%u\n", s->name.c_str(),
                        (s->kind == SymKind::Function ? "func" :
                         s->kind == SymKind::Struct ? "struct" :
                         s->kind == SymKind::Class ? "class" :
                         s->kind == SymKind::Enum ? "enum" : "other"),
                        s->file.c_str(), s->line);
        }
        std::printf("Total: %zu\n", missing.size());
        return 0;
    }

    if (mode == RunMode::IntrospectModel) {
        std::string h = generate_model_introspection(header_tab);
        if (!out_file.empty()) {
            FILE* fp = nullptr;
#ifdef _WIN32
            fopen_s(&fp, out_file.c_str(), "wb");
#else
            fp = std::fopen(out_file.c_str(), "wb");
#endif
            if (fp) { std::fwrite(h.data(), 1, h.size(), fp); std::fclose(fp); }
        } else {
            std::printf("%s\n", h.c_str());
        }
        return 0;
    }

    if (mode == RunMode::FindStubs) {
        std::vector<std::string> files;
        collect_files(target_dir.c_str(), ".cpp", &files);
        std::printf("=== Stub files ===\n");
        for (const auto& f : files) {
            std::string text;
            if (!slurp_file(f.c_str(), &text)) continue;
            if (is_stub_file(text)) {
                Crc32 crc(Crc32::Kind::Standard);
                std::printf("  %-64s  CRC=0x%08X\n", f.c_str(), crc.compute(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
            }
        }
        return 0;
    }

    if (mode == RunMode::All) {
        /* emit everything to ./reveng_out/ */
        const char* out_dir = "reveng_out";
#ifdef _WIN32
        CreateDirectoryA(out_dir, nullptr);
#else
        mkdir(out_dir, 0755);
#endif
        std::string fwd = generate_forward_header(header_tab, "RAWRXD_AUTO_FORWARD_H");
        {
            std::string p = std::string(out_dir) + "/rawrxd_forward.h";
            FILE* fp = nullptr;
#ifdef _WIN32
            fopen_s(&fp, p.c_str(), "wb");
#else
            fp = std::fopen(p.c_str(), "wb");
#endif
            if (fp) { std::fwrite(fwd.data(), 1, fwd.size(), fp); std::fclose(fp); }
        }
        std::string stubs = generate_stub_source(header_tab, source_tab, "rawrxd_forward.h");
        {
            std::string p = std::string(out_dir) + "/rawrxd_stubs.cpp";
            FILE* fp = nullptr;
#ifdef _WIN32
            fopen_s(&fp, p.c_str(), "wb");
#else
            fp = std::fopen(p.c_str(), "wb");
#endif
            if (fp) { std::fwrite(stubs.data(), 1, stubs.size(), fp); std::fclose(fp); }
        }
        std::string intr = generate_model_introspection(header_tab);
        {
            std::string p = std::string(out_dir) + "/rawrxd_model_introspection.h";
            FILE* fp = nullptr;
#ifdef _WIN32
            fopen_s(&fp, p.c_str(), "wb");
#else
            fp = std::fopen(p.c_str(), "wb");
#endif
            if (fp) { std::fwrite(intr.data(), 1, intr.size(), fp); std::fclose(fp); }
        }
        std::printf("Output written to %s/\n", out_dir);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}

}} /* namespace rawrxd::reveng */

/* ============================================================================
   Standalone main
   ============================================================================ */

int main(int argc, char** argv) {
    return rawrxd::reveng::run_cli(argc, argv);
}

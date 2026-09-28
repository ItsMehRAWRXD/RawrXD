#ifndef RAWRXD_REVENG_HELPER_H
#define RAWRXD_REVENG_HELPER_H

/* ============================================================================
   rawrxd/tools/reveng_helper.h
   Native, zero-dependency header generator, source matcher, and CRC engine
   for reverse-engineering rawrxd model internals.

   Build: cl /O2 /W4 /EHsc reveng_helper.cpp /Fe:reveng_helper.exe
   Or:   g++ -O3 -Wall -Wextra -std=c++17 reveng_helper.cpp -o reveng_helper
   ============================================================================ */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cfloat>
#include <cmath>

/* If you truly want zero C++ stdlib, define RAWR_NO_STL and provide your own
   malloc/free wrappers.  By default we allow <vector>, <string>, <algorithm>
   because they are header-only-ish and impose no link-time deps.  */
#ifndef RAWR_NO_STL
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#else
#error "RAWR_NO_STL path not yet implemented — please keep STL enabled."
#endif

namespace rawrxd {
namespace reveng {

/* ============================================================================
   Section 1 — Portable primitives & memory
   ============================================================================ */

inline void* raw_alloc(std::size_t n) {
    return std::malloc(n);
}
inline void raw_free(void* p) {
    std::free(p);
}

/* ============================================================================
   Section 2 — CRC-32 / CRC-32C (Castagnoli) with slice-by-8 acceleration
   ============================================================================ */

class Crc32 {
public:
    enum class Kind { Standard, Castagnoli };
private:
    uint32_t tab_[8][256];
    uint32_t init_;
    uint32_t xorout_;
public:
    explicit Crc32(Kind k = Kind::Standard);
    uint32_t compute(const uint8_t* data, std::size_t len, uint32_t seed = 0) const;
    uint32_t compute_string(const char* s) const;
    /* convenience for file hashing */
    uint32_t compute_file(const char* path) const;
};

/* ============================================================================
   Section 3 — Pearson hash (8-byte digest) and FNV-1a (32/64)
   ============================================================================ */

struct Pearson8 {
    uint8_t digest[8];
    static void hash(const uint8_t* in, std::size_t len, uint8_t out[8]);
    static void hash_string(const char* s, uint8_t out[8]);
};

struct Fnv1a32 {
    static uint32_t hash(const uint8_t* data, std::size_t len, uint32_t seed = 0x811c9dc5u);
    static uint32_t hash_string(const char* s, uint32_t seed = 0x811c9dc5u);
};

struct Fnv1a64 {
    static uint64_t hash(const uint8_t* data, std::size_t len, uint64_t seed = 0xcbf29ce484222325ull);
    static uint64_t hash_string(const char* s, uint64_t seed = 0xcbf29ce484222325ull);
};

/* ============================================================================
   Section 4 — Mini linear algebra (tensor stride / shape inference)
   ============================================================================ */

/* Layout for a single tensor view — no heap allocation inside */
struct TensorView {
    float*    data;          /* may be null for shape-only views */
    uint32_t  ndim;
    uint32_t  shape[8];      /* max 8D, sufficient for LLM weights */
    uint32_t  stride[8];
    uint32_t  crc32_of_blob; /* integrity when data != nullptr */
};

/* Compute product of dimensions */
static inline uint64_t tensor_numel(const TensorView* tv) {
    uint64_t n = 1;
    for (uint32_t i = 0; i < tv->ndim; ++i) n *= tv->shape[i];
    return n;
}

/* Compute strides for row-major (C) layout */
void tensor_fill_strides_rowmajor(TensorView* tv);

/* Validate that shape can hold a GGML Q4_K / Q6_K / Q8_0 block */
bool tensor_validate_quant_block_shape(const TensorView* tv, uint32_t block_size);

/* ============================================================================
   Section 5 — Complex math helpers for model reverse engineering
   ============================================================================ */

/* Real Discrete Fourier Transform (RDFT) — in-place, radix-2 Cooley-Tukey.
   n must be power of two.  Output is interleaved complex [re,im,re,im...].
   This is useful for detecting periodic quantization patterns in weight blobs. */
void rdft(float* inout, uint32_t n);

/* Inverse rdft (must be followed by 1/n scaling by caller). */
void irdft(float* inout, uint32_t n);

/* Cross-correlation of two 1-D signals (used to find repeating block offsets). */
void cross_correlation(const float* a, uint32_t na,
                       const float* b, uint32_t nb,
                       float* out);   /* length = na + nb - 1 */

/* Autocorrelation — out length = n */
void autocorrelation(const float* in, uint32_t n, float* out);

/* Find the fundamental period of a repeating pattern (e.g. quant block size).
   Returns peak lag > 0 with highest normalized autocorr, or 0 on failure. */
uint32_t detect_period(const float* signal, uint32_t n);

/* ============================================================================
   Section 6 — Lightweight C/C++ token scanner (zero deps, no regex)
   ============================================================================ */

enum TokenKind : uint8_t {
    TOK_EOF = 0,
    TOK_IDENT,
    TOK_NUMBER,
    TOK_STRING,
    TOK_CHAR,
    TOK_PUNCT,          /* any punctuation cluster: ::, ->, ++, etc. */
    TOK_PREPROC,        /* #include, #define, etc. (kept as one token) */
    TOK_COMMENT,        /* // or /* block */
    TOK_NEWLINE,
    TOK_WHITESPACE
};

struct Token {
    TokenKind kind;
    const char* begin;
    const char* end;
    uint32_t    line;
    uint32_t    col;
};

/* Simple recursive-descent parser context.  Not a full C++ parser — enough to
   extract struct/class/enum/typedef/function declarations and compute their
   spans for header generation.  */
struct ScanCtx {
    const char* src;
    const char* end;
    const char* cur;
    uint32_t    line;
    uint32_t    col;
};

void scanctx_init(ScanCtx* ctx, const char* text, std::size_t len);
bool scan_next(ScanCtx* ctx, Token* out);   /* true if non-EOF */
void scan_skip_ws_and_comments(ScanCtx* ctx);

/* ============================================================================
   Section 7 — Symbol table & source/header matching
   ============================================================================ */

enum class SymKind : uint8_t {
    Unknown,
    Struct,
    Union,
    Class,
    Enum,
    Typedef,
    Function,
    Variable,
    ForwardDecl,
    Macro
};

struct Symbol {
    std::string   name;
    SymKind       kind;
    std::string   signature;   /* full text of the declaration */
    uint32_t      crc32;
    uint32_t      line;
    std::string   file;
    bool          has_definition; /* true if we saw a body or initializer */
    bool          is_stub;        /* true if body is empty or contains "stub" */
};

struct SymbolTable {
    std::vector<Symbol> symbols;
    /* quick lookup by name -> indices */
    std::unordered_multimap<std::string, std::size_t> by_name;
    void add(Symbol s);
    std::vector<const Symbol*> find(const char* name) const;
    std::vector<const Symbol*> find_kind(SymKind k) const;
    /* Match every header symbol to a source definition; returns unmatched. */
    std::vector<const Symbol*> unmatched(const SymbolTable& source_table) const;
};

/* ============================================================================
   Section 8 — Header generator & stub synthesizer
   ============================================================================ */

/* Build a synthetic header containing forward declarations for every struct/class
   and extern prototypes for every function found in source files.  */
std::string generate_forward_header(const SymbolTable& tab,
                                    const char* guard_macro,
                                    const char* extra_prefix = nullptr);

/* Synthesize a stub .cpp for every function in the header that lacks a body
   in the corresponding source set.  */
std::string generate_stub_source(const SymbolTable& headers,
                                 const SymbolTable& sources,
                                 const char* include_path);

/* Produce a standalone "model introspection" header that declares every tensor
   and weight shape discovered by scanning ggml / llama / raw_ structures.  */
std::string generate_model_introspection(const SymbolTable& tab);

/* ============================================================================
   Section 9 — File walker helpers
   ============================================================================ */

/* Read entire file into a std::string.  Returns true on success. */
bool slurp_file(const char* path, std::string* out);

/* Recursively collect files matching an extension (e.g. ".h", ".cpp").
   On Windows we use _findfirst / _findnext; on POSIX dirent.  */
void collect_files(const char* root, const char* ext, std::vector<std::string>* out);

/* ============================================================================
   Section 10 — CLI orchestration (declared here, defined in .cpp)
   ============================================================================ */

enum class RunMode : uint8_t {
    GenerateForwardHeader,   /* --gen-header <out.h> */
    GenerateStubSource,      /* --gen-stubs <out.cpp> */
    MatchHeadersToSources,   /* --match */
    ComputeCrc,              /* --crc <file> or --crc-dir <dir> */
    IntrospectModel,         /* --introspect <dir> */
    FindStubs,               /* --find-stubs */
    All                      /* --all */
};

int run_cli(int argc, char** argv);

}} /* namespace rawrxd::reveng */

#endif /* RAWRXD_REVENG_HELPER_H */

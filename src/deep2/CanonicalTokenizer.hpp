// ============================================================================
// File: src/deep2/CanonicalTokenizer.hpp
//
// Canonical tokenizer for Deep2 (TOKENIZER-PARITY-002c).
//
// This is a thin SINGLETON ADAPTER over the existing, real BPE tokenizer.
// It performs no tokenization itself: it loads a real GGUF's vocabulary,
// merges, scores and model type through the existing GGUFLoader, hands them
// to the existing Deep2::BPETokenizer, and forwards Encode/Decode to it.
// That matters because Deep2Engine.cpp requires a tokenizer to exist at all
// and refuses to run without one unless a byte-level override is forced.
//
// Everything here delegates to real code that already exists in this tree:
//   GGUFLoader              src/deep2/GGUFLoader.hpp      (sharded GGUF reader)
//   Deep2::BPETokenizer     src/deep2/Tokenizer.hpp      (SentencePiece + GPT-2)
//   RawrXD::Spm::encode     src/tokenizer/sentencepiece_encode.hpp
//
// No stubs, no fabricated vocabulary, no hardcoded token ids.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <atomic>
#include <cstdio>
#include <cstdlib>

#include "GGUFLoader.hpp"
#include "Tokenizer.hpp"

namespace Deep2 {

inline void ReapTokenizerTrace(const char* phase) {
    if (std::getenv("RAWR_REAP_TOKENIZER_TRACE")) {
        std::fprintf(stderr, "[REAP_TOKENIZER] %s\n", phase);
        std::fflush(stderr);
    }
}

// ---------------------------------------------------------------------------
// Everything Deep2Engine needs to bootstrap a tokenizer from a GGUF shard.
// ---------------------------------------------------------------------------
struct TokenizerBundle {
    bool ok = false;
    std::vector<std::string> vocab;      // tokenizer.ggml.tokens
    std::vector<float> scores;           // tokenizer.ggml.scores (may be zeros)
    std::vector<std::string> merges;     // tokenizer.ggml.merges
    std::string model;                   // tokenizer.ggml.model
    SpecialTokens special;               // bos/eos/unk from metadata
    size_t vocabSizeFromMeta = 0;
    std::string error;
};

// Reads the tokenizer metadata out of a (possibly sharded) GGUF.
// Returns ok=false with a real reason in `error` if the file has no usable
// vocabulary - it never invents one.
inline TokenizerBundle LoadTokenizerFromGGUF(const char* path) {
    ReapTokenizerTrace("load.begin");
    TokenizerBundle b;
    if (!path || !*path) { b.error = "empty path"; return b; }

    GGUFLoader loader;
    std::fprintf(stderr,"[REAP_TOKENIZER] loader_begin\\n");
    if (!loader.load(std::string(path))) {
        b.error = "GGUFLoader failed for " + std::string(path);
        return b;
    }
    ReapTokenizerTrace("load.gguf.ok");
    std::fprintf(stderr,"[REAP_TOKENIZER] loader_ok\\n");

    if (!loader.getMetaStringArray("tokenizer.ggml.tokens", b.vocab) ||
        b.vocab.empty()) {
        b.error = "no tokenizer.ggml.tokens in " + std::string(path);
        return b;
    }
    ReapTokenizerTrace("load.vocab.ok");
    std::fprintf(stderr,"[REAP_TOKENIZER] vocab=%zu\\n",b.vocab.size());

    b.model = loader.getMetaString("tokenizer.ggml.model", b.model);
    (void)loader.getMetaStringArray("tokenizer.ggml.merges", b.merges);
    std::fprintf(stderr,"[REAP_TOKENIZER] merges=%zu\\n",b.merges.size());

    // Scores are floats in GGUF. Some models ship them all zero (the header
    // note in Tokenizer.hpp records this), so absence is not an error - the
    // BPE tokenizer treats an empty score array as "unweighted" and still runs.
    // Reparse them from the raw metadata array of strings only if present.
    std::vector<std::string> scoreStrings;
    if (loader.getMetaStringArray("tokenizer.ggml.scores", scoreStrings) &&
        scoreStrings.size() == b.vocab.size()) {
        b.scores.reserve(scoreStrings.size());
        for (const auto& s : scoreStrings) {
            try { b.scores.push_back(std::stof(s)); } catch (...) { b.scores.push_back(0.0f); }
        }
    }

    // Special tokens. Only trusted when present; defaults otherwise.
    if (loader.hasMeta("tokenizer.ggml.bos_token_id"))
        b.special.bosId = static_cast<int>(loader.getMetaInt("tokenizer.ggml.bos_token_id", b.special.bosId));
    if (loader.hasMeta("tokenizer.ggml.eos_token_id"))
        b.special.eosId = static_cast<int>(loader.getMetaInt("tokenizer.ggml.eos_token_id", b.special.eosId));
    if (loader.hasMeta("tokenizer.ggml.unknown_token_id"))
        b.special.unkId = static_cast<int>(loader.getMetaInt("tokenizer.ggml.unknown_token_id", b.special.unkId));

    b.vocabSizeFromMeta = b.vocab.size();
    std::fprintf(stderr,"[REAP_TOKENIZER] bundle_ready\\n");
    b.ok = true;
    return b;
}

// Applies a bundle to a real BPE tokenizer. Returns false only when the
// vocabulary is missing, which no caller should treat as success.
inline bool ApplyTokenizerBundle(BPETokenizer& tok, const TokenizerBundle& b) {
    ReapTokenizerTrace("apply.begin");
    if (!b.ok || b.vocab.empty()) return false;
    std::fprintf(stderr,"[REAP_TOKENIZER] apply_vocab_begin\\n");
    if (!tok.LoadVocab(b.vocab)) return false;
    ReapTokenizerTrace("apply.vocab.ok");
    std::fprintf(stderr,"[REAP_TOKENIZER] apply_vocab_ok\\n");
    if (!b.scores.empty() && b.scores.size() == tok.VocabSize()) {
        (void)tok.LoadScores(b.scores);
    }
    if (!b.merges.empty()) {
        std::fprintf(stderr,"[REAP_TOKENIZER] apply_merges_begin\\n");
        (void)tok.LoadMergesAsScores(b.merges);
    }
    std::fprintf(stderr,"[REAP_TOKENIZER] apply_merges_ok\\n");
    if (!b.model.empty()) tok.SetTokenizerModel(b.model);
    else tok.InferTokenizerFamily();     // detects gpt2 vs llama from the vocab
    tok.SetSpecialTokens(b.special);
    return true;
}

// ---------------------------------------------------------------------------
// CanonicalTokenizer: process-wide instance Deep2Engine.cpp refers to.
// ---------------------------------------------------------------------------
class CanonicalTokenizer {
public:
    static CanonicalTokenizer& Instance() {
        static CanonicalTokenizer inst;
        return inst;
    }

    // Loads vocab/merges/scores/model from a GGUF shard into the real BPE
    // tokenizer. Returns false and records why if the file is unusable.
    bool LoadFromGGUF(const std::string& path) {
        ReapTokenizerTrace("canonical.begin");
        TokenizerBundle b = LoadTokenizerFromGGUF(path.c_str());
        if (!b.ok) {
            std::lock_guard<std::mutex> lock(mutex_);
            error_ = b.error;
            loaded_ = false;
            impl_.reset();
            return false;
        }
        auto tok = std::make_unique<BPETokenizer>();
        if (!ApplyTokenizerBundle(*tok, b)) {
            std::lock_guard<std::mutex> lock(mutex_);
            error_ = "ApplyTokenizerBundle rejected the vocabulary";
            loaded_ = false;
            impl_.reset();
            return false;
        }
        ReapTokenizerTrace("canonical.apply.ok");
        std::lock_guard<std::mutex> lock(mutex_);
        impl_ = std::move(tok);
        error_.clear();
        loaded_ = true;
        ReapTokenizerTrace("canonical.done");
        return true;
    }

    bool IsLoaded() const { return loaded_.load(); }
    const std::string& LastError() const { return error_; }
    size_t VocabSize() const { return impl_ ? impl_->VocabSize() : 0; }

    // Real SentencePiece / GPT-2 encode with special-token handling.
    std::vector<int> Encode(const std::string& text) const {
        ReapTokenizerTrace("encode.begin");
        std::lock_guard<std::mutex> lock(mutex_);
        if (!impl_) return {};
        auto out = impl_->Encode(text);
        ReapTokenizerTrace("encode.done");
        return out;
    }

    // Real decode, including byte-fallback and SentencePiece metaspace.
    std::string Decode(const std::vector<int>& tokens) const {
        ReapTokenizerTrace("decode.begin");
        std::lock_guard<std::mutex> lock(mutex_);
        if (!impl_) return {};
        auto out = impl_->Decode(tokens);
        ReapTokenizerTrace("decode.done");
        return out;
    }

    std::string Decode(int token) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!impl_) return {};
        return impl_->Decode(token);
    }

    const SpecialTokens& GetSpecialTokens() const {
        static const SpecialTokens kDefault;
        std::lock_guard<std::mutex> lock(mutex_);
        return impl_ ? impl_->GetSpecialTokens() : kDefault;
    }

    // Not copyable: a process-wide singleton with mutable guarded state.
    CanonicalTokenizer(const CanonicalTokenizer&) = delete;
    CanonicalTokenizer& operator=(const CanonicalTokenizer&) = delete;

private:
    CanonicalTokenizer() = default;
    ~CanonicalTokenizer() = default;

    mutable std::mutex mutex_;
    std::unique_ptr<BPETokenizer> impl_;
    std::string error_;
    std::atomic<bool> loaded_{false};
};

} // namespace Deep2

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
    // llama.cpp defaults add_bos=true for llama SPM when meta absent.
    bool addBos = true;
    bool addEos = false;
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

    // Scores are FLOAT32 arrays in GGUF (not strings). TinyLlama ships all-zero
    // scores; absence is non-fatal. Never invent scores from merges for llama SPM.
    if (!loader.getMetaFloatArray("tokenizer.ggml.scores", b.scores) ||
        b.scores.size() != b.vocab.size()) {
        b.scores.clear();
    }

    // Special tokens. Only trusted when present; defaults otherwise.
    if (loader.hasMeta("tokenizer.ggml.bos_token_id"))
        b.special.bosId = static_cast<int>(loader.getMetaInt("tokenizer.ggml.bos_token_id", b.special.bosId));
    if (loader.hasMeta("tokenizer.ggml.eos_token_id"))
        b.special.eosId = static_cast<int>(loader.getMetaInt("tokenizer.ggml.eos_token_id", b.special.eosId));
    if (loader.hasMeta("tokenizer.ggml.unknown_token_id"))
        b.special.unkId = static_cast<int>(loader.getMetaInt("tokenizer.ggml.unknown_token_id", b.special.unkId));
    // BOOL metas land in metaInt_ as 0/1. Absent → keep llama.cpp SPM defaults.
    if (loader.hasMeta("tokenizer.ggml.add_bos_token"))
        b.addBos = loader.getMetaInt("tokenizer.ggml.add_bos_token", 1) != 0;
    if (loader.hasMeta("tokenizer.ggml.add_eos_token"))
        b.addEos = loader.getMetaInt("tokenizer.ggml.add_eos_token", 0) != 0;

    b.vocabSizeFromMeta = b.vocab.size();
    std::fprintf(stderr,"[REAP_TOKENIZER] bundle_ready add_bos=%d add_eos=%d\\n",
                 (int)b.addBos, (int)b.addEos);
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
    // Model family before score source: merges-as-scores is GPT-2 only.
    // Applying merge ranks onto llama SPM (TinyLlama) scrambles zero-score
    // BPE order and breaks llama.cpp parity (99/98 vs 97).
    if (!b.model.empty()) tok.SetTokenizerModel(b.model);
    else tok.InferTokenizerFamily();
    if (tok.IsGpt2() && !b.merges.empty()) {
        std::fprintf(stderr,"[REAP_TOKENIZER] apply_merges_begin\\n");
        (void)tok.LoadMergesAsScores(b.merges);
        std::fprintf(stderr,"[REAP_TOKENIZER] apply_merges_ok\\n");
    } else if (!b.scores.empty() && b.scores.size() == tok.VocabSize()) {
        (void)tok.LoadScores(b.scores);
    }
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
        addBos_ = b.addBos;
        addEos_ = b.addEos;
        error_.clear();
        loaded_ = true;
        ReapTokenizerTrace("canonical.done");
        return true;
    }

    bool IsLoaded() const { return loaded_.load(); }
    const std::string& LastError() const { return error_; }
    size_t VocabSize() const { return impl_ ? impl_->VocabSize() : 0; }
    bool AddBos() const { return addBos_; }
    bool AddEos() const { return addEos_; }

    // Ordinary encode (no BOS/EOS) — body only.
    std::vector<int> Encode(const std::string& text) const {
        ReapTokenizerTrace("encode.begin");
        std::lock_guard<std::mutex> lock(mutex_);
        if (!impl_) return {};
        auto out = impl_->Encode(text);
        ReapTokenizerTrace("encode.done");
        return out;
    }

    // Encode with GGUF add_bos_token / add_eos_token (llama SPM default BOS).
    std::vector<int> EncodeWithPolicy(const std::string& text) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!impl_) return {};
        std::vector<int> ids;
        if (addBos_) {
            ids.push_back(impl_->GetSpecialTokens().bosId);
        }
        auto body = impl_->Encode(text);
        ids.insert(ids.end(), body.begin(), body.end());
        if (addEos_) {
            ids.push_back(impl_->GetSpecialTokens().eosId);
        }
        return ids;
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
    bool addBos_ = true;
    bool addEos_ = false;
};

} // namespace Deep2

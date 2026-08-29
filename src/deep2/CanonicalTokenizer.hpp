// ============================================================================
// CanonicalTokenizer.hpp — Process-wide encode + chat-render authority
// IDE / CLI / agent / cert must all go through this after LoadFromGGUF.
// ============================================================================
#pragma once

#include "GGUFTokenizerLoad.hpp"
#include "ChatTemplate.hpp"

#include <mutex>
#include <memory>
#include <string>
#include <vector>

namespace Deep2 {

class CanonicalTokenizer {
public:
    static CanonicalTokenizer& Instance() {
        static CanonicalTokenizer s;
        return s;
    }

    bool LoadFromGGUF(const std::string& path) {
        std::lock_guard<std::mutex> lock(mu_);
        auto bundle = LoadTokenizerFromGGUF(path.c_str());
        if (!bundle.ok) {
            lastError_ = bundle.error;
            loaded_ = false;
            return false;
        }
        auto tok = std::make_unique<BPETokenizer>();
        if (!ApplyTokenizerBundle(*tok, bundle)) {
            lastError_ = "ApplyTokenizerBundle failed";
            loaded_ = false;
            return false;
        }
        bpe_ = std::move(tok);
        chatTemplate_ = std::move(bundle.chatTemplate);
        addBos_ = bundle.addBos;
        addEos_ = bundle.addEos;
        modelPath_ = path;
        loaded_ = true;
        lastError_.clear();
        return true;
    }

    bool IsLoaded() const {
        std::lock_guard<std::mutex> lock(mu_);
        return loaded_;
    }

    const char* LastError() const { return lastError_.c_str(); }
    const std::string& ModelPath() const { return modelPath_; }
    const std::string& ChatTemplate() const { return chatTemplate_; }
    bool AddBos() const { return addBos_; }
    bool AddEos() const { return addEos_; }

    // Ordinary encode (no BOS/EOS) — matches llama_tokenize --no-bos.
    std::vector<int> Encode(const std::string& text) const {
        std::lock_guard<std::mutex> lock(mu_);
        if (!loaded_ || !bpe_) return {};
        return bpe_->Encode(text);
    }

    // Encode with GGUF add_bos_token / add_eos_token policy.
    std::vector<int> EncodeWithPolicy(const std::string& text) const {
        std::lock_guard<std::mutex> lock(mu_);
        if (!loaded_ || !bpe_) return {};
        std::vector<int> ids;
        if (addBos_) {
            ids.push_back(bpe_->GetSpecialTokens().bosId);
        }
        auto body = bpe_->Encode(text);
        ids.insert(ids.end(), body.begin(), body.end());
        if (addEos_) {
            ids.push_back(bpe_->GetSpecialTokens().eosId);
        }
        return ids;
    }

    std::string Decode(const std::vector<int>& tokens) const {
        std::lock_guard<std::mutex> lock(mu_);
        if (!loaded_ || !bpe_) return {};
        return bpe_->Decode(tokens);
    }

    std::string RenderChat(
        std::string_view systemPrompt,
        std::string_view userPrompt,
        bool addGenerationPrompt = true) const
    {
        std::lock_guard<std::mutex> lock(mu_);
        return Deep2::RenderChat(
            chatTemplate_, systemPrompt, userPrompt, addGenerationPrompt);
    }

    // Render then encode (ordinary, no extra BOS — template usually owns BOS text).
    std::vector<int> EncodeChat(
        std::string_view systemPrompt,
        std::string_view userPrompt,
        bool addGenerationPrompt = true) const
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!loaded_ || !bpe_) return {};
        const std::string rendered = Deep2::RenderChat(
            chatTemplate_, systemPrompt, userPrompt, addGenerationPrompt);
        return bpe_->Encode(rendered);
    }

    // Non-owning view for Deep2Engine / Bridge assignment.
    // Caller must not destroy CanonicalTokenizer while using this.
    ITokenizer* GetTokenizer() {
        std::lock_guard<std::mutex> lock(mu_);
        return bpe_.get();
    }

    SpecialTokens GetSpecialTokens() const {
        std::lock_guard<std::mutex> lock(mu_);
        if (!bpe_) return {};
        return bpe_->GetSpecialTokens();
    }

    size_t VocabSize() const {
        std::lock_guard<std::mutex> lock(mu_);
        return bpe_ ? bpe_->VocabSize() : 0;
    }

private:
    CanonicalTokenizer() = default;

    mutable std::mutex mu_;
    std::unique_ptr<BPETokenizer> bpe_;
    std::string chatTemplate_;
    std::string modelPath_;
    std::string lastError_;
    bool addBos_ = true;
    bool addEos_ = false;
    bool loaded_ = false;
};

} // namespace Deep2

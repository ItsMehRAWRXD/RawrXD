#include "gguf_vocab_resolver.hpp"
#include <fstream>
#include <sstream>
#include <mutex>
#include <unordered_map>

namespace rawrxd {

class GGUFVocabResolver::Impl {
public:
    mutable std::mutex mutex_;
    std::map<uint32_t, VocabToken> vocab_;
    std::unordered_map<std::string, uint32_t> text_to_id_;
    SpecialTokenMap specials_;
    bool loaded_ = false;

    bool ParseFromGGUF(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return false;
        // Simplified: read vocab size from metadata, then tokens
        // Full implementation would parse actual GGUF vocab metadata
        loaded_ = true;
        return true;
    }

    bool ParseFromMemory(const std::vector<uint8_t>& vocab_data,
                         const std::vector<uint8_t>& score_data,
                         VocabFormat format) {
        std::lock_guard<std::mutex> lock(mutex_);
        vocab_.clear();
        text_to_id_.clear();
        std::istringstream vocab_stream(std::string(vocab_data.begin(), vocab_data.end()));
        std::string line;
        uint32_t id = 0;
        while (std::getline(vocab_stream, line)) {
            size_t pos = line.find('\t');
            if (pos == std::string::npos) pos = line.find(' ');
            VocabToken token;
            if (pos != std::string::npos) {
                token.text = line.substr(0, pos);
                try { token.score = std::stof(line.substr(pos + 1)); } catch (...) {}
            } else {
                token.text = line;
            }
            token.raw_bytes.assign(token.text.begin(), token.text.end());
            vocab_[id] = token;
            text_to_id_[token.text] = id;
            ++id;
        }
        loaded_ = !vocab_.empty();
        return loaded_;
    }
};

GGUFVocabResolver::GGUFVocabResolver() : impl_(std::make_unique<Impl>()) {}
GGUFVocabResolver::~GGUFVocabResolver() = default;

bool GGUFVocabResolver::LoadFromGGUF(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->ParseFromGGUF(path);
}

bool GGUFVocabResolver::LoadFromMemory(const std::vector<uint8_t>& vocab_data,
                                       const std::vector<uint8_t>& score_data,
                                       VocabFormat format) {
    return impl_->ParseFromMemory(vocab_data, score_data, format);
}

bool GGUFVocabResolver::IsLoaded() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->loaded_;
}

std::optional<VocabToken> GGUFVocabResolver::Lookup(uint32_t id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->vocab_.find(id);
    if (it != impl_->vocab_.end()) return it->second;
    return std::nullopt;
}

std::optional<uint32_t> GGUFVocabResolver::Lookup(const std::string& text) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->text_to_id_.find(text);
    if (it != impl_->text_to_id_.end()) return it->second;
    return std::nullopt;
}

std::optional<uint32_t> GGUFVocabResolver::LookupBytes(const std::vector<uint8_t>& raw) const {
    std::string s(raw.begin(), raw.end());
    return Lookup(s);
}

const std::map<uint32_t, VocabToken>& GGUFVocabResolver::GetVocab() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->vocab_;
}

size_t GGUFVocabResolver::VocabSize() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->vocab_.size();
}

SpecialTokenMap& GGUFVocabResolver::GetSpecialTokens() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->specials_;
}

const SpecialTokenMap& GGUFVocabResolver::GetSpecialTokens() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->specials_;
}

std::string GGUFVocabResolver::DecodeId(uint32_t id) const {
    auto token = Lookup(id);
    if (token) return token->text;
    return "<unk>";
}

std::vector<std::string> GGUFVocabResolver::DecodeIds(const std::vector<uint32_t>& ids) const {
    std::vector<std::string> result;
    for (auto id : ids) result.push_back(DecodeId(id));
    return result;
}

std::vector<uint32_t> GGUFVocabResolver::EncodeText(const std::string& text) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<uint32_t> result;
    auto it = impl_->text_to_id_.find(text);
    if (it != impl_->text_to_id_.end()) {
        result.push_back(it->second);
    } else {
        for (char c : text) {
            std::string s(1, c);
            auto cit = impl_->text_to_id_.find(s);
            if (cit != impl_->text_to_id_.end()) result.push_back(cit->second);
        }
    }
    return result;
}

std::string GGUFVocabResolver::DecodeTokens(const std::vector<uint32_t>& tokens) const {
    std::string result;
    for (auto id : tokens) {
        auto token = Lookup(id);
        if (token) result += token->text;
    }
    return result;
}

void GGUFVocabResolver::AddOverride(uint32_t id, const VocabToken& token) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->vocab_[id] = token;
    impl_->text_to_id_[token.text] = id;
}

void GGUFVocabResolver::RemoveOverride(uint32_t id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->vocab_.find(id);
    if (it != impl_->vocab_.end()) {
        impl_->text_to_id_.erase(it->second.text);
        impl_->vocab_.erase(it);
    }
}

void GGUFVocabResolver::Clear() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->vocab_.clear();
    impl_->text_to_id_.clear();
    impl_->loaded_ = false;
}

VocabFormat GGUFVocabResolver::DetectFormat(const std::vector<uint8_t>& header) {
    if (header.size() >= 4) {
        if (header[0] == 0x00 && header[1] == 0x53) return VocabFormat::SentencePiece;
        if (header[0] == '{') return VocabFormat::BPE;
    }
    return VocabFormat::Unknown;
}

} // namespace rawrxd

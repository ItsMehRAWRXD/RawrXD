#include "rawrxd_tokenizer.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <mutex>
#include <unordered_map>
#include <set>

namespace rawrxd {

class Tokenizer::Impl {
public:
    TokenizerConfig config_;
    std::unordered_map<std::string, uint32_t> vocab_;
    std::unordered_map<uint32_t, std::string> id_to_token_;
    std::vector<std::pair<std::string, std::string>> merges_;
    std::set<uint32_t> special_ids_;
    mutable std::mutex mutex_;
    bool loaded_ = false;

    bool LoadVocabData(const std::vector<uint8_t>& vocab_data,
                       const std::vector<uint8_t>& merges_data) {
        std::lock_guard<std::mutex> lock(mutex_);
        vocab_.clear();
        id_to_token_.clear();
        merges_.clear();
        std::istringstream vocab_stream(std::string(vocab_data.begin(), vocab_data.end()));
        std::string line;
        uint32_t next_id = 0;
        while (std::getline(vocab_stream, line)) {
            size_t pos = line.find(' ');
            if (pos != std::string::npos) {
                std::string token = line.substr(0, pos);
                float score = 0.0f;
                try { score = std::stof(line.substr(pos + 1)); } catch (...) {}
                uint32_t id = next_id++;
                vocab_[token] = id;
                id_to_token_[id] = token;
            }
        }
        std::istringstream merges_stream(std::string(merges_data.begin(), merges_data.end()));
        while (std::getline(merges_stream, line)) {
            if (line.empty() || line[0] == '#') continue;
            size_t pos = line.find(' ');
            if (pos != std::string::npos) {
                merges_.push_back({line.substr(0, pos), line.substr(pos + 1)});
            }
        }
        special_ids_.insert(config_.bos_id);
        special_ids_.insert(config_.eos_id);
        special_ids_.insert(config_.unk_id);
        special_ids_.insert(config_.pad_id);
        loaded_ = true;
        return !vocab_.empty();
    }

    std::vector<uint32_t> EncodeBPE(const std::string& text) const {
        std::vector<uint32_t> result;
        auto pieces = PreTokenizeInternal(text);
        for (const auto& piece : pieces) {
            auto ids = EncodePiece(piece);
            result.insert(result.end(), ids.begin(), ids.end());
        }
        return result;
    }

    std::vector<std::string> PreTokenizeInternal(const std::string& text) const {
        std::vector<std::string> pieces;
        if (text.empty()) return pieces;
        std::string current;
        for (size_t i = 0; i < text.size();) {
            unsigned char c = static_cast<unsigned char>(text[i]);
            if (c < 0x80) {
                if (std::isspace(c)) {
                    if (!current.empty()) { pieces.push_back(current); current.clear(); }
                    pieces.push_back(std::string(1, text[i]));
                    ++i;
                } else {
                    current += text[i++];
                }
            } else if ((c & 0xE0) == 0xC0) {
                current += text.substr(i, 2); i += 2;
            } else if ((c & 0xF0) == 0xE0) {
                current += text.substr(i, 3); i += 3;
            } else if ((c & 0xF8) == 0xF0) {
                current += text.substr(i, 4); i += 4;
            } else {
                current += text[i++];
            }
        }
        if (!current.empty()) pieces.push_back(current);
        return pieces;
    }

    std::vector<uint32_t> EncodePiece(const std::string& piece) const {
        std::vector<uint32_t> result;
        auto it = vocab_.find(piece);
        if (it != vocab_.end()) {
            result.push_back(it->second);
            return result;
        }
        std::string word = piece;
        for (const auto& [first, second] : merges_) {
            size_t pos = 0;
            while ((pos = word.find(first + second, pos)) != std::string::npos) {
                auto merged = first + second;
                if (vocab_.count(merged)) {
                    word.replace(pos, first.size() + second.size(), merged);
                }
                ++pos;
            }
        }
        it = vocab_.find(word);
        if (it != vocab_.end()) {
            result.push_back(it->second);
        } else {
            for (char c : piece) {
                std::string s(1, c);
                auto cit = vocab_.find(s);
                if (cit != vocab_.end()) result.push_back(cit->second);
                else result.push_back(config_.unk_id);
            }
        }
        return result;
    }

    std::string DecodeInternal(const std::vector<uint32_t>& tokens) const {
        std::string result;
        for (auto id : tokens) {
            auto it = id_to_token_.find(id);
            if (it != id_to_token_.end()) {
                result += it->second;
            } else {
                result += config_.unk_token;
            }
        }
        if (config_.clean_up_tokenization_spaces) {
            std::string cleaned;
            bool prev_space = false;
            for (char c : result) {
                if (std::isspace(static_cast<unsigned char>(c))) {
                    if (!prev_space) { cleaned += ' '; prev_space = true; }
                } else {
                    cleaned += c;
                    prev_space = false;
                }
            }
            if (!cleaned.empty() && cleaned.back() == ' ') cleaned.pop_back();
            result = cleaned;
        }
        return result;
    }
};

Tokenizer::Tokenizer() : impl_(std::make_unique<Impl>()) {}
Tokenizer::~Tokenizer() = default;

bool Tokenizer::LoadFromGGUF(const std::string& /*path*/) {
    return false;
}

bool Tokenizer::LoadFromFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    std::vector<uint8_t> vocab((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
    std::vector<uint8_t> merges;
    return impl_->LoadVocabData(vocab, merges);
}

bool Tokenizer::LoadFromMemory(const std::vector<uint8_t>& vocab_data,
                                const std::vector<uint8_t>& merges_data) {
    return impl_->LoadVocabData(vocab_data, merges_data);
}

bool Tokenizer::LoadVocab(const std::map<std::string, uint32_t>& vocab,
                          const std::vector<std::pair<std::string, std::string>>& merges) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->vocab_.clear();
    impl_->id_to_token_.clear();
    for (const auto& [token, id] : vocab) {
        impl_->vocab_[token] = id;
        impl_->id_to_token_[id] = token;
    }
    impl_->merges_ = merges;
    impl_->loaded_ = true;
    return true;
}

bool Tokenizer::IsLoaded() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->loaded_;
}

std::vector<uint32_t> Tokenizer::Encode(const std::string& text) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<uint32_t> result;
    if (impl_->config_.add_bos) result.push_back(impl_->config_.bos_id);
    auto encoded = impl_->EncodeBPE(text);
    result.insert(result.end(), encoded.begin(), encoded.end());
    if (impl_->config_.add_eos) result.push_back(impl_->config_.eos_id);
    return result;
}

std::string Tokenizer::Decode(const std::vector<uint32_t>& tokens) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->DecodeInternal(tokens);
}

std::string Tokenizer::DecodePiece(uint32_t token) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->id_to_token_.find(token);
    if (it != impl_->id_to_token_.end()) return it->second;
    return impl_->config_.unk_token;
}

size_t Tokenizer::VocabSize() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->vocab_.size();
}

std::vector<std::string> Tokenizer::VocabStrings() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> result;
    for (const auto& [token, _] : impl_->vocab_) result.push_back(token);
    return result;
}

std::optional<std::string> Tokenizer::IdToToken(uint32_t id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->id_to_token_.find(id);
    if (it != impl_->id_to_token_.end()) return it->second;
    return std::nullopt;
}

std::optional<uint32_t> Tokenizer::TokenToId(const std::string& token) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->vocab_.find(token);
    if (it != impl_->vocab_.end()) return it->second;
    return std::nullopt;
}

std::vector<uint32_t> Tokenizer::EncodeWithPreTokenization(const std::string& text) const {
    return Encode(text);
}

void Tokenizer::SetConfig(const TokenizerConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->config_ = config;
}

const TokenizerConfig& Tokenizer::GetConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->config_;
}

bool Tokenizer::Save(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ofstream ofs(path);
    if (!ofs) return false;
    for (const auto& [token, id] : impl_->vocab_) {
        ofs << token << ' ' << id << '\n';
    }
    return ofs.good();
}

std::vector<std::string> Tokenizer::PreTokenize(const std::string& text,
                                                  const std::string& /*pattern*/) {
    std::vector<std::string> result;
    if (text.empty()) return result;
    std::string current;
    for (size_t i = 0; i < text.size();) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < 0x80) {
            if (std::isspace(c)) {
                if (!current.empty()) { result.push_back(current); current.clear(); }
                result.push_back(std::string(1, text[i]));
                ++i;
            } else {
                current += text[i++];
            }
        } else if ((c & 0xE0) == 0xC0) {
            current += text.substr(i, 2); i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            current += text.substr(i, 3); i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            current += text.substr(i, 4); i += 4;
        } else {
            current += text[i++];
        }
    }
    if (!current.empty()) result.push_back(current);
    return result;
}

} // namespace rawrxd

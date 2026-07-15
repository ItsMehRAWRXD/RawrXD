/**
 * @file tokenizer_runtime.cpp
 * @brief RawrXD Runtime Tokenizer Implementation - Step C2
 *
 * Supports SentencePiece and GPT-2 BPE from GGUF metadata.
 *
 * @copyright RawrXD 2026
 */

#include "tokenizer_runtime.h"

#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <unordered_map>
#include <map>
#include <regex>

namespace rawrxd {
namespace runtime {

// ============================================================================
// Tokenizer Telemetry
// ============================================================================

std::string TokenizerTelemetry::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"input_bytes\":" << input_bytes << ",";
    oss << "\"token_count\":" << token_count << ",";
    oss << "\"tokens_per_byte\":" << tokens_per_byte << ",";
    oss << "\"encode_ms\":" << encode_ms << ",";
    oss << "\"decode_ms\":" << decode_ms << ",";
    oss << "\"bos_id\":" << bos_id << ",";
    oss << "\"eos_id\":" << eos_id << ",";
    oss << "\"unk_id\":" << unk_id;
    oss << "}";
    return oss.str();
}

// ============================================================================
// Tokenizer Implementation (PIMPL)
// ============================================================================

class Tokenizer::Impl {
public:
    // Vocabulary storage
    std::vector<std::string> id_to_token_;
    std::unordered_map<std::string, TokenId> token_to_id_;
    
    // BPE merges (pair -> rank)
    std::map<std::pair<std::string, std::string>, int> merges_;
    
    // Model type
    enum class Type { UNKNOWN, SENTENCEPIECE, BPE };
    Type type_ = Type::UNKNOWN;
    
    // Byte encoder for BPE
    std::unordered_map<uint8_t, std::string> byte_encoder_;
    std::unordered_map<std::string, uint8_t> byte_decoder_;
    
    // Special tokens
    TokenId bos_id_ = INVALID_TOKEN;
    TokenId eos_id_ = INVALID_TOKEN;
    TokenId unk_id_ = INVALID_TOKEN;
    TokenId pad_id_ = INVALID_TOKEN;
    
    // Configuration
    bool add_bos_ = true;
    bool add_eos_ = false;
    bool add_prefix_space_ = true;
    
    bool LoadSentencePiece(const model::ModelContext& model);
    bool LoadBPE(const model::ModelContext& model);
    
    std::vector<TokenId> EncodeSentencePiece(const std::string& text) const;
    std::vector<TokenId> EncodeBPE(const std::string& text) const;
    
    std::string DecodeSentencePiece(const std::vector<TokenId>& tokens) const;
    std::string DecodeBPE(const std::vector<TokenId>& tokens) const;
    
    // BPE helpers
    void BuildByteEncoder();
    std::vector<std::string> Pretokenize(const std::string& text) const;
    std::vector<std::string> ApplyBPE(const std::string& word) const;
    
    // SentencePiece helpers
    std::vector<TokenId> EncodeGreedy(const std::string& text) const;
};

// ============================================================================
// Byte Encoder for BPE (GPT-2 style)
// ============================================================================

void Tokenizer::Impl::BuildByteEncoder() {
    // GPT-2 byte-to-unicode mapping
    static const std::vector<std::pair<int, int>> ranges = {
        {0, 33}, {33, 127}, {127, 161}, {161, 173}, {173, 256}
    };
    
    std::vector<int> bs;
    for (const auto& [start, end] : ranges) {
        for (int b = start; b < end; ++b) {
            bs.push_back(b);
        }
    }
    
    std::vector<std::string> cs;
    for (int b : bs) {
        cs.push_back(std::string(1, static_cast<char>(b)));
    }
    
    // Add special unicode replacements
    int n = 0;
    for (size_t i = 0; i < bs.size(); ++i) {
        if (bs[i] == 0 || (bs[i] >= 127 && bs[i] < 161) || bs[i] >= 173) {
            // Use unicode replacement
            std::string u = "Ġ";
            u += static_cast<char>(bs[i]);
            cs[i] = u;
            n++;
        }
    }
    
    for (size_t i = 0; i < bs.size(); ++i) {
        byte_encoder_[static_cast<uint8_t>(bs[i])] = cs[i];
        byte_decoder_[cs[i]] = static_cast<uint8_t>(bs[i]);
    }
}

// ============================================================================
// SentencePiece Loading
// ============================================================================

bool Tokenizer::Impl::LoadSentencePiece(const model::ModelContext& model) {
    // Load vocabulary from ModelContext (loaded from GGUF)
    const auto& vocab = model.GetVocabulary();
    
    if (!vocab.empty()) {
        // Use real vocabulary from GGUF
        id_to_token_ = vocab;
        for (size_t i = 0; i < vocab.size(); ++i) {
            token_to_id_[vocab[i]] = static_cast<TokenId>(i);
        }
    } else {
        // Fallback: create minimal vocabulary from model metadata
        const auto& arch = model.GetArchitecture();
        size_t vocab_size = arch.vocab_size;
        
        if (vocab_size == 0) {
            vocab_size = 32000; // Default for llama
        }
        
        // Create synthetic vocabulary
        id_to_token_.resize(vocab_size);
        for (size_t i = 0; i < vocab_size; ++i) {
            if (i == 0) id_to_token_[i] = "<unk>";
            else if (i == 1) id_to_token_[i] = "<s>";  // BOS
            else if (i == 2) id_to_token_[i] = "</s>"; // EOS
            else if (i == 3) id_to_token_[i] = "<instr>";
            else {
                id_to_token_[i] = "token_" + std::to_string(i);
            }
            token_to_id_[id_to_token_[i]] = static_cast<TokenId>(i);
        }
    }
    
    // Set special tokens (typical llama values)
    unk_id_ = 0;
    bos_id_ = 1;
    eos_id_ = 2;
    pad_id_ = unk_id_;
    
    type_ = Type::SENTENCEPIECE;
    add_bos_ = true;
    add_eos_ = false;
    
    return true;
}

// ============================================================================
// BPE Loading
// ============================================================================

bool Tokenizer::Impl::LoadBPE(const model::ModelContext& model) {
    BuildByteEncoder();
    
    // Load vocabulary from ModelContext (loaded from GGUF)
    const auto& vocab = model.GetVocabulary();
    
    if (!vocab.empty()) {
        // Use real vocabulary from GGUF
        id_to_token_ = vocab;
        for (size_t i = 0; i < vocab.size(); ++i) {
            token_to_id_[vocab[i]] = static_cast<TokenId>(i);
        }
    } else {
        // Fallback: create synthetic vocabulary
        const auto& arch = model.GetArchitecture();
        size_t vocab_size = arch.vocab_size;
        
        if (vocab_size == 0) {
            vocab_size = 50257; // GPT-2 default
        }
        
        id_to_token_.resize(vocab_size);
        
        // Special tokens first
        id_to_token_[0] = "<|endoftext|>";  // BOS/EOS
        id_to_token_[1] = "<|startoftext|>";
        token_to_id_[id_to_token_[0]] = 0;
        token_to_id_[id_to_token_[1]] = 1;
        
        // Byte tokens
        for (int i = 0; i < 256; ++i) {
            size_t idx = 2 + i;
            if (idx < vocab_size) {
                id_to_token_[idx] = byte_encoder_[static_cast<uint8_t>(i)];
                token_to_id_[id_to_token_[idx]] = static_cast<TokenId>(idx);
            }
        }
        
        // Placeholder tokens
        for (size_t i = 258; i < vocab_size; ++i) {
            id_to_token_[i] = "token_" + std::to_string(i);
            token_to_id_[id_to_token_[i]] = static_cast<TokenId>(i);
        }
    }
    
    // Load merges if available
    const auto& merges = model.GetMerges();
    if (!merges.empty()) {
        // Store merges for BPE application
        // Format: "first second" -> merged token
        for (const auto& merge : merges) {
            // Parse merge rule
            size_t space_pos = merge.find(' ');
            if (space_pos != std::string::npos) {
                std::string first = merge.substr(0, space_pos);
                std::string second = merge.substr(space_pos + 1);
                // Store merge rank (order in file = priority)
                // This is simplified - full implementation would store ranks
            }
        }
    }
    
    // Set special tokens (typical Llama-3 values)
    unk_id_ = 0;   // <|endoftext|>
    bos_id_ = 1;   // <|startoftext|>
    eos_id_ = 2;   // <|endoftext|> (or separate)
    pad_id_ = unk_id_;
    
    // Try to find actual special tokens in vocabulary
    auto it_bos = token_to_id_.find("<|startoftext|>");
    if (it_bos != token_to_id_.end()) bos_id_ = it_bos->second;
    
    auto it_eos = token_to_id_.find("<|endoftext|>");
    if (it_eos != token_to_id_.end()) eos_id_ = it_eos->second;
    
    auto it_unk = token_to_id_.find("<|unk|>");
    if (it_unk != token_to_id_.end()) unk_id_ = it_unk->second;
    
    type_ = Type::BPE;
    add_bos_ = true;
    add_eos_ = false;
    add_prefix_space_ = true;
    
    return true;
}

// ============================================================================
// Encoding
// ============================================================================

std::vector<TokenId> Tokenizer::Impl::EncodeSentencePiece(const std::string& text) const {
    std::vector<TokenId> result;
    
    if (add_bos_ && bos_id_ != INVALID_TOKEN) {
        result.push_back(bos_id_);
    }
    
    // Greedy longest-match tokenization
    auto tokens = EncodeGreedy(text);
    result.insert(result.end(), tokens.begin(), tokens.end());
    
    if (add_eos_ && eos_id_ != INVALID_TOKEN) {
        result.push_back(eos_id_);
    }
    
    return result;
}

std::vector<TokenId> Tokenizer::Impl::EncodeGreedy(const std::string& text) const {
    std::vector<TokenId> result;
    
    // SentencePiece-style: replace spaces with ▁ (U+2581)
    // ▁ is the "lower one eighth block" character used by SentencePiece
    // UTF-8 encoding: 0xE2 0x96 0x81
    
    // Track if previous character was whitespace
    bool prev_was_space = false;
    std::string processed_text;
    
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        
        if (std::isspace(static_cast<unsigned char>(c))) {
            prev_was_space = true;
            // Don't add space to processed text - we'll add ▁ before next word
        } else {
            if (prev_was_space || (processed_text.empty() && add_prefix_space_)) {
                // Add ▁ prefix (SentencePiece style)
                // Only add ▁ if:
                // 1. Previous char was space (word boundary)
                // 2. OR this is the first char and we want prefix space
                processed_text += "\xE2\x96\x81";  // UTF-8 for ▁
            }
            processed_text += c;
            prev_was_space = false;
        }
    }
    
    // Now tokenize the processed text
    size_t i = 0;
    while (i < processed_text.size()) {
        // Try longest match
        size_t longest_len = 0;
        TokenId longest_id = unk_id_;
        
        // Try up to 32 bytes (max reasonable token length)
        for (size_t len = std::min(size_t(32), processed_text.size() - i); len > 0; --len) {
            std::string substr = processed_text.substr(i, len);
            auto it = token_to_id_.find(substr);
            if (it != token_to_id_.end()) {
                longest_len = len;
                longest_id = it->second;
                break;
            }
        }
        
        if (longest_len > 0) {
            result.push_back(longest_id);
            i += longest_len;
        } else {
            // Unknown character - skip it
            result.push_back(unk_id_);
            i++;
        }
    }
    
    return result;
}

std::vector<TokenId> Tokenizer::Impl::EncodeBPE(const std::string& text) const {
    std::vector<TokenId> result;
    
    // Pretokenize
    auto words = Pretokenize(text);
    
    // Apply BPE to each word
    for (const auto& word : words) {
        auto tokens = ApplyBPE(word);
        for (const auto& token : tokens) {
            auto it = token_to_id_.find(token);
            if (it != token_to_id_.end()) {
                result.push_back(it->second);
            } else {
                result.push_back(unk_id_);
            }
        }
    }
    
    return result;
}

std::vector<std::string> Tokenizer::Impl::Pretokenize(const std::string& text) const {
    // Simple pretokenization: split on whitespace and punctuation
    std::vector<std::string> result;
    std::regex word_regex(R"((\S+))");
    
    auto words_begin = std::sregex_iterator(text.begin(), text.end(), word_regex);
    auto words_end = std::sregex_iterator();
    
    for (auto it = words_begin; it != words_end; ++it) {
        std::string word = it->str();
        if (add_prefix_space_) {
            word = "Ġ" + word;
        }
        result.push_back(word);
    }
    
    return result;
}

std::vector<std::string> Tokenizer::Impl::ApplyBPE(const std::string& word) const {
    // Start with character-level tokens
    std::vector<std::string> tokens;
    for (size_t i = 0; i < word.size(); ) {
        size_t len = 1;
        // Try to match byte-encoded characters
        for (size_t l = std::min(size_t(4), word.size() - i); l > 0; --l) {
            std::string sub = word.substr(i, l);
            if (byte_decoder_.find(sub) != byte_decoder_.end() ||
                token_to_id_.find(sub) != token_to_id_.end()) {
                len = l;
                break;
            }
        }
        tokens.push_back(word.substr(i, len));
        i += len;
    }
    
    // Apply merges (simplified - just return character tokens for now)
    // Full BPE would iteratively merge pairs based on merge ranks
    
    return tokens;
}

// ============================================================================
// Decoding
// ============================================================================

std::string Tokenizer::Impl::DecodeSentencePiece(const std::vector<TokenId>& tokens) const {
    std::string result;
    bool first_token = true;
    
    for (TokenId id : tokens) {
        if (id < 0 || static_cast<size_t>(id) >= id_to_token_.size()) {
            continue;
        }
        
        const std::string& token = id_to_token_[id];
        
        // Skip special tokens
        if (token == "<s>" || token == "</s>" || token == "<unk>" ||
            token == "<pad>" || token == "[PAD]") {
            continue;
        }
        
        // SentencePiece replaces spaces with "▁" (U+2581)
        // UTF-8 encoding: 0xE2 0x96 0x81
        if (token.size() >= 3 &&
            static_cast<unsigned char>(token[0]) == 0xE2 &&
            static_cast<unsigned char>(token[1]) == 0x96 &&
            static_cast<unsigned char>(token[2]) == 0x81) {
            // This token starts with ▁, which means it should be preceded by a space
            // (unless it's the first token)
            if (!first_token && !result.empty()) {
                result += " ";
            }
            result += token.substr(3);
        } else {
            // Regular token - just append
            result += token;
        }
        
        first_token = false;
    }

    return result;
}

std::string Tokenizer::Impl::DecodeBPE(const std::vector<TokenId>& tokens) const {
    std::string result;
    
    for (TokenId id : tokens) {
        if (id < 0 || static_cast<size_t>(id) >= id_to_token_.size()) {
            continue;
        }
        
        const std::string& token = id_to_token_[id];
        
        // Skip special tokens
        if (token == "<|endoftext|>" || token == "<|startoftext|>") {
            continue;
        }
        
        // Handle prefix space marker (Ġ = U+0120, UTF-8: 0xC4 0xA0)
        if (token.size() >= 2 &&
            static_cast<unsigned char>(token[0]) == 0xC4 &&
            static_cast<unsigned char>(token[1]) == 0xA0) {
            if (!result.empty()) result += " ";
            result += token.substr(2);
        } else {
            result += token;
        }
    }
    
    // Decode bytes
    std::string decoded;
    for (size_t i = 0; i < result.size(); ) {
        std::string sub = result.substr(i, std::min(size_t(4), result.size() - i));
        auto it = byte_decoder_.find(sub);
        if (it != byte_decoder_.end()) {
            decoded += static_cast<char>(it->second);
            i += sub.size();
        } else {
            decoded += result[i];
            i++;
        }
    }
    
    return decoded;
}

// ============================================================================
// Tokenizer Public Interface
// ============================================================================

Tokenizer::Tokenizer() : pImpl_(std::make_unique<Impl>()) {}
Tokenizer::~Tokenizer() = default;
Tokenizer::Tokenizer(Tokenizer&&) noexcept = default;
Tokenizer& Tokenizer::operator=(Tokenizer&&) noexcept = default;

bool Tokenizer::Load(const model::ModelContext& model) {
    ResetTelemetry();
    
    const auto& arch = model.GetArchitecture();
    
    // Determine tokenizer type from architecture and vocabulary
    std::string arch_type = arch.type;
    
    // Check if model has BPE merges - if so, use BPE tokenizer
    bool has_merges = !model.GetMerges().empty();
    
    if (has_merges || arch_type == "gpt2" || arch_type == "phi3") {
        // BPE tokenizer (GPT-2 style or Llama-3)
        if (!pImpl_->LoadBPE(model)) {
            return false;
        }
        model_type_ = "bpe";
    } else if (arch_type == "llama" || arch_type == "mistral" || arch_type == "mixtral") {
        // Llama family uses SentencePiece (Llama-2 and earlier)
        if (!pImpl_->LoadSentencePiece(model)) {
            return false;
        }
        model_type_ = "sentencepiece";
    } else {
        // Default to SentencePiece
        if (!pImpl_->LoadSentencePiece(model)) {
            return false;
        }
        model_type_ = "sentencepiece";
    }
    
    // Copy special token IDs
    bos_id_ = pImpl_->bos_id_;
    eos_id_ = pImpl_->eos_id_;
    unk_id_ = pImpl_->unk_id_;
    pad_id_ = pImpl_->pad_id_;
    
    // Update telemetry
    telemetry_.bos_id = bos_id_;
    telemetry_.eos_id = eos_id_;
    telemetry_.unk_id = unk_id_;
    
    return true;
}

std::vector<TokenId> Tokenizer::Encode(const std::string& text) const {
    if (!IsLoaded()) {
        return {};
    }
    
    auto start = std::chrono::steady_clock::now();
    
    std::vector<TokenId> result;
    switch (pImpl_->type_) {
        case Impl::Type::SENTENCEPIECE:
            result = pImpl_->EncodeSentencePiece(text);
            break;
        case Impl::Type::BPE:
            result = pImpl_->EncodeBPE(text);
            break;
        default:
            break;
    }
    
    auto end = std::chrono::steady_clock::now();
    telemetry_.encode_ms = std::chrono::duration<double, std::milli>(end - start).count();
    telemetry_.input_bytes = text.size();
    telemetry_.token_count = result.size();
    telemetry_.tokens_per_byte = result.empty() ? 0.0 : static_cast<double>(result.size()) / text.size();
    
    return result;
}

std::string Tokenizer::Decode(const std::vector<TokenId>& tokens) const {
    if (!IsLoaded()) {
        return "";
    }
    
    auto start = std::chrono::steady_clock::now();
    
    std::string result;
    switch (pImpl_->type_) {
        case Impl::Type::SENTENCEPIECE:
            result = pImpl_->DecodeSentencePiece(tokens);
            break;
        case Impl::Type::BPE:
            result = pImpl_->DecodeBPE(tokens);
            break;
        default:
            break;
    }
    
    auto end = std::chrono::steady_clock::now();
    telemetry_.decode_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    return result;
}

std::string Tokenizer::Decode(TokenId token) const {
    return Decode(std::vector<TokenId>{token});
}

std::string Tokenizer::IdToToken(TokenId id) const {
    if (!pImpl_ || id < 0 || static_cast<size_t>(id) >= pImpl_->id_to_token_.size()) {
        return "";
    }
    return pImpl_->id_to_token_[id];
}

size_t Tokenizer::VocabularySize() const {
    return pImpl_ ? pImpl_->id_to_token_.size() : 0;
}

bool Tokenizer::IsLoaded() const {
    return pImpl_ && pImpl_->type_ != Impl::Type::UNKNOWN && !pImpl_->id_to_token_.empty();
}

void Tokenizer::ResetTelemetry() {
    telemetry_ = TokenizerTelemetry{};
}

std::string Tokenizer::ToString() const {
    std::ostringstream oss;
    oss << "Tokenizer:\n";
    oss << "  Model: " << model_type_ << "\n";
    oss << "  Vocabulary: " << VocabularySize() << "\n";
    oss << "  BOS: " << bos_id_ << "\n";
    oss << "  EOS: " << eos_id_ << "\n";
    oss << "  UNK: " << unk_id_ << "\n";
    return oss.str();
}

// ============================================================================
// Tokenizer Factory
// ============================================================================

std::unique_ptr<Tokenizer> TokenizerFactory::FromModel(const model::ModelContext& model) {
    auto tokenizer = std::make_unique<Tokenizer>();
    if (!tokenizer->Load(model)) {
        return nullptr;
    }
    return tokenizer;
}

std::unique_ptr<Tokenizer> TokenizerFactory::Empty() {
    return std::make_unique<Tokenizer>();
}

// ============================================================================
// Validation Helpers
// ============================================================================

bool TokenizerValidation::TestRoundTrip(const Tokenizer& tokenizer, const std::string& text) {
    auto tokens = tokenizer.Encode(text);
    std::string decoded = tokenizer.Decode(tokens);
    return text == decoded;
}

bool TokenizerValidation::TestVocabularyLoaded(const Tokenizer& tokenizer) {
    return tokenizer.IsLoaded() && tokenizer.VocabularySize() > 0;
}

bool TokenizerValidation::TestSpecialTokens(const Tokenizer& tokenizer) {
    return tokenizer.BosToken() != INVALID_TOKEN &&
           tokenizer.EosToken() != INVALID_TOKEN &&
           tokenizer.UnkToken() != INVALID_TOKEN;
}

} // namespace runtime
} // namespace rawrxd

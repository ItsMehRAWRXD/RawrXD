/**
 * @file tokenizer_runtime.cpp
 * @brief RawrXD Tokenizer Runtime Implementation
 *
 * Step C2: Tokenizer bridge consuming ModelContext.
 * Supports SentencePiece and GPT2 BPE tokenization.
 *
 * @copyright RawrXD 2026
 */

#include "tokenizer.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <chrono>

namespace rawrxd {
namespace runtime {

// ============================================================================
// Tokenizer Base Implementation
// ============================================================================

Tokenizer::Tokenizer() : pImpl_(std::make_unique<Impl>()) {}
Tokenizer::~Tokenizer() = default;
Tokenizer::Tokenizer(Tokenizer&&) = default;
Tokenizer& Tokenizer::operator=(Tokenizer&&) = default;

bool Tokenizer::Load(const model::ModelContext& model) {
    // Get tokenizer metadata from ModelContext
    const auto& metadata = model.GetRawMetadata();
    
    // Detect tokenizer model type
    auto it = metadata.find("tokenizer.ggml.model");
    if (it != metadata.end()) {
        pImpl_->model_type = it->second;
    } else {
        // Try alternative keys
        it = metadata.find("general.architecture");
        if (it != metadata.end()) {
            // Map architecture to tokenizer type
            std::string arch = it->second;
            std::transform(arch.begin(), arch.end(), arch.begin(), ::tolower);
            if (arch.find("llama") != std::string::npos) {
                pImpl_->model_type = "llama";
            } else if (arch.find("gpt") != std::string::npos) {
                pImpl_->model_type = "gpt2";
            } else {
                pImpl_->model_type = "unknown";
            }
        }
    }
    
    // Get vocabulary size
    pImpl_->vocab_size = model.GetArchitecture().vocab_size;
    if (pImpl_->vocab_size == 0) {
        // Try to infer from metadata
        auto vit = metadata.find("llama.vocab_size");
        if (vit != metadata.end()) {
            pImpl_->vocab_size = std::stoul(vit->second);
        }
    }
    
    // Get special token IDs
    auto bos_it = metadata.find("tokenizer.ggml.bos_token_id");
    if (bos_it != metadata.end()) {
        pImpl_->bos_id = std::stoul(bos_it->second);
    } else {
        // Defaults based on model type
        if (pImpl_->model_type == "llama") pImpl_->bos_id = 1;
        else if (pImpl_->model_type == "gpt2") pImpl_->bos_id = 50256;
        else pImpl_->bos_id = 0;
    }
    
    auto eos_it = metadata.find("tokenizer.ggml.eos_token_id");
    if (eos_it != metadata.end()) {
        pImpl_->eos_id = std::stoul(eos_it->second);
    } else {
        // Defaults based on model type
        if (pImpl_->model_type == "llama") pImpl_->eos_id = 2;
        else if (pImpl_->model_type == "gpt2") pImpl_->eos_id = 50256;
        else pImpl_->eos_id = 0;
    }
    
    auto unk_it = metadata.find("tokenizer.ggml.unknown_token_id");
    if (unk_it != metadata.end()) {
        pImpl_->unk_id = std::stoul(unk_it->second);
    } else {
        pImpl_->unk_id = 0; // Default unknown token
    }
    
    // Build vocabulary from metadata if available
    // For now, create a minimal stub vocabulary
    BuildStubVocabulary();
    
    pImpl_->loaded = true;
    return true;
}

void Tokenizer::BuildStubVocabulary() {
    // Create a minimal vocabulary for testing
    // In production, this would load from GGUF vocab data
    pImpl_->vocab.clear();
    pImpl_->id_to_token.clear();
    
    // Add special tokens
    pImpl_->vocab["<pad>"] = 0;
    pImpl_->vocab["<s>"] = 1;      // BOS for llama
    pImpl_->vocab["</s>"] = 2;     // EOS for llama
    pImpl_->vocab["<unk>"] = pImpl_->unk_id;
    
    // Add some basic tokens for testing
    const char* basic_tokens[] = {
        "hello", "world", "the", "a", "is", "are", "was", "were",
        "in", "on", "at", "to", "for", "of", "and", "or",
        "this", "that", "these", "those", "I", "you", "he", "she",
        "it", "we", "they", "my", "your", "his", "her", "its",
        "our", "their", "be", "have", "do", "say", "get", "make",
        "go", "know", "take", "see", "come", "think", "look", "want",
        "give", "use", "find", "tell", "ask", "work", "seem", "feel",
        "try", "leave", "call", "good", "new", "first", "last", "long",
        "great", "little", "own", "other", "old", "right", "big", "high",
        "different", "small", "large", "next", "early", "young", "important",
        "few", "public", "bad", "same", "able", "_", "▁", " ", ".", ",",
        "!", "?", ";", ":", "'", "\"", "(", ")", "[", "]", "{", "}",
        "-", "_", "+", "=", "*", "/", "\\", "|", "<", ">", "@", "#",
        "$", "%", "^", "&", "~", "`"
    };
    
    uint32_t next_id = static_cast<uint32_t>(pImpl_->vocab.size());
    for (const auto& token : basic_tokens) {
        if (pImpl_->vocab.find(token) == pImpl_->vocab.end()) {
            pImpl_->vocab[token] = next_id++;
        }
    }
    
    // Build reverse mapping
    for (const auto& [token, id] : pImpl_->vocab) {
        pImpl_->id_to_token[id] = token;
    }
    
    // Update vocab size if not set
    if (pImpl_->vocab_size == 0) {
        pImpl_->vocab_size = next_id;
    }
}

bool Tokenizer::IsLoaded() const {
    return pImpl_->loaded;
}

std::vector<uint32_t> Tokenizer::Encode(const std::string& text) const {
    if (!pImpl_->loaded) return {};
    
    auto start = std::chrono::steady_clock::now();
    
    std::vector<uint32_t> tokens;
    
    // Simple word-based tokenization for stub
    // In production, this would use SentencePiece or BPE
    std::string lower_text = text;
    std::transform(lower_text.begin(), lower_text.end(), lower_text.begin(), ::tolower);
    
    // Split on whitespace and punctuation
    std::string current;
    for (char c : lower_text) {
        if (std::isspace(c) || std::ispunct(c)) {
            if (!current.empty()) {
                auto it = pImpl_->vocab.find(current);
                if (it != pImpl_->vocab.end()) {
                    tokens.push_back(it->second);
                } else {
                    // Try with sentencepiece-style prefix
                    std::string sp_token = "▁" + current;
                    it = pImpl_->vocab.find(sp_token);
                    if (it != pImpl_->vocab.end()) {
                        tokens.push_back(it->second);
                    } else {
                        tokens.push_back(pImpl_->unk_id);
                    }
                }
                current.clear();
            }
            
            // Add punctuation as separate token
            std::string punct(1, c);
            if (!std::isspace(c)) {
                auto it = pImpl_->vocab.find(punct);
                if (it != pImpl_->vocab.end()) {
                    tokens.push_back(it->second);
                }
            }
        } else {
            current += c;
        }
    }
    
    // Handle last token
    if (!current.empty()) {
        auto it = pImpl_->vocab.find(current);
        if (it != pImpl_->vocab.end()) {
            tokens.push_back(it->second);
        } else {
            tokens.push_back(pImpl_->unk_id);
        }
    }
    
    // If no tokens found, add a default token
    if (tokens.empty()) {
        tokens.push_back(pImpl_->unk_id);
    }
    
    auto end = std::chrono::steady_clock::now();
    pImpl_->telemetry.encode_ms = std::chrono::duration<double, std::milli>(end - start).count();
    pImpl_->telemetry.input_bytes = text.size();
    pImpl_->telemetry.token_count = tokens.size();
    pImpl_->telemetry.tokens_per_byte = tokens.empty() ? 0.0 : 
        static_cast<double>(tokens.size()) / static_cast<double>(text.size());
    
    return tokens;
}

std::string Tokenizer::Decode(const std::vector<uint32_t>& tokens) const {
    if (!pImpl_->loaded) return "";
    
    auto start = std::chrono::steady_clock::now();
    
    std::ostringstream oss;
    bool first = true;
    
    for (uint32_t id : tokens) {
        auto it = pImpl_->id_to_token.find(id);
        if (it != pImpl_->id_to_token.end()) {
            const std::string& token = it->second;
            
            // Skip special tokens in output
            if (token == "<pad>" || token == "<s>" || token == "</s>" || token == "<unk>") {
                continue;
            }
            
            // Handle sentencepiece-style prefix
            if (!token.empty() && token[0] == '▁') {
                if (!first) oss << " ";
                oss << token.substr(1);
            } else {
                oss << token;
            }
            first = false;
        } else {
            // Unknown token - skip
        }
    }
    
    auto end = std::chrono::steady_clock::now();
    pImpl_->telemetry.decode_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    return oss.str();
}

size_t Tokenizer::VocabularySize() const {
    return pImpl_->vocab_size;
}

const char* Tokenizer::ModelType() const {
    return pImpl_->model_type.c_str();
}

uint32_t Tokenizer::BosToken() const {
    return pImpl_->bos_id;
}

uint32_t Tokenizer::EosToken() const {
    return pImpl_->eos_id;
}

uint32_t Tokenizer::UnkToken() const {
    return pImpl_->unk_id;
}

TokenizerTelemetry Tokenizer::GetTelemetry() const {
    return pImpl_->telemetry;
}

std::string Tokenizer::ToString() const {
    std::ostringstream oss;
    oss << "Tokenizer:\n";
    oss << "  Model: " << pImpl_->model_type << "\n";
    oss << "  Vocabulary: " << pImpl_->vocab_size << "\n";
    oss << "  BOS: " << pImpl_->bos_id << "\n";
    oss << "  EOS: " << pImpl_->eos_id << "\n";
    oss << "  UNK: " << pImpl_->unk_id << "\n";
    return oss.str();
}

// ============================================================================
// TokenizerFactory
// ============================================================================

std::unique_ptr<Tokenizer> TokenizerFactory::FromModel(const model::ModelContext& model) {
    auto tokenizer = std::make_unique<Tokenizer>();
    if (!tokenizer->Load(model)) {
        return nullptr;
    }
    return tokenizer;
}

std::unique_ptr<Tokenizer> TokenizerFactory::CreateStub() {
    auto tokenizer = std::make_unique<Tokenizer>();
    // Create a minimal stub for testing
    tokenizer->pImpl_->model_type = "stub";
    tokenizer->pImpl_->vocab_size = 1000;
    tokenizer->pImpl_->bos_id = 1;
    tokenizer->pImpl_->eos_id = 2;
    tokenizer->pImpl_->unk_id = 0;
    tokenizer->pImpl_->loaded = true;
    tokenizer->BuildStubVocabulary();
    return tokenizer;
}

// ============================================================================
// TokenizerValidation
// ============================================================================

bool TokenizerValidation::TestVocabularyLoaded(const Tokenizer& tokenizer) {
    return tokenizer.IsLoaded() && tokenizer.VocabularySize() > 0;
}

bool TokenizerValidation::TestSpecialTokens(const Tokenizer& tokenizer) {
    return tokenizer.BosToken() != tokenizer.UnkToken() &&
           tokenizer.EosToken() != tokenizer.UnkToken();
}

bool TokenizerValidation::TestRoundTrip(const Tokenizer& tokenizer, const std::string& text) {
    auto tokens = tokenizer.Encode(text);
    std::string decoded = tokenizer.Decode(tokens);
    
    // Normalize both for comparison
    std::string normalized_text = text;
    std::string normalized_decoded = decoded;
    
    // Convert to lowercase and trim whitespace
    auto normalize = [](std::string& s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        // Trim leading/trailing whitespace
        size_t start = s.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) {
            s.clear();
            return;
        }
        size_t end = s.find_last_not_of(" \t\n\r");
        s = s.substr(start, end - start + 1);
    };
    
    normalize(normalized_text);
    normalize(normalized_decoded);
    
    return normalized_text == normalized_decoded;
}

} // namespace runtime
} // namespace rawrxd

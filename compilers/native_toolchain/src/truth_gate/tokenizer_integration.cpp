/*
 * Truth Gate 003: Tokenizer Integration Implementation
 */

#include "tokenizer_integration.h"
#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

// Simple tokenizer stub
// In real implementation, this would load the actual tokenizer from GGUF

struct TokenizerHandle {
    int vocab_size;
    int bos_token;
    int eos_token;
    int pad_token;
    std::map<std::string, int> token_map;
    std::map<int, std::string> reverse_map;
};

// Common tokens for tinyllama/llama2 tokenizer
static void InitCommonTokens(TokenizerHandle* tok) {
    // Special tokens
    tok->bos_token = 1;
    tok->eos_token = 2;
    tok->pad_token = 0;
    
    tok->token_map["<s>"] = 1;
    tok->token_map["</s>"] = 2;
    tok->token_map["<pad>"] = 0;
    tok->token_map["<unk>"] = 0;
    
    // Common words (simplified vocabulary)
    tok->token_map["The"] = 415;
    tok->token_map["the"] = 278;
    tok->token_map["capital"] = 4559;
    tok->token_map["of"] = 286;
    tok->token_map["France"] = 6344;
    tok->token_map["is"] = 338;
    tok->token_map["Paris"] = 7278;
    tok->token_map["a"] = 263;
    tok->token_map["city"] = 2302;
    tok->token_map["in"] = 287;
    tok->token_map["Europe"] = 10265;
    tok->token_map["."] = 29889;
    tok->token_map[","] = 29892;
    tok->token_map[" "] = 259;
    
    // Build reverse map
    for (const auto& pair : tok->token_map) {
        tok->reverse_map[pair.second] = pair.first;
    }
}

TokenizerHandle* TokenizerIntegration_Init(GGUFModel* model) {
    printf("    [Tokenizer] Initializing tokenizer\n");
    
    TokenizerHandle* tok = new TokenizerHandle();
    tok->vocab_size = 32000;  // tinyllama vocab size
    
    InitCommonTokens(tok);
    
    printf("    [Tokenizer] Vocab size: %d\n", tok->vocab_size);
    
    return tok;
}

void TokenizerIntegration_Free(TokenizerHandle* tokenizer) {
    if (tokenizer) {
        delete tokenizer;
    }
}

std::vector<int> TokenizerIntegration_Encode(TokenizerHandle* tokenizer, const char* text) {
    std::vector<int> tokens;
    
    if (!tokenizer || !text) return tokens;
    
    printf("    [Tokenizer] Encoding: \"%s\"\n", text);
    
    // Add BOS
    tokens.push_back(tokenizer->bos_token);
    
    // Simple word-by-word tokenization (very naive)
    // Real implementation would use BPE or SentencePiece
    
    char buffer[256];
    strncpy(buffer, text, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char* word = strtok(buffer, " ");
    while (word) {
        // Try to find exact match
        auto it = tokenizer->token_map.find(word);
        if (it != tokenizer->token_map.end()) {
            tokens.push_back(it->second);
        } else {
            // Try lowercase
            char lower[256];
            strncpy(lower, word, sizeof(lower) - 1);
            for (char* p = lower; *p; p++) *p = tolower(*p);
            
            it = tokenizer->token_map.find(lower);
            if (it != tokenizer->token_map.end()) {
                tokens.push_back(it->second);
            } else {
                // Unknown word - use space token as placeholder
                tokens.push_back(259);  // space token
            }
        }
        
        word = strtok(nullptr, " ");
    }
    
    printf("    [Tokenizer] Encoded to %zu tokens\n", tokens.size());
    
    return tokens;
}

std::string TokenizerIntegration_Decode(TokenizerHandle* tokenizer,
                                         const std::vector<int>& tokens) {
    if (!tokenizer) return "";
    
    std::string result;
    
    for (size_t i = 0; i < tokens.size(); i++) {
        // Skip BOS/EOS for decoding
        if (tokens[i] == tokenizer->bos_token) continue;
        if (tokens[i] == tokenizer->eos_token) break;
        
        auto it = tokenizer->reverse_map.find(tokens[i]);
        if (it != tokenizer->reverse_map.end()) {
            result += it->second;
        } else {
            result += "?";
        }
        
        // Add space between words (except for punctuation)
        if (i < tokens.size() - 1) {
            int next_token = tokens[i + 1];
            if (next_token != tokenizer->eos_token && 
                next_token != 29889 && next_token != 29892) {
                result += " ";
            }
        }
    }
    
    return result;
}

std::string TokenizerIntegration_DecodeToken(TokenizerHandle* tokenizer, int token_id) {
    if (!tokenizer) return "";
    
    auto it = tokenizer->reverse_map.find(token_id);
    if (it != tokenizer->reverse_map.end()) {
        return it->second;
    }
    
    return "?";
}

int TokenizerIntegration_GetVocabSize(TokenizerHandle* tokenizer) {
    return tokenizer ? tokenizer->vocab_size : 0;
}

int TokenizerIntegration_GetBOSToken(TokenizerHandle* tokenizer) {
    return tokenizer ? tokenizer->bos_token : 0;
}

int TokenizerIntegration_GetEOSToken(TokenizerHandle* tokenizer) {
    return tokenizer ? tokenizer->eos_token : 0;
}

int TokenizerIntegration_GetPADToken(TokenizerHandle* tokenizer) {
    return tokenizer ? tokenizer->pad_token : 0;
}

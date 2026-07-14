/*
 * Truth Gate 003: Tokenizer Integration
 * 
 * Text <-> token ID conversion
 */

#ifndef TOKENIZER_INTEGRATION_H
#define TOKENIZER_INTEGRATION_H

#include <vector>
#include <string>
#include "gguf_integration.h"

// Opaque tokenizer handle
struct TokenizerHandle;

// Initialize tokenizer from model
TokenizerHandle* TokenizerIntegration_Init(GGUFModel* model);

// Free tokenizer
void TokenizerIntegration_Free(TokenizerHandle* tokenizer);

// Encode text to tokens
std::vector<int> TokenizerIntegration_Encode(TokenizerHandle* tokenizer, 
                                              const char* text);

// Decode tokens to text
std::string TokenizerIntegration_Decode(TokenizerHandle* tokenizer,
                                         const std::vector<int>& tokens);

// Decode single token
std::string TokenizerIntegration_DecodeToken(TokenizerHandle* tokenizer, int token_id);

// Get vocab size
int TokenizerIntegration_GetVocabSize(TokenizerHandle* tokenizer);

// Get BOS/EOS/PAD tokens
int TokenizerIntegration_GetBOSToken(TokenizerHandle* tokenizer);
int TokenizerIntegration_GetEOSToken(TokenizerHandle* tokenizer);
int TokenizerIntegration_GetPADToken(TokenizerHandle* tokenizer);

#endif // TOKENIZER_INTEGRATION_H

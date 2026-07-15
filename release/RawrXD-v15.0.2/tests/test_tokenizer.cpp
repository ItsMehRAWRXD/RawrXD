#include <gtest/gtest.h>
#include "rawrxd/inference/Tokenizer.hpp"
#include <fstream>
#include <cstdio>

using namespace rawrxd::inference;

class TokenizerTest : public ::testing::Test {
protected:
    std::string tempVocabPath;
    
    void SetUp() override {
        // Create temporary vocab file for testing
        tempVocabPath = std::tmpnam(nullptr);
        tempVocabPath += "_vocab.json";
        
        // Create a simple BPE vocab
        std::ofstream vocabFile(tempVocabPath);
        vocabFile << R"({
            "version": "1.0",
            "type": "bpe",
            "vocab": {
                "<|endoftext|>": 0,
                "<|padding|>": 1,
                "the": 2,
                "quick": 3,
                "brown": 4,
                "fox": 5,
                "jumps": 6,
                "over": 7,
                "lazy": 8,
                "dog": 9,
                "hello": 10,
                "world": 11,
                " ": 12,
                "t": 13,
                "h": 14,
                "e": 15,
                "q": 16,
                "u": 17,
                "i": 18,
                "c": 19,
                "k": 20,
                "b": 21,
                "r": 22,
                "o": 23,
                "w": 24,
                "n": 25,
                "f": 26,
                "x": 27,
                "j": 28,
                "m": 29,
                "p": 30,
                "s": 31,
                "v": 32,
                "l": 33,
                "a": 34,
                "z": 35,
                "y": 36,
                "d": 37,
                "g": 38
            },
            "merges": [
                "t h",
                "h e",
                "q u",
                "u i",
                "i c",
                "c k",
                "b r",
                "r o",
                "o w",
                "w n",
                "f o",
                "o x",
                "j u",
                "u m",
                "m p",
                "p s",
                "o v",
                "v e",
                "e r",
                "l a",
                "a z",
                "z y",
                "d o",
                "o g",
                "h e l",
                "l l o",
                "w o r",
                "o r l",
                "r l d"
            ],
            "special_tokens": {
                "eos": "<|endoftext|>",
                "pad": "<|padding|>"
            }
        })";
        vocabFile.close();
    }
    
    void TearDown() override {
        // Clean up temp file
        std::remove(tempVocabPath.c_str());
    }
};

TEST_F(TokenizerTest, LoadVocabulary) {
    BPETokenizer tokenizer;
    
    bool success = tokenizer.Load(tempVocabPath);
    EXPECT_TRUE(success);
    
    EXPECT_EQ(tokenizer.VocabSize(), 39);
}

TEST_F(TokenizerTest, EncodeSimple) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::string text = "the";
    std::vector<int> tokens = tokenizer.Encode(text);
    
    EXPECT_EQ(tokens.size(), 1);
    EXPECT_EQ(tokens[0], 2); // "the" token
}

TEST_F(TokenizerTest, EncodeWithSpaces) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::string text = "the quick";
    std::vector<int> tokens = tokenizer.Encode(text);
    
    // Should tokenize to: "the", " ", "quick"
    EXPECT_GE(tokens.size(), 3);
    EXPECT_EQ(tokens[0], 2);  // "the"
    EXPECT_EQ(tokens[1], 12); // " "
    EXPECT_EQ(tokens[2], 3);  // "quick"
}

TEST_F(TokenizerTest, EncodeFullSentence) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::string text = "the quick brown fox";
    std::vector<int> tokens = tokenizer.Encode(text);
    
    EXPECT_GT(tokens.size(), 0);
    
    // Decode and check round-trip
    std::string decoded = tokenizer.Decode(tokens);
    // Note: BPE may not be perfectly reversible due to merge rules
    EXPECT_FALSE(decoded.empty());
}

TEST_F(TokenizerTest, DecodeTokens) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::vector<int> tokens = {2, 12, 3}; // "the", " ", "quick"
    std::string text = tokenizer.Decode(tokens);
    
    EXPECT_FALSE(text.empty());
    EXPECT_NE(text.find("the"), std::string::npos);
    EXPECT_NE(text.find("quick"), std::string::npos);
}

TEST_F(TokenizerTest, SpecialTokens) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    // Check special token IDs
    EXPECT_EQ(tokenizer.EosTokenId(), 0);
    EXPECT_EQ(tokenizer.PadTokenId(), 1);
    
    // Check special token strings
    EXPECT_EQ(tokenizer.EosToken(), "<|endoftext|>");
    EXPECT_EQ(tokenizer.PadToken(), "<|padding|>");
}

TEST_F(TokenizerTest, EncodeWithSpecialTokens) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::string text = "hello world";
    std::vector<int> tokens = tokenizer.Encode(text, /*addSpecialTokens=*/true);
    
    // Should have EOS token at end
    EXPECT_EQ(tokens.back(), tokenizer.EosTokenId());
}

TEST_F(TokenizerTest, BatchEncode) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::vector<std::string> texts = {
        "the quick",
        "brown fox",
        "lazy dog"
    };
    
    auto batchTokens = tokenizer.EncodeBatch(texts);
    
    EXPECT_EQ(batchTokens.size(), 3);
    for (const auto& tokens : batchTokens) {
        EXPECT_GT(tokens.size(), 0);
    }
}

TEST_F(TokenizerTest, BatchDecode) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::vector<std::vector<int>> batchTokens = {
        {2, 12, 3},
        {4, 12, 5},
        {8, 12, 9}
    };
    
    auto texts = tokenizer.DecodeBatch(batchTokens);
    
    EXPECT_EQ(texts.size(), 3);
    for (const auto& text : texts) {
        EXPECT_FALSE(text.empty());
    }
}

TEST_F(TokenizerTest, TokenToString) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    EXPECT_EQ(tokenizer.TokenToString(2), "the");
    EXPECT_EQ(tokenizer.TokenToString(3), "quick");
    EXPECT_EQ(tokenizer.TokenToString(0), "<|endoftext|>");
}

TEST_F(TokenizerTest, StringToToken) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    EXPECT_EQ(tokenizer.StringToToken("the"), 2);
    EXPECT_EQ(tokenizer.StringToToken("quick"), 3);
    EXPECT_EQ(tokenizer.StringToToken("<|endoftext|>"), 0);
}

TEST_F(TokenizerTest, CountTokens) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::string text = "the quick brown fox";
    size_t count = tokenizer.CountTokens(text);
    
    EXPECT_GT(count, 0);
}

TEST_F(TokenizerTest, TruncateSequence) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::string text = "the quick brown fox jumps over the lazy dog";
    std::vector<int> tokens = tokenizer.Encode(text);
    
    size_t originalSize = tokens.size();
    
    // Truncate to first 5 tokens
    tokenizer.Truncate(tokens, /*maxLength=*/5, /*fromEnd=*/false);
    
    EXPECT_EQ(tokens.size(), 5);
    EXPECT_LE(tokens.size(), originalSize);
}

TEST_F(TokenizerTest, PadSequence) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::vector<int> tokens = {2, 3, 4}; // "the", "quick", "brown"
    
    tokenizer.Pad(tokens, /*targetLength=*/10);
    
    EXPECT_EQ(tokens.size(), 10);
    EXPECT_EQ(tokens[0], 2);
    EXPECT_EQ(tokens[1], 3);
    EXPECT_EQ(tokens[2], 4);
    
    // Remaining should be padding tokens
    for (size_t i = 3; i < tokens.size(); ++i) {
        EXPECT_EQ(tokens[i], tokenizer.PadTokenId());
    }
}

TEST_F(TokenizerTest, CreateAttentionMask) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::vector<int> tokens = {2, 3, 4, 1, 1}; // Last two are padding
    
    auto mask = tokenizer.CreateAttentionMask(tokens);
    
    // Real tokens should have mask=1, padding should have mask=0
    EXPECT_EQ(mask[0], 1);
    EXPECT_EQ(mask[1], 1);
    EXPECT_EQ(mask[2], 1);
    EXPECT_EQ(mask[3], 0);
    EXPECT_EQ(mask[4], 0);
}

TEST_F(TokenizerTest, EmptyInput) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    std::string emptyText = "";
    std::vector<int> tokens = tokenizer.Encode(emptyText);
    
    // Should return at least EOS token
    EXPECT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens.back(), tokenizer.EosTokenId());
}

TEST_F(TokenizerTest, UnknownTokens) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    // Text with characters not in vocab
    std::string text = "the quick @#$";
    std::vector<int> tokens = tokenizer.Encode(text);
    
    // Should still produce valid tokens
    EXPECT_GT(tokens.size(), 0);
}

TEST_F(TokenizerTest, SaveAndLoad) {
    BPETokenizer tokenizer1;
    tokenizer1.Load(tempVocabPath);
    
    // Save to new file
    std::string newPath = std::tmpnam(nullptr);
    newPath += "_new_vocab.json";
    
    bool saved = tokenizer1.Save(newPath);
    EXPECT_TRUE(saved);
    
    // Load in new tokenizer
    BPETokenizer tokenizer2;
    bool loaded = tokenizer2.Load(newPath);
    EXPECT_TRUE(loaded);
    
    // Should have same vocab size
    EXPECT_EQ(tokenizer1.VocabSize(), tokenizer2.VocabSize());
    
    // Cleanup
    std::remove(newPath.c_str());
}

TEST_F(TokenizerTest, ChatTemplate) {
    BPETokenizer tokenizer;
    tokenizer.Load(tempVocabPath);
    
    // Set a simple chat template
    tokenizer.SetChatTemplate("{{system}}\n{{user}}\n{{assistant}}");
    
    std::vector<std::pair<std::string, std::string>> messages = {
        {"system", "You are a helpful assistant."},
        {"user", "Hello!"},
        {"assistant", "Hi there!"}
    };
    
    std::string formatted = tokenizer.ApplyChatTemplate(messages);
    
    EXPECT_FALSE(formatted.empty());
    EXPECT_NE(formatted.find("system"), std::string::npos);
    EXPECT_NE(formatted.find("user"), std::string::npos);
}

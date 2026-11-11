// REAP tokenizer metadata inspector — uses existing GGUFLoader to read
// tokenizer metadata keys from a GGUF shard.
#include "deep2/GGUFLoader.hpp"
#include <cstdio>
#include <string>
#include <vector>
#include <iostream>

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] :
        "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M\\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf";

    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        std::cerr << "LOAD_FAILED: " << loader.error() << "\n";
        return 2;
    }

    // Check all known tokenizer metadata keys
    const char* keys[] = {
        "tokenizer.ggml.model",
        "tokenizer.ggml.tokens",
        "tokenizer.ggml.scores",
        "tokenizer.ggml.merges",
        "tokenizer.ggml.bos_token_id",
        "tokenizer.ggml.eos_token_id",
        "tokenizer.ggml.unknown_token_id",
        "tokenizer.ggml.padding_token_id",
        "tokenizer.chat_template",
        "tokenizer.ggml.add_bos_token",
        "tokenizer.ggml.add_eos_token",
    };

    for (const char* key : keys) {
        if (loader.hasMeta(key)) {
            std::string val = loader.getMetaString(key, "(no string)");
            std::vector<std::string> arr = loader.getMetaStringArray(key, std::vector<std::string>());
            std::cout << key << ":\n";
            std::cout << "  hasMeta=true\n";
            std::cout << "  getMetaString=\"" << val << "\"\n";
            std::cout << "  getMetaStringArray count=" << arr.size() << "\n";
            if (!arr.empty() && arr.size() <= 5) {
                for (size_t i = 0; i < arr.size(); ++i) {
                    std::cout << "    [" << i << "] = \"" << arr[i] << "\"\n";
                }
            } else if (!arr.empty()) {
                std::cout << "    [0] = \"" << arr[0] << "\" (truncated, " << arr.size() << " items)\n";
            }
            // Try int values too
            int64_t ival = loader.getMetaInt(key, -1);
            if (ival != -1) {
                std::cout << "  getMetaInt=" << ival << "\n";
            }
            std::cout << "\n";
        } else {
            std::cout << key << ": hasMeta=false\n";
        }
    }

    // Also list all metadata keys containing "tokenizer"
    std::cout << "\n=== All metadata keys ===\n";
    // We can't iterate all keys with GGUFLoader API, but let's check a few more
    const char* moreKeys[] = {
        "tokenizer.ggml.tokens",
        "tokenizer.ggml.merges",
    };
    for (const char* key : moreKeys) {
        std::vector<std::string> arr;
        if (loader.getMetaStringArray(key, arr)) {
            std::cout << key << " array size: " << arr.size() << "\n";
        }
    }

    return 0;
}

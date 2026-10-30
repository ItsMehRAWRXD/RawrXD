/**
 * @file test_ollama_chat.cpp
 * @brief Direct test of generateOllamaModel function
 */

#include "win32app/Win32IDE.cpp"
#include <iostream>
#include <string>

int main() {
    std::cout << "=== Testing generateOllamaModel directly ===\n";
    
    // Test with nemotron-3-nano:4b
    std::string model = "nemotron-3-nano:4b";
    std::string prompt = "Reply with exactly RAWRXD_CHAT_OK";
    int maxTokens = 128;
    std::string baseUrl = "";  // Use default
    
    std::cout << "Model: " << model << "\n";
    std::cout << "Prompt: " << prompt << "\n";
    std::cout << "Max tokens: " << maxTokens << "\n\n";
    
    // Call the function
    std::string result = generateOllamaModel(baseUrl, model, prompt, maxTokens);
    
    std::cout << "\n=== Result ===\n";
    if (result.empty()) {
        std::cout << "EMPTY RESPONSE (check ollama_debug.log for details)\n";
        return 1;
    } else {
        std::cout << "Response: " << result << "\n";
        std::cout << "Length: " << result.length() << "\n";
        return 0;
    }
}
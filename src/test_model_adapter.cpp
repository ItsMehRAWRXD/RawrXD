// Test suite for model_adapter_v2.hpp
// Compile: cl /EHsc /std:c++17 test_model_adapter.cpp /Fe:test_adapter.exe

#include "model_adapter_v2.hpp"
#include <iostream>
#include <assert>
#include <string_view>

using namespace RawrXD;

// ============================================================================
// Test Helpers
// ============================================================================
int testsPassed = 0;
int testsFailed = 0;

void Test(bool condition, const char* name) {
    if (condition) {
        std::cout << "[PASS] " << name << std::endl;
        testsPassed++;
    } else {
        std::cout << "[FAIL] " << name << std::endl;
        testsFailed++;
    }
}

// ============================================================================
// Model Family Detection Tests
// ============================================================================
void TestModelFamilyDetection() {
    std::cout << "\n=== Model Family Detection ===" << std::endl;
    
    Test(DetectModelFamily("bigdaddyg:latest") == ModelFamily::BigDaddyG, "bigdaddyg:latest");
    Test(DetectModelFamily("bigdaddyg:v2") == ModelFamily::BigDaddyG, "bigdaddyg:v2");
    Test(DetectModelFamily("phi3:mini") == ModelFamily::Phi3, "phi3:mini");
    Test(DetectModelFamily("Phi-3-medium") == ModelFamily::Phi3, "Phi-3-medium (case insensitive)");
    Test(DetectModelFamily("llama3.2:3b") == ModelFamily::Llama3, "llama3.2:3b");
    Test(DetectModelFamily("llama-3-8b") == ModelFamily::Llama3, "llama-3-8b");
    Test(DetectModelFamily("llama2:7b") == ModelFamily::Llama2, "llama2:7b");
    Test(DetectModelFamily("mistral:latest") == ModelFamily::Mistral, "mistral:latest");
    Test(DetectModelFamily("dolphin-mistral") == ModelFamily::Mistral, "dolphin-mistral");
    Test(DetectModelFamily("qwen2.5:14b") == ModelFamily::Qwen, "qwen2.5:14b");
    Test(DetectModelFamily("gemma3:4b") == ModelFamily::Gemma, "gemma3:4b");
    Test(DetectModelFamily("codestral:latest") == ModelFamily::Codestral, "codestral:latest");
    Test(DetectModelFamily("unknown-model") == ModelFamily::Generic, "unknown-model (generic fallback)");
}

// ============================================================================
// Prompt Formatter Tests
// ============================================================================
void TestPromptFormatters() {
    std::cout << "\n=== Prompt Formatters ===" << std::endl;
    
    // Mistral/LLaMA-2
    {
        MistralLlama2Formatter fmt;
        std::string result = fmt.Format("", "Hello");
        Test(result == "[INST] Hello [/INST]", "Mistral: no system prompt");
        
        result = fmt.Format("You are helpful.", "Hello");
        Test(result.find("[INST] <<SYS>>") != std::string::npos, "Mistral: with system prompt");
        Test(result.find("You are helpful.") != std::string::npos, "Mistral: system content");
    }
    
    // Phi-3
    {
        Phi3Formatter fmt;
        std::string result = fmt.Format("", "Hello");
        Test(result.find("<|user|>") != std::string::npos, "Phi3: user tag");
        Test(result.find("<|assistant|>") != std::string::npos, "Phi3: assistant tag");
    }
    
    // LLaMA-3
    {
        Llama3Formatter fmt;
        std::string result = fmt.Format("", "Hello");
        Test(result.find("<|begin_of_text|>") != std::string::npos, "Llama3: begin token");
        Test(result.find("<|eot_id|>") != std::string::npos, "Llama3: eot token");
    }
}

// ============================================================================
// Output Parser Tests
// ============================================================================
void TestOutputParsers() {
    std::cout << "\n=== Output Parsers ===" << std::endl;
    
    // BigDaddyG parser
    {
        BigDaddyGParser parser;
        
        // Basic [TEXT]...[END]
        std::string result = parser.Parse("[TEXT]Hello world[END]");
        Test(result == "Hello world", "BigDaddyG: basic [TEXT]...[END]");
        
        // With whitespace
        result = parser.Parse("[TEXT]  Hello world  [END]");
        Test(result == "Hello world", "BigDaddyG: trimmed whitespace");
        
        // [/TEXT] variant
        result = parser.Parse("[TEXT]Hello world[/TEXT]");
        Test(result == "Hello world", "BigDaddyG: [/TEXT] variant");
        
        // Leading thinking tokens
        result = parser.Parse("...thinking...[TEXT]Hello[END]");
        Test(result == "Hello", "BigDaddyG: with thinking tokens");
        
        // No markers - pass through
        result = parser.Parse("Plain text output");
        Test(result == "Plain text output", "BigDaddyG: no markers (pass-through)");
        
        // Empty
        result = parser.Parse("");
        Test(result == "", "BigDaddyG: empty input");
        
        // Only whitespace
        result = parser.Parse("   ");
        Test(result == "   ", "BigDaddyG: only whitespace");
        
        // Missing [END]
        result = parser.Parse("[TEXT]Hello world");
        Test(result == "[TEXT]Hello world", "BigDaddyG: missing [END] (pass-through)");
        
        // Nested markers (edge case)
        result = parser.Parse("[TEXT]Outer [TEXT]Inner[/TEXT] Outer[END]");
        Test(result.find("Outer") != std::string::npos, "BigDaddyG: nested markers");
    }
    
    // Generic parser
    {
        GenericParser parser;
        std::string result = parser.Parse("Any text");
        Test(result == "Any text", "Generic: pass-through");
    }
}

// ============================================================================
// Streaming Parser Tests
// ============================================================================
void TestStreamingParsers() {
    std::cout << "\n=== Streaming Parsers ===" << std::endl;
    
    // BigDaddyG streaming
    {
        auto parser = std::make_unique<BigDaddyGStreamingParser>();
        
        // Complete marker in one chunk
        parser->Feed("[TEXT]Hello[END]");
        Test(parser->HasOutput(), "Streaming: complete marker");
        Test(parser->Consume() == "Hello", "Streaming: extracted content");
        
        parser->Reset();
        
        // Split marker: [TE in first chunk
        parser->Feed("[TE");
        Test(!parser->HasOutput(), "Streaming: partial marker (no output yet)");
        
        // XT]Hello[END] in second chunk
        parser->Feed("XT]Hello[END]");
        Test(parser->HasOutput(), "Streaming: completed split marker");
        Test(parser->Consume() == "Hello", "Streaming: content after split");
        
        parser->Reset();
        
        // Multiple chunks
        parser->Feed("[TEXT]Hello ");
        parser->Feed("world");
        parser->Feed("[END]");
        Test(parser->Consume() == "Hello world", "Streaming: multiple chunks");
        
        parser->Reset();
        
        // Finish without end marker
        parser->Feed("[TEXT]Partial content");
        parser->Finish();
        Test(parser->HasOutput(), "Streaming: finish flushes content");
        Test(parser->Consume().find("Partial") != std::string::npos, "Streaming: partial content on finish");
    }
}

// ============================================================================
// Integration Tests
// ============================================================================
void TestIntegration() {
    std::cout << "\n=== Integration Tests ===" << std::endl;
    
    // Format + Parse round-trip
    {
        std::string model = "bigdaddyg:latest";
        std::string prompt = "Hello";
        
        std::string formatted = FormatModelPrompt(model, prompt);
        Test(formatted.find("[INST]") != std::string::npos, "Integration: bigdaddyg formatted");
        
        std::string rawOutput = "[TEXT]Greetings![END]";
        std::string parsed = ParseModelOutput(model, rawOutput);
        Test(parsed == "Greetings!", "Integration: bigdaddyg parsed");
    }
    
    // Phi-3 (no special parsing needed)
    {
        std::string model = "phi3:mini";
        std::string formatted = FormatModelPrompt(model, "Hello");
        Test(formatted.find("<|user|>") != std::string::npos, "Integration: phi3 formatted");
        
        std::string parsed = ParseModelOutput(model, "Clean output");
        Test(parsed == "Clean output", "Integration: phi3 pass-through");
    }
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Model Adapter V2 Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    TestModelFamilyDetection();
    TestPromptFormatters();
    TestOutputParsers();
    TestStreamingParsers();
    TestIntegration();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return testsFailed > 0 ? 1 : 0;
}

// test_chat_template_unit.cpp - Unit test for chat template formatting (no generation)
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include "ChatTemplate.hpp"

using namespace Deep2;

static bool testPhi3() {
    printf("=== Phi-3 Template Test ===\n");
    ChatTemplate tmpl;
    tmpl.init(ChatTemplateType::PHI3);
    
    std::vector<ChatMessage> messages = {
        {"system", "You are a helpful assistant.", ""},
        {"user", "hello", ""},
    };
    
    std::string formatted = tmpl.format(messages);
    printf("Formatted: %s\n", formatted.c_str());
    
    std::string expected = "<|system|>\nYou are a helpful assistant.<|end|>"
                           "<|user|>\nhello<|end|>"
                           "<|assistant|>";
    
    if (formatted == expected) {
        printf("[PASS] Phi-3 template matches expected\n");
        return true;
    } else {
        printf("[FAIL] Phi-3 template mismatch\n");
        printf("Expected: %s\n", expected.c_str());
        return false;
    }
}

static bool testLlama3() {
    printf("\n=== Llama-3 Template Test ===\n");
    ChatTemplate tmpl;
    tmpl.init(ChatTemplateType::LLAMA3);
    
    std::vector<ChatMessage> messages = {
        {"system", "You are a helpful assistant.", ""},
        {"user", "hello", ""},
    };
    
    std::string formatted = tmpl.format(messages);
    printf("Formatted: %s\n", formatted.c_str());
    
    std::string expected = "<|begin_of_text|>"
                           "<|start_header_id|>system<|end_header_id|>\n\n"
                           "You are a helpful assistant.<|eot_id|>"
                           "<|start_header_id|>user<|end_header_id|>\n\n"
                           "hello<|eot_id|>"
                           "<|start_header_id|>assistant<|end_header_id|>\n\n";
    
    if (formatted == expected) {
        printf("[PASS] Llama-3 template matches expected\n");
        return true;
    } else {
        printf("[FAIL] Llama-3 template mismatch\n");
        printf("Expected: %s\n", expected.c_str());
        return false;
    }
}

static bool testQwen() {
    printf("\n=== Qwen Template Test ===\n");
    ChatTemplate tmpl;
    tmpl.init(ChatTemplateType::QWEN2);
    
    std::vector<ChatMessage> messages = {
        {"system", "You are a helpful assistant.", ""},
        {"user", "hello", ""},
    };
    
    std::string formatted = tmpl.format(messages);
    printf("Formatted: %s\n", formatted.c_str());
    
    std::string expected = "<|im_start|>system\n"
                           "You are a helpful assistant.<|im_end|>\n"
                           "<|im_start|>user\n"
                           "hello<|im_end|>\n"
                           "<|im_start|>assistant\n";
    
    if (formatted == expected) {
        printf("[PASS] Qwen template matches expected\n");
        return true;
    } else {
        printf("[FAIL] Qwen template mismatch\n");
        printf("Expected: %s\n", expected.c_str());
        return false;
    }
}

static bool testMistral() {
    printf("\n=== Mistral Template Test ===\n");
    ChatTemplate tmpl;
    tmpl.init(ChatTemplateType::MISTRAL);
    
    std::vector<ChatMessage> messages = {
        {"user", "hello", ""},
    };
    
    std::string formatted = tmpl.format(messages);
    printf("Formatted: %s\n", formatted.c_str());
    
    std::string expected = "[INST] hello [/INST]";
    
    if (formatted == expected) {
        printf("[PASS] Mistral template matches expected\n");
        return true;
    } else {
        printf("[FAIL] Mistral template mismatch\n");
        printf("Expected: %s\n", expected.c_str());
        return false;
    }
}

static bool testGemma() {
    printf("\n=== Gemma Template Test ===\n");
    ChatTemplate tmpl;
    tmpl.init(ChatTemplateType::GEMMA2);
    
    std::vector<ChatMessage> messages = {
        {"user", "hello", ""},
    };
    
    std::string formatted = tmpl.format(messages);
    printf("Formatted: %s\n", formatted.c_str());
    
    std::string expected = "<start_of_turn>user\n"
                           "hello<end_of_turn>\n"
                           "<start_of_turn>model\n";
    
    if (formatted == expected) {
        printf("[PASS] Gemma template matches expected\n");
        return true;
    } else {
        printf("[FAIL] Gemma template mismatch\n");
        printf("Expected: %s\n", expected.c_str());
        return false;
    }
}

static bool testDetection() {
    printf("\n=== Template Detection Test ===\n");
    
    // Test Phi-3 detection from template string
    std::string phi3Tmpl = "{% for message in messages %}{% if message['role'] == 'system' %}<|system|>{{ message['content'] }}<|end|>{% elif message['role'] == 'user' %}<|user|>{{ message['content'] }}<|end|>{% elif message['role'] == 'assistant' %}<|assistant|>{{ message['content'] }}<|end|>{% endif %}{% endfor %}<|assistant|>";
    
    ChatTemplateType detected = ChatTemplate::detectFromTemplate(phi3Tmpl);
    if (detected == ChatTemplateType::PHI3) {
        printf("[PASS] Detected Phi-3 from Jinja template\n");
    } else {
        printf("[FAIL] Expected Phi-3, got %d\n", static_cast<int>(detected));
        return false;
    }
    
    // Test Llama-3 detection
    std::string llama3Tmpl = "<|begin_of_text|>{% for message in messages %}<|start_header_id|>{{ message['role'] }}<|end_header_id|>\n\n{{ message['content'] }}<|eot_id|>{% endfor %}<|start_header_id|>assistant<|end_header_id|>\n\n";
    detected = ChatTemplate::detectFromTemplate(llama3Tmpl);
    if (detected == ChatTemplateType::LLAMA3) {
        printf("[PASS] Detected Llama-3 from Jinja template\n");
    } else {
        printf("[FAIL] Expected Llama-3, got %d\n", static_cast<int>(detected));
        return false;
    }
    
    // Test model name detection
    detected = ChatTemplate::detectFromModel("phi3", "Phi-3-mini");
    if (detected == ChatTemplateType::PHI3) {
        printf("[PASS] Detected Phi-3 from model name\n");
    } else {
        printf("[FAIL] Expected Phi-3 from model name, got %d\n", static_cast<int>(detected));
        return false;
    }
    
    detected = ChatTemplate::detectFromModel("llama", "llama-3-8b");
    if (detected == ChatTemplateType::LLAMA3) {
        printf("[PASS] Detected Llama-3 from model name\n");
    } else {
        printf("[FAIL] Expected Llama-3 from model name, got %d\n", static_cast<int>(detected));
        return false;
    }
    
    return true;
}

static bool testEndOfTurn() {
    printf("\n=== End-of-Turn Detection Test ===\n");
    
    ChatTemplate phi3Tmpl;
    phi3Tmpl.init(ChatTemplateType::PHI3);
    
    if (phi3Tmpl.isEndOfTurn("<|end|>")) {
        printf("[PASS] Phi-3 detects <|end|> as EOT\n");
    } else {
        printf("[FAIL] Phi-3 should detect <|end|> as EOT\n");
        return false;
    }
    
    ChatTemplate llama3Tmpl;
    llama3Tmpl.init(ChatTemplateType::LLAMA3);
    
    if (llama3Tmpl.isEndOfTurn("<|eot_id|>")) {
        printf("[PASS] Llama-3 detects <|eot_id|> as EOT\n");
    } else {
        printf("[FAIL] Llama-3 should detect <|eot_id|> as EOT\n");
        return false;
    }
    
    return true;
}

int main() {
    printf("[TEST] Chat Template Unit Tests\n\n");
    
    int passed = 0;
    int total = 0;
    
    #define RUN_TEST(name) \
        do { \
            total++; \
            if (test##name()) passed++; \
        } while(0)
    
    RUN_TEST(Phi3);
    RUN_TEST(Llama3);
    RUN_TEST(Qwen);
    RUN_TEST(Mistral);
    RUN_TEST(Gemma);
    RUN_TEST(Detection);
    RUN_TEST(EndOfTurn);
    
    printf("\n========================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("========================================\n");
    
    return (passed == total) ? 0 : 1;
}

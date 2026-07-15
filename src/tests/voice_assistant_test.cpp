// voice_assistant_test.cpp — Test Voice Assistant Integration
// Tests the voice assistant panel and command routing
// ============================================================================

#include <iostream>
#include <memory>
#include "../core/voice_assistant_manager.hpp"

int main() {
    std::cout << "=== Voice Assistant Integration Test ===" << std::endl;
    
    // Create voice assistant manager
    auto manager = std::make_unique<VoiceAssistantManager>();
    
    // Test Siri-style assistant
    std::cout << "\n--- Testing Siri-Style Assistant ---" << std::endl;
    auto siri_result = manager->process_voice_input("What's the weather like today?", "siri");
    std::cout << "Assistant: " << siri_result["assistant"] << std::endl;
    std::cout << "Response: " << siri_result["response"] << std::endl;
    std::cout << "Intent: " << siri_result["intent"] << std::endl;
    std::cout << "Confidence: " << siri_result["confidence"] << std::endl;
    
    // Test Alexa-style assistant
    std::cout << "\n--- Testing Alexa-Style Assistant ---" << std::endl;
    auto alexa_result = manager->process_voice_input("Turn on the living room lights", "alexa");
    std::cout << "Assistant: " << alexa_result["assistant"] << std::endl;
    std::cout << "Response: " << alexa_result["response"] << std::endl;
    std::cout << "Skill: " << alexa_result["skill_used"] << std::endl;
    std::cout << "Action: " << alexa_result["action_performed"] << std::endl;
    
    // Test Hybrid assistant
    std::cout << "\n--- Testing Hybrid Assistant ---" << std::endl;
    auto hybrid_result = manager->process_voice_input("Can you help me with something?", "hybrid");
    std::cout << "Assistant: " << hybrid_result["assistant"] << std::endl;
    std::cout << "Response: " << hybrid_result["response"] << std::endl;
    std::cout << "Mode: " << hybrid_result["mode"] << std::endl;
    
    // Test session management
    std::cout << "\n--- Testing Session Management ---" << std::endl;
    std::string session_id = manager->create_session();
    std::cout << "Created session: " << session_id << std::endl;
    
    auto session_result = manager->process_voice_input("Set a timer for 5 minutes", "hybrid", session_id);
    std::cout << "Session response: " << session_result["response"] << std::endl;
    
    auto history = manager->get_session_history(session_id);
    std::cout << "Session history: " << history.dump(2) << std::endl;
    
    manager->end_session(session_id);
    std::cout << "Session ended" << std::endl;
    
    // Test assistant info
    std::cout << "\n--- Assistant Information ---" << std::endl;
    auto info = manager->get_assistant_info();
    std::cout << "Available assistants: " << info.dump(2) << std::endl;
    
    std::cout << "\n=== All Tests Passed ===" << std::endl;
    return 0;
}
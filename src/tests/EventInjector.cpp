#include "EventInjector.h"
#include "../telemetry/FeedbackCollector.h"
#include <fstream>
#include <json/json.h>
#include <thread>
#include <chrono>

namespace RawrXD::E2E {

bool EventInjector::ReplayTrace(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    
    if (!Json::parseFromStream(builder, file, &root, &errors)) {
        return false;
    }
    
    auto& collector = FeedbackCollector::instance();
    size_t event_count = 0;
    
    // Process events array
    const auto& events = root["events"];
    for (const auto& event : events) {
        std::string signal_str = event["signal"].asString();
        float confidence = event["confidence"].asFloat();
        std::string context = event["context_hash"].asString();
        int delay_ms = event.get("delay_ms", 0).asInt();
        
        // Map string to enum
        InteractionSignal signal;
        if (signal_str == "TAB_ACCEPT") signal = InteractionSignal::TAB_ACCEPT;
        else if (signal_str == "IGNORE") signal = InteractionSignal::IGNORE;
        else if (signal_str == "DISMISS") signal = InteractionSignal::DISMISS;
        else if (signal_str == "EDIT_AFTER_ACCEPT") signal = InteractionSignal::EDIT_AFTER_ACCEPT;
        else continue;
        
        // Inject with optional delay simulation
        Pulse(signal, confidence);
        event_count++;
        
        // Simulate realistic timing if delay specified
        if (delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
    }
    
    return event_count > 0;
}

void EventInjector::Pulse(const InteractionSignal& signal, float confidence) {
    auto& collector = FeedbackCollector::instance();
    
    // Generate synthetic context hash based on signal type
    std::string context_hash = "e2e_test_" + std::to_string(static_cast<int>(signal)) + 
                               "_" + std::to_string(static_cast<int>(confidence * 100));
    
    // Record the interaction
    collector.record(
        signal,
        context_hash,
        "synthetic_suggestion",  // suggestion_text
        0.75f,                   // trie_score
        confidence,              // semantic_score
        confidence,              // final_score
        0                        // edit_distance
    );
}

} // namespace RawrXD::E2E

#include "telemetry/FeedbackCollector.h"
#include "fusion/AdaptiveFusionEngine.h"
#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>
#include <vector>

namespace RawrXD {

void RunFusionIntegrationTest() {
    std::cout << "[Test] Starting Fusion Engine Integration Test..." << std::endl;

    auto& collector = Telemetry::FeedbackCollector::instance();
    auto& fusion = Fusion::AdaptiveFusionEngine::instance();

    // Initialize the fusion engine
    Fusion::AdaptiveFusionConfig config;
    config.initial_alpha = 0.5;
    config.learning_rate = 0.01;
    fusion.initialize(config);

    // 1. Verify initial state
    bool confidence = false;
    float initial_weight = fusion.get_weight_confident(confidence);
    std::cout << "[Test] Initial Alpha Weight: " << initial_weight << std::endl;

    // 2. Wire the feedback loop
    collector.SetHandler([&](const Telemetry::FeedbackEntry& entry) {
        fusion.update_from_signal(entry.signal, entry.context_hash, 
                                     entry.trie_score, entry.semantic_score);
    });

    // 3. Simulate burst of feedback
    const int TEST_ITERATIONS = 100;
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        Telemetry::FeedbackEntry entry;
        entry.context_hash = "test_case_" + std::to_string(i);
        // Toggle reward to see if weights move
        entry.signal = (i % 2 == 0) ? 
            Telemetry::InteractionSignal::TAB_ACCEPT : 
            Telemetry::InteractionSignal::IGNORE_5S;
        entry.trie_score = 0.8f;
        entry.semantic_score = 0.6f;
        entry.final_score = 0.7f;
        entry.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        entry.edit_distance = 0;
        
        collector.record(
            entry.signal,
            entry.context_hash,
            "test_suggestion",
            entry.trie_score,
            entry.semantic_score,
            entry.final_score,
            entry.edit_distance
        );
    }

    // 4. Wait for background worker to drain
    std::cout << "[Test] Waiting for worker thread to process queue..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // 5. Verify convergence/change
    float final_weight = fusion.get_weight_confident(confidence);
    std::cout << "[Test] Final Alpha Weight: " << final_weight << std::endl;

    if (std::abs(final_weight - initial_weight) > 1e-5f) {
        std::cout << "[Test] SUCCESS: Weights updated successfully." << std::endl;
    } else {
        std::cerr << "[Test] FAILURE: Weights did not update." << std::endl;
    }
    
    // Show persona stats
    auto persona = fusion.get_persona();
    std::cout << "[Test] Total Interactions: " << persona.total_interactions << std::endl;
    std::cout << "[Test] Tab Accepts: " << persona.tab_accepts << std::endl;
    std::cout << "[Test] Dismissals: " << persona.dismissals << std::endl;
}

} // namespace RawrXD

int main() {
    RawrXD::RunFusionIntegrationTest();
    return 0;
}

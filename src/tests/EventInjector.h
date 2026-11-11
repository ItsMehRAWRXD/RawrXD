#pragma once

#include "../telemetry/FeedbackCollector.h"
#include <string>

namespace RawrXD::E2E {

/**
 * @brief Injects synthetic telemetry into the FeedbackCollector
 * 
 * Phase 19: Replays Golden Record traces for testing the learning pipeline
 */
class EventInjector {
public:
    /**
     * @brief Replay a Golden Record JSON trace file
     * @param filepath Path to JSON trace file
     * @return true if replay successful
     */
    static bool ReplayTrace(const std::string& filepath);
    
    /**
     * @brief Inject a single interaction signal
     * @param signal Type of interaction
     * @param confidence Confidence score (0.0-1.0)
     */
    static void Pulse(const InteractionSignal& signal, float confidence);
    
    /**
     * @brief Generate synthetic trace file for testing
     * @param filepath Output file path
     * @param event_count Number of events to generate
     * @return true if generation successful
     */
    static bool GenerateSyntheticTrace(const std::string& filepath, size_t event_count);
};

} // namespace RawrXD::E2E

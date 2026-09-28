#include "agentic_deep_thinking_engine.hpp"

static bool s_thinking = false;

void AgenticDeepThinkingEngine::configure(const ThinkingContext& ctx) {
}

std::string AgenticDeepThinkingEngine::think(const std::string& input) {
    s_thinking = true;
    return "deep_thought: " + input;
}

bool AgenticDeepThinkingEngine::isThinking() const {
    return s_thinking;
}

void AgenticDeepThinkingEngine::cancel() {
    s_thinking = false;
}

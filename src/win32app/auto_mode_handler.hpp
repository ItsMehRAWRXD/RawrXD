#pragma once
// ============================================================================
// auto_mode_handler.hpp — Auto Mode (G05): visible route + fail-closed fallback
// ============================================================================
// Routes Auto → Ask|Plan|Agent|Debug by light task heuristics. Decision must
// be logged by the caller. Unknown/empty → Ask. Never silently maps to a
// default-model path. RUNTIME exercise is NOT_RUN until tip absorb.
// ============================================================================

#include <string>
#include <cctype>
#include "agentic_mode_switcher.hpp"

namespace RawrXD {

inline const char* AutoModeSystemPrompt() {
    return
        "You are in Auto mode. The host may re-route this turn to Ask, Plan, "
        "Agent, or Debug based on the task. Follow the effective mode contract "
        "stated in the user prefix. If unsure, ask one clarifying question.";
}

inline std::string AutoModeUserPrefix(AgenticMode routed) {
    return std::string("[Auto mode: routed=") + AgenticModeToString(routed) + "] ";
}

// Visible routing: keyword heuristics only. Empty/unknown → Ask (fallback).
inline AgenticMode AutoModeRoute(const std::string& task) {
    auto lower = task;
    for (char& c : lower)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower.empty())
        return AgenticMode::Ask;
    if (lower.find("debug") != std::string::npos ||
        lower.find("breakpoint") != std::string::npos ||
        lower.find("stack trace") != std::string::npos ||
        lower.find("segfault") != std::string::npos)
        return AgenticMode::Debug;
    if (lower.find("plan") != std::string::npos ||
        lower.find("checklist") != std::string::npos ||
        lower.find("decompose") != std::string::npos)
        return AgenticMode::Plan;
    if (lower.find("implement") != std::string::npos ||
        lower.find("fix") != std::string::npos ||
        lower.find("build") != std::string::npos ||
        lower.find("refactor") != std::string::npos)
        return AgenticMode::Agent;
    return AgenticMode::Ask;
}

} // namespace RawrXD

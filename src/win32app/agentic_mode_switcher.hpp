#pragma once
// ============================================================================
// agentic_mode_switcher.hpp — Plan / Agent / Ask / Debug / Auto Mode Architecture
// ============================================================================
// Agentic UI modes: Plan (stabilize → checklist → approve), Agent (autonomous
// todo + subagent), Ask (Q&A), Debug (debugger-oriented), Auto (route+fallback).
// Ordinals 0–4 preserved for tip ABI; Debug=5 / Auto=6 require RELINK.
// ============================================================================

#include <string>

namespace RawrXD {

enum class AgenticMode {
    Ask          = 0,  // Question answering, verification, citations
    Plan         = 1,  // Research via subagent → structured plan → user approval
    Agent        = 2,  // Autonomous execution: manage_todo_list + runSubagent, streaming
    DeepThink    = 3,  // Extended reasoning: multi-pass chain-of-thought before response
    DeepResearch = 4,  // Long-horizon research: iterative web/codebase search + synthesis
    Debug        = 5,  // Debugger-oriented: break/step/stack/watch context (G04)
    Auto         = 6   // Route by task/capabilities with visible decision + fallback (G05)
};

inline const char* AgenticModeToString(AgenticMode m) {
    switch (m) {
        case AgenticMode::Ask:          return "Ask";
        case AgenticMode::Plan:         return "Plan";
        case AgenticMode::Agent:        return "Agent";
        case AgenticMode::DeepThink:    return "DeepThink";
        case AgenticMode::DeepResearch: return "DeepResearch";
        case AgenticMode::Debug:        return "Debug";
        case AgenticMode::Auto:         return "Auto";
        default:                        return "Ask";
    }
}

inline AgenticMode AgenticModeFromInt(int i) {
    switch (i) {
        case 1: return AgenticMode::Plan;
        case 2: return AgenticMode::Agent;
        case 3: return AgenticMode::DeepThink;
        case 4: return AgenticMode::DeepResearch;
        case 5: return AgenticMode::Debug;
        case 6: return AgenticMode::Auto;
        default: return AgenticMode::Ask;
    }
}

inline int AgenticModeToInt(AgenticMode m) {
    return static_cast<int>(m);
}

} // namespace RawrXD

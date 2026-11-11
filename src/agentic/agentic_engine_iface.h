// ============================================================================
// File: src/agentic/agentic_engine_iface.h
//
// Qt-free interface to the agentic inference engine.
//
// Why this exists
// ---------------
// subagent_core.h forward-declares `class AgenticEngine;` and stores only an
// AgenticEngine*, so it is pure C++20. Its implementation, subagent_core.cpp,
// needs the complete type only to call AgenticEngine::chat().
//
// The src/agentic_engine.h in the main tree declares an engine class that
// inherits from the Qt object base and carries the Qt meta-object macro, with
// ~66 Qt references and NO chat() member, so it can neither be included from
// a Qt-free translation unit nor satisfy the call sites. It is consumed by 11
// other translation units and is deliberately left untouched.
//
// This header declares the minimal contract subagent_core.cpp actually uses,
// so SubAgentManager can be built and linked without any Qt dependency.
//
// This is an INTERFACE, not an implementation. The engine object it describes
// must be provided by whoever constructs a SubAgentManager; HexMag passes
// nullptr, in which case the manager fails closed (it throws "No AgenticEngine
// available" rather than fabricating output).
// ============================================================================

#pragma once

#include <string>

// Declared at global scope to match the forward declaration in subagent_core.h
// and the symbol the linker expects.
class AgenticEngine {
public:
    virtual ~AgenticEngine() = default;

    // Single-turn completion. Throws or returns a non-empty string on success;
    // returns an empty string only when the engine genuinely has no answer.
    virtual std::string chat(const std::string& prompt) = 0;
};

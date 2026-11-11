// ============================================================================
// File: src/inference_engine_qtfree.h
//
// Qt-free declaration of the abstract inference engine.
//
// Why this exists
// ---------------
// src/cpu_inference_engine.h includes "inference_engine.h". That name does not
// exist under src/, so it resolves through -I include to include/inference_engine.h,
// which is a 178-byte shim forwarding to the Qt application engine header. That
// makes src/cpu_inference_engine.h - and everything through it, including
// src/native_agent.hpp and src/subagent_core.cpp - unbuildable without Qt,
// even though none of them use Qt themselves.
//
// This project is explicitly Qt-free, so this header provides the abstract
// engine contract from the dependency-free RawrXD_Interfaces.h instead.
//
// Naming note: this file deliberately does NOT share the name
// "inference_engine.h". If it did it would shadow include/inference_engine.h
// for every source under src/ - including src/benchmark_runner.cpp and
// src/tests/batch4_ipc_spec_ast_arb_smoke.cpp, which include that name
// directly and must keep resolving to the Qt shim. A distinct name keeps this
// change local to the callers that opt in.
// ============================================================================

#pragma once

#include "RawrXD_Interfaces.h"

// <windows.h> reaches us through RawrXD_Interfaces.h and defines max/min as
// function-like macros. Those silently break every std::max/std::min call in
// code compiled through this chain (subagent_core.cpp hits exactly that).
// Undefining them here is local to this include chain and cannot affect the
// Qt translation units.
#undef max
#undef min

// src/native_agent.hpp refers to the engine as CPUInference::CPUInferenceEngine,
// but the engine is declared as RawrXD::CPUInferenceEngine (cpu_inference_engine.h
// line 79, inside `namespace RawrXD`). The namespace simply does not exist under
// that name. This alias reconciles the two without editing any declaration.
namespace RawrXD {
    namespace CPUInference = RawrXD;
}

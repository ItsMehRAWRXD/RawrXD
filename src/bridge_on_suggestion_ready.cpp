// bridge_on_suggestion_ready.cpp — Production implementation of Bridge_OnSuggestionReady
// Replaces: bridge_on_suggestion_ready_stub.cpp
//
// Provides the Bridge_OnSuggestionReady callback that receives ghost text
// suggestions from the inference engine. Now delegates to ghost_text_engine.h
// for thread-safe buffer management.
//
// DAY 1: This file now includes ghost_text_engine.h and uses the production
// implementation instead of being a stub.

#include "ghost_text_engine.h"

// Bridge functions are now implemented in ghost_text_engine.cpp
// This file exists for backward compatibility with existing build systems

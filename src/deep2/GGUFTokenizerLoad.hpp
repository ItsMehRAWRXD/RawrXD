// ============================================================================
// File: src/deep2/GGUFTokenizerLoad.hpp
//
// GGUF tokenizer loading for Deep2.
//
// Deep2Engine.cpp includes this header but uses nothing from it directly; the
// types it relies on (TokenizerBundle, LoadTokenizerFromGGUF,
// ApplyTokenizerBundle, CanonicalTokenizer) live in CanonicalTokenizer.hpp.
// This header is the single entry point that pulls them in, and it is kept as
// a real loader rather than an empty stub because the engine's model-load
// path genuinely needs to build a tokenizer from a GGUF shard.
// ============================================================================

#pragma once

#include "CanonicalTokenizer.hpp"

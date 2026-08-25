// ============================================================================
// LlamaNativeBridge.cpp — Stub implementation
// ============================================================================

#include "LlamaNativeBridge.hpp"
#include <cstdio>

LlamaNativeBridge::LlamaNativeBridge() = default;
LlamaNativeBridge::~LlamaNativeBridge() = default;

bool LlamaNativeBridge::Initialize(const wchar_t* /*dllPath*/) {
    return false;
}

bool LlamaNativeBridge::LoadModel(const wchar_t* /*modelPath*/, int /*contextSize*/, unsigned int /*seed*/) {
    return false;
}

void LlamaNativeBridge::UnloadModel() {
}

LlamaNativeBridge::GenerationResult LlamaNativeBridge::Generate(const std::string& /*prompt*/, int /*maxTokens*/,
                                                                  float /*temperature*/, float /*topP*/, int /*topK*/) {
    return GenerationResult{};
}

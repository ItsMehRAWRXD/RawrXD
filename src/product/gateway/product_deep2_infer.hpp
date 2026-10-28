#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
namespace rawr {
// Shared IDE/CLI session: Resolve + streamable OpenSession for ProductRun.
bool ProductOpenSession(const char* modelAliasOrPath);
void ProductCloseSession();
bool ProductSessionOpen();
void ProductRequestCancel();

// Production product-serve infer: real Deep2Engine via ProductRun (no hardcoded text).
// maxTokens=0 → product default 64 (StreamBody); never hard-clamp to 8.
bool ProductDeep2Infer(const char* prompt, char* out, size_t cap,
                       uint32_t maxTokens = 0);
/* Last ProductRun GENERATED_TOKENS after Infer/Stream (0 if none). */
uint32_t ProductDeep2LastEvalCount();
// Streaming ProductRun — same path as rawr run / IDE Copilot.
// Returns productPass; outFailedStage/Owner filled on fail (never generic success).
bool ProductDeep2InferStream(const char* prompt, uint32_t maxTokens,
                             const std::function<bool(const std::string&)>& onPiece,
                             std::string* outText = nullptr,
                             const char** outFailedStage = nullptr,
                             const char** outFailedOwner = nullptr,
                             const char** outExitReason = nullptr,
                             int* outFirstToken = nullptr);
} // namespace rawr

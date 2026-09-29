// IdeGenerationDiag.h — RAWRXD_IDE_GENERATION_UNSILENT_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace ide_diag {
enum class Stage { Tokenize, Prefill, Forward, Logits, Sampler, Callback, Render, Join, Done, Stall };
void beginSession();
void recordStage(Stage stage);
void recordStall(Stage stage);
void endSession();
}} // namespace rawrxd::ide_diag
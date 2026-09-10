#pragma once
/* Streamer harness helpers — arm/scan/usage only; main stays thin. */
#include "Deep2StreamApi.hpp"
#include <cstdint>

void StreamerOnEv(const Deep2::Deep2StreamEvent* ev, void* user);
int StreamerForbiddenArgExeScan(int argc, char** argv);
int StreamerArmSpeedEnv();
void StreamerUsage();
void StreamerEmitPostGenerate(const Deep2::Deep2StreamParityObs& obs,
                              const char* model, uint32_t maxTok);
int StreamerRuntimePass(const Deep2::Deep2StreamParityObs& obs);

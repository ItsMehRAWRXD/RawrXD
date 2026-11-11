// ==============================================================================
// Lockstep_Tape.cpp — Instantiate globals defined in Lockstep_Tape.hpp
// ==============================================================================
#include "Lockstep_Tape.hpp"

// Global instances
LockstepTape g_LockstepTape;
void* g_hEvent_SimulationTick = nullptr;
void* g_hEvent_FrameComplete = nullptr;

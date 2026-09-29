// ============================================================================
// w7_resource_leak_gate.cpp
// ============================================================================
// W7 RESOURCE LEAK CERTIFICATION GATE
//
// Verifies that repeated model load/unload cycles do not leak:
//   - Memory (WorkingSet delta)
//   - Handles (GDI + USER + process handles)
//   - Threads
//
// Method: Run the exe N times with --chat-exit-on-done, measuring
// process resource consumption before and after each run. The gate
// compares resource usage across runs to detect leaks.
//
// This is a host-side PowerShell script, not a C++ file — but the
// certification receipt format is defined here for reference.
// ============================================================================

// Receipt format:
/*
GATE=W7_RESOURCE_LEAK_CERTIFICATION_001

TOTAL_CYCLES=<N>
MODEL=<path>

MEMORY_DELTA_MAX=<KB>
HANDLE_DELTA_MAX=<count>
THREAD_DELTA_MAX=<count>

LEAKS_DETECTED=0
MEMORY_LEAK=0
HANDLE_LEAK=0
THREAD_LEAK=0

VERDICT=PASS|FAIL

PER_CYCLE:
  CYCLE_1: MEM=<KB> HANDLES=<n> THREADS=<n> EXIT=<code>
  CYCLE_2: MEM=<KB> HANDLES=<n> THREADS=<n> EXIT=<code>
  ...
*/
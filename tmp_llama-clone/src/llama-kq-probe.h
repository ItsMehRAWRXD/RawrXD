//=============================================================================
// RAW-XD diagnostic probe: dump attention kq/kq_soft tensors per layer.
// Enabled only when RAWRXD_PROBE_DIR is set; otherwise zero overhead.
// Local diagnostic instrumentation for reference-parity measurement.
//=============================================================================
#ifndef LLAMA_KQ_PROBE_H
#define LLAMA_KQ_PROBE_H

#include <cstdint>

struct ggml_tensor;

void rawrxd_probe_register(ggml_tensor * t, const char * name, int il);
void rawrxd_probe_dump_and_clear();

// True when the probe is active (RAWRXD_PROBE_DIR set). Callers use this to
// keep instrumented graph nodes out of runs that do not probe.
bool rawrxd_probe_enabled();

#endif // LLAMA_KQ_PROBE_H

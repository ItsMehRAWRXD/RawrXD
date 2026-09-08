#pragma once
/* ACTUAL_E2E_GENERATION_ONLY — supporting gates ≠ PASS. */
#define RAWRXD_EXECUTION_POLICY_ACTUAL_E2E_GENERATION_ONLY 1
#define ACTUAL_E2E_GENERATION_001 1

/*
  PASS iff END_TO_END production stream produces model text + clean teardown.
  SPV/KERNEL/PARITY/MEASURE/WINNER/TUNER/MODEL_OPEN/PREFILL/HEARTBEAT alone ≠ PASS.
  QKV/KVA tune is transient inside the same generation, not a destination cert.
  Crash instrumentation belongs inside the production executable.
  WALL_WITHIN_BUDGET is a separate final line from STREAM_COMPLETE.
*/

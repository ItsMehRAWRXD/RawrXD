#ifndef DEEP2_E2E_INTEGRATION_CONTRACT_H
#define DEEP2_E2E_INTEGRATION_CONTRACT_H

/*
  Bind these contracts to existing RawrXD / Deep2 product objects.

  1. D2DecodeBalancer:
     - Feed calibrated absolute lane timestamps from the existing dual aggregate.
     - Work units MUST represent the single effective-work authority used by the
       packed operator. Do not independently rebalance rows and repetitions.

  2. D2PersistentDecode:
     - prepare_persistent_commands() must record/reuse the actual product command
       buffers/descriptors after warmup.
     - ensure_persistent_kv() should bind to the existing persistent KV owner.
     - execute_token() must fill D2TokenTiming from the real packed dual-GPU path.
     - prefetch_token() must enqueue exact ranges only.
     - advance_kv() commits only after token output is valid.

  3. D2Residency:
     - Each model tensor/expert/KV/scratch allocation is a node.
     - Hot execution weights should allow the owning GPU(s); cold expert/model
       ranges may allow RAM/MMAP.
     - A hot node landing in MMAP is a fail-closed critical-path violation unless
       explicitly marked D2_RES_COLD_OK.

  4. D2Streamer:
     - open_model/prefill/decode_one/reset/close must be the native Deep2 path.
     - decode_one() must report external_runtime_calls=0.
     - no Ollama or llama.cpp runtime fallback may be hidden behind callbacks.

  5. Endurance:
     - Use actual installed GGUF paths.
     - Minimum certification suggestion:
         dense Q2_K: 2 generations x 64 tokens
         second dense quant: 2 x 64
         MoE selective-residency model: 2 x 64
         cancel/reset/reuse: separate exercised case
     - Promotion remains external to this drop and must stay 0 until live receipts.
*/

#endif

# RawrXD / Deep2 — Full-Model Certification Receipt

- **Model:** Qwen3.8 Flash Next AD IQ1_M-M64 (qwen4exp)
- **Certification scope:** complete 1,224-tensor model only; no unit or microbenchmark promotion.
- **Date:** 2026-10-20

## Artifact and structural prerequisites

| Check | Result | Evidence |
|---|---|---|
| Canonical sharded GGUF discovery | PASS | deep2_shard_probe: shards=2 tensors=1224 mapped_bytes=84930920928 arch=qwen4exp |
| ROM pack receipt | PASS | qwen_pack.stdout.log: 1,224 tensors, 144 expert-streamed, 1,080 persistent, 84,955,299,840 bytes, 64-KiB alignment |
| ROM physical size/header | PASS | magic=RXROM001, version=1, alignment=65536, table=56, data=131072, tensorCount=1224, fileBytes=84955299840 |
| ROM payload digest/reopen | PASS | ROM_READ_PASS tensors=1224 alignment=65536, exit 0; payload hash=0x12916395ED8BA845 |
| GPU admission after reboot | PASS prerequisite | R9700 and RX 7800 XT both Status=OK, ProblemCode=0; see pnp_after.json |

## Full-model execution gates

| Gate | Status | Receipt |
|---|---|---|
| Complete native GPU bind | **BLOCKED** | deep2_gpu_certify ingested arch=qwen4exp blocks=48 embd=2560 vocab=248320 experts=512 used=10, then failed closed: missing output_norm.weight because Universal ingest currently consumes only the first shard. |
| Complete CPU forward | **BLOCKED** | deep2_full_forward_profile rejected blk.0.ffn_down_exps.weight as an unsupported/malformed GGML type/shape. |
| Qwen4Exp graph execution | **BLOCKED** | BuildGraph explicitly emits unsupported: QSA, PLE, hyperconnection and sparse-MoE operators are not implemented. |
| Full forward finite logits | NOT_RUN | No complete-model executor reached a forward pass. |
| Trusted full-logit parity | NOT_RUN | No reference comparison was possible. |
| Multi-token autoregressive generation | NOT_RUN | No complete-model token stream was emitted. |
| GPU-only residency/transfer proof | NOT_RUN | Device admission passed, but model execution did not bind. |
| Sustained TPS / 150 TPS | NOT_RUN | NOT_RUN != PASS. |

## Certification decision

**FULL_MODEL_CERTIFICATION=BLOCKED**

The ROM artifact is structurally and digest valid, and both physical GPUs are admitted. Full-model certification is not granted because the native executor does not yet consume the two-shard Qwen4Exp topology and does not implement the required QSA/PLE/hyperconnection/sparse-MoE graph. The earlier GEMV result is explicitly excluded from this certificate.

Required closure is a shard-aware Universal ingest that preserves all 1,224 tensor mappings, followed by Qwen4Exp graph/operator implementation and an end-to-end GPU/reference/multi-token receipt.


# Deep2 Virtual Weight Residency / link-budget contract

Date: 2026-10-20

This receipt records a source-level residency contract and a CPU-side scheduler
test. It is not a GPU performance certification.

## What is now wired

- `src/deep2/VulkanWeightStreamer.hpp/.cpp` owns bounded transfer slots,
  generation-tagged tickets, cache hits, asynchronous completion, and explicit
  release. A stale ticket cannot bind a reused slot.
- Strict mode refuses initialization without a real transfer backend. The
  scheduler therefore cannot report GPU residency from a CPU-only placeholder.
- `src/deep2/StreamLinkBudget.hpp` computes the link budget from configurable
  bandwidth and target TPS. Defaults are 54 GB/s and 150 TPS, yielding:

  `54,000,000,000 / 150 = 360,000,000 bytes/token ≈ 343.3 MiB/token`.

- The existing `StreamTransfer_Emit` receipt now emits measured bytes-to-GPU per
  token and a `STREAM_LINK_BUDGET_STATUS`. With zero token receipts the status
  remains `NOT_RUN`.

## Contract test

Command:

```text
cmake -S . -B build_streamer_contract -DDEEP2_BUILD_STREAMER_TEST=ON -DRAWRXD_BUILD_TESTS=OFF -DENABLE_VULKAN=OFF
cmake --build build_streamer_contract --config Release --target deep2_weight_streamer_test --parallel 2
ctest --test-dir build_streamer_contract -C Release -R deep2_weight_streamer_contract --output-on-failure
```

Result: **1/1 passed**.

The test covers strict no-backend denial, duplicate-request cache hits, bounded
two-slot allocation, no eviction of live bindings, release/reuse, stale-ticket
rejection, and the 360 MB/token arithmetic witness. Its synthetic receipt shows
`STREAM_LINK_BUDGET_STATUS=PASS` only for the fixture's supplied counters; it is
not evidence of a live transfer run.

## Runtime boundary

The RX 7800 XT remains excluded while Windows reports Code 43, so no dual-GPU
transfer or Vulkan link measurement is claimed here. The next runtime receipt
must come from the existing Vulkan upload path and include real submissions,
waits, `TRANSFER_BYTES_TO_GPU_TOTAL`, token count, and end-to-end wall time.

`SOURCE_WIRED=1` does not imply `RUNTIME_REACHED=1`, and `NOT_RUN != PASS`.

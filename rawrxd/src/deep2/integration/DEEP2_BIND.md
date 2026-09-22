# Batch 71–75 real Deep2 bind

The current Deep2 tree already exposes:

    const GpuForwardCounters& Deep2Engine::gpuForwardCounters() const;

and `GpuForwardCounters` contains:
- forwardSlot[0], forwardSlot[1]
- hostSyncBoundaries
- hostMaterializations
- ownershipTransfers
- intraSlotHostTransfers
- liveDecodeResidentTokens
- liveDecodeTokens
- hostForwardLayerCalls
- layerSubmits / opSubmits
- q4k/q6k/q2k packed ops
- cpuF32Expands

## Token measurement bind

Before token:

    auto before = Deep2::B71GpuCounterAdapter::capture(
        engine.gpuForwardCounters());

Run exactly one target decode token.

After token:

    auto after = Deep2::B71GpuCounterAdapter::capture(
        engine.gpuForwardCounters());

    auto delta = Deep2::B71GpuCounterAdapter::delta(before, after);

Populate Batch 67 token telemetry from:
- real CPU monotonic wall timestamps
- Vulkan timestamp queries for GPU0/GPU1 and overlap
- real bytes/FLOPs counters
- `delta.gpu0Forwards`, `delta.gpu1Forwards`
- `delta.hostMaterializations`
- `delta.intraSlotHostTransfers`
- `delta.cpuF32Expands`

Do not infer GPU1 live from enumeration. `delta.gpu1Forwards > 0` is required.

## Rawr CLI bind

Add a `bench` branch beside the existing `run/list` product commands:

    rawr bench <model> --contract --tokens 384

Use `B72RawrBenchCli` for subcommand-specific args, then:
1. load/resolve model
2. warmup
3. Batch 66 metadata bind
4. Batch 67 capture
5. Batch 68 roofline calibration
6. Batch 69 contract
7. Batch 70 receipt
8. Batch 73 atomic evidence persistence
9. print concise authority result

## Evidence path

Suggested:

    evidence/RAWRXD_PERFORMANCE_001/contracts/<model-key>/

Keep:
- canonical receipt
- .sha256 sidecar
- optional raw per-token telemetry file

Batch 73 writes receipt via `.tmp -> rename` so an interrupted run does not leave a final-looking partial receipt.

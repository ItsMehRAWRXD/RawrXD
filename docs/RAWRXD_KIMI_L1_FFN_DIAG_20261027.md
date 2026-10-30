# Kimi K2 Layer-1 FFN diagnostic checkpoint

Date: 2026-10-27

## Build

The opt-in Layer-1 diagnostic compiles after using the existing
`Deep2Engine::SwiGLU` member implementation directly. No duplicate activation
wrapper was added.

```text
TARGET=rawrxd_deep2_engine
BUILD_EXIT=0
EXECUTABLE_SHA256=D57EFB4F7C345175EA6D29902757162F7566CE8C7FD3FD4E4740032AA6DE0FA8
```

## One-token runtime

The run used the 13-shard Kimi K2 Q4_K_M set and completed with `RUN_EXIT=0`.
The receipt contains real Layer-39 routing and expert execution:

```text
T0_L39_ROUTER_DONE ids=[108,111,214,40,0,180,205,271]
T0_L39_DOWN_DONE = 8/8
T0_L39_SHARED_ACCUM_DONE
T0_L39_HOST_MOE_DONE
T0_L39_RESIDUAL_DONE
T0_L39_EXIT
```

The run also recorded 7,670,261,696 raw stream bytes read, 915 read
operations, 2 cache hits, 915 cache misses, and zero GPU upload bytes. These
are movement measurements for this run, not a claim that GPU execution is
working.

```text
GPU1_REAL_COMPUTE=NOT_PROVEN
DUALSTICK_BIND=vc0=1 vc1=0 devices=1
```

## Open boundary

`L1_DIAG` emitted zero lines in this run, so the Layer-1 numerical comparison
did not execute or was not reached by the active path. The Layer-39 receipt is
useful regression evidence, but it does not establish Layer-1 parity, full
depth numerical correctness, or GPU1 contribution.

Runtime log SHA-256:

```text
BEAD353C4ED30A5069593702F5E80FC9FEF0529D6DB723915A398B2362569743
```

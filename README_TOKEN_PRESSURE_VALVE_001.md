# TOKEN_PRESSURE_VALVE_001

No-dependency x64 MASM token-flow controller for RawrXD.

This is the "shower head" layer: it changes token pressure patterns after decode
observation and before sampler/stream policy. It does not change:

```text
context length
temperature
GPU split
model path
model load/unload lifecycle
CommandBroker(message, mode)
```

## Files

```text
include/RawrXD_TokenPressureValve.hpp
include/RawrXD_TokenPressureValveBridge.hpp
src/asm/RawrXD_TokenPressureValve_x64.inc
src/asm/RawrXD_TokenPressureValve_x64.asm
src/win32app/RawrXD_TokenPressureValveBridge.cpp
cmake/RawrXD_TokenPressureValve.cmake
evidence/TOKEN_PRESSURE_VALVE_001/SOURCE_DROP_MANIFEST.txt
```

## Build

Copy the overlay into the RawrXD repo root and include:

```cmake
include(cmake/RawrXD_TokenPressureValve.cmake)
```

If your tree already has a MASM object-library target, add only this file to that
MASM target:

```text
src/asm/RawrXD_TokenPressureValve_x64.asm
```

Then add the bridge C++ file to `RawrXD-Win32IDE`.

## Integration

Initialize once per generation stream:

```cpp
TPV_State valve = {};
TPV_InitState(&valve, TPV_MODE_NEEDLE, 0);
```

For every emitted candidate or accepted token:

```cpp
TPV_Result pressure = {};
TPV_UpdateUtf8Token(&valve, tokenId, tokenText, tokenTextBytes, &pressure);

TPV_SamplerHints hints = {};
TPV_ResultToSamplerHints(&pressure, &hints);
```

The caller owns how hints map into its existing sampler:

```text
repeat_penalty_bps -> increase local repeat penalty
top_k_delta        -> narrow or widen candidate set
stop_hint          -> stop/cancel if host policy agrees
compress_hint      -> prefer summary/closure tokens
repair_hint        -> favor fix/code/error-resolution lane
approval_hold      -> stop before destructive/edit execution
```

## Pressure modes

```text
NEEDLE  direct, narrow, low branch
MIST    softer and wider
PULSE   alternating explore/compress cadence
RINSE   compress and close structure
CUTOFF  early stop on loop pressure
REPAIR  stronger repair/fix/code bias after observed failure
```

## Evidence boundary

Passing this source overlay means the valve links and returns action bits from
real token input. It is not evidence of model correctness by itself.

Acceptance:

```text
MASM_LINKED=1
NO_THIRD_PARTY_DEPS=1
CTX_MUTATED=0
TEMP_MUTATED=0
GPU_SPLIT_MUTATED=0
MODEL_PATH_MUTATED=0
REAL_TOKEN_STREAM_OBSERVED=1
PRESSURE_ACTIONS_OBSERVED>=1
```


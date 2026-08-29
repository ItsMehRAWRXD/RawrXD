# HexMag Polymorphic Repeat Tuner — Runtime Integration

This drop closes the main wiring gap between the supplied sovereign agent runtime
and `RawrXD_HexMag_RepeatTuner.asm`.

## What changed

1. `RawrXD_HexMag_RepeatTuner.fixed.asm`
   - Adds a real generic `HX_FAIL_WRONG` mutation path.
   - Preserves more-specific failure strategies when `HX_FAIL_WRONG` is ORed with them.
   - Adds Win64 shadow-space/alignment around nested calls in `HexMag_Tuner_Fingerprint`
     and `hx_unique`.
   - Keeps the existing hard invariants:
     - new fingerprint per retry,
     - new generation_id per retry,
     - Q_BLOCKING,
     - blocking_passes=3,
     - missing-information evidence guard,
     - zero persistent weight delta,
     - exhaustion fails closed.

2. `HexMagRepeatTunerBridge.hpp`
   - Exact 48-byte C++ ABI mirror of `HX_GEN_PROFILE`.
   - Caller-side `RepeatSession` wrapper.
   - Holds one process mutex for the whole request because the supplied MASM owns
     a single global `g_Tuner`; this prevents inter-request state clobbering and
     enforces Q_BLOCKING.
   - Adds request hashing, strategy names, generation/fingerprint checks, and prompt
     directives.

3. `rawrxd_agentic_runtime_all.hexmag.cpp`
   - Actually calls HexMag at runtime.
   - Tool/build/schema/duplicate failures become tuner failure masks.
   - A rejected generation mutates the HexMag profile and changes generation_id.
   - Final candidate text is buffered while verification is enabled; rejected text is
     not printed as a successful answer.
   - Runs three blocking verifier passes against the task + observed transcript.
   - On verifier failure, classifies failure and retries with a changed profile.
   - On retry exhaustion returns `INSUFFICIENT_INFORMATION` instead of fake success.
   - Adds compile-time sampling adapters for Deep2 engines exposing any of:
       `setSampling(float,float)`,
       `setTemperature(float)`,
       `setTopP(float)`.
     If none exist, prompt/genome mutation still changes the generation request and
     the runtime logs `native_sampling=0` rather than pretending temperature/top-p
     were applied.

4. `hexmag_repeat_tuner_cert.cpp`
   - Checks unique fingerprints/generation IDs.
   - Checks `HX_FAIL_WRONG -> REVERSE`.
   - Checks TEST -> REPAIR.
   - Checks UNSUPPORTED -> REVERSE.
   - Checks MISSING_INFO -> EVIDENCE_GUARD with temp=0/candidate_count=1.
   - Checks Q_BLOCKING + 3 passes + zero weight delta.
   - Checks retry exhaustion fails closed.

## Suggested repository placement

```text
src/agentic/rawrxd_agentic_runtime_all.cpp
src/agentic/HexMagRepeatTunerBridge.hpp
src/asm/RawrXD_HexMag_RepeatTuner.asm
tests/hexmag_repeat_tuner_cert.cpp
```

Replace the runtime and ASM files with the patched versions after reviewing the diff.

## CMake wiring

For MSVC/MASM, wire the assembly object into both the agent and the cert target:

```cmake
enable_language(ASM_MASM)

add_library(rawrxd_hexmag_repeat OBJECT
    src/asm/RawrXD_HexMag_RepeatTuner.asm
)

target_compile_options(rawrxd_hexmag_repeat PRIVATE
    $<$<COMPILE_LANGUAGE:ASM_MASM>:/I${CMAKE_SOURCE_DIR}/src/asm>
)

target_sources(RawrXD-Agentic PRIVATE
    $<TARGET_OBJECTS:rawrxd_hexmag_repeat>
)

target_include_directories(RawrXD-Agentic PRIVATE
    ${CMAKE_SOURCE_DIR}/src/agentic
)

add_executable(hexmag_repeat_tuner_cert
    tests/hexmag_repeat_tuner_cert.cpp
    $<TARGET_OBJECTS:rawrxd_hexmag_repeat>
)

target_include_directories(hexmag_repeat_tuner_cert PRIVATE
    ${CMAKE_SOURCE_DIR}/src/agentic
)
```

Adjust the ASM directory if `RawrXD_Common.inc` lives elsewhere.

## Certification run

```powershell
cmake --build build-ninja --target RawrXD-Agentic hexmag_repeat_tuner_cert
& .\build-ninja\bin\hexmag_repeat_tuner_cert.exe
```

Expected terminal invariant:

```text
HEXMAG_POLYMORPHIC_REPEAT_TUNER_001=PASS
blocking_passes=3
queue_policy=Q_BLOCKING
persistent_weight_delta_bytes=0
exhaustion=INSUFFICIENT_INFORMATION
```

## Important scope note

This closes *repeat-generation polymorphism* in the supplied single-agent runtime.
It does not by itself create a parallel multi-agent swarm scheduler. The supplied
MASM state is singleton, so this bridge deliberately serializes complete requests
under Q_BLOCKING. If the HexMag swarm must run multiple requests concurrently, the
next architectural change is to convert the MASM API from global `g_Tuner` state to
caller-owned `HX_TUNER_STATE*` contexts.

The three-pass verifier is evidence-grounded but is still a model verifier. It can
detect/reject failures from observed tool/test evidence; it is not a mathematical
proof that an arbitrary natural-language answer is correct.

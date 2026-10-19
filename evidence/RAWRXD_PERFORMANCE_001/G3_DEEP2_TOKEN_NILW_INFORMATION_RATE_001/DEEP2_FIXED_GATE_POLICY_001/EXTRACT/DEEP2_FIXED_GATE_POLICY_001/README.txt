DEEP2_FIXED_GATE_POLICY_001
===========================
Purpose
-------
Make the five performance/information gates permanent and codec-independent:
  100 MB/token  = 100,000,000 bytes/token max
  1 GB/s        = 1,000,000,000 bytes/s max
  10 TPS        = 10,000 milli-TPS min
  128-token     = 128 tokens min
  TOKEN_NILW    = 0.0008 max = 1/1250 exactly

Design rule
-----------
Quantization/codec fixtures NEVER own these constants. Q4 is only an independent
proof witness:
  4.0 * 0.005 * 0.04 = 0.0008
implemented without floating point as:
  (4000/1000) * (5/1000) * (4/100) = 1/1250.

Future Q2/Q3/Q5/Q6/Q8/NVFP/other extensions may add witnesses, but they must
reduce to the same permanent policy or fail their witness. They cannot mutate
GatePolicy.

Persistence model
-----------------
Deep2FixedGatePolicy_Init writes canonical fields. A persisted copy can be stored
by the caller; Deep2FixedGatePolicy_Validate rejects any altered/stale copy.
The assembly module itself has no filesystem, runtime, scheduler, GPU, CRT, C++
or model-loader dependency.

Authority boundary
------------------
This module evaluates five invariant gates only. It does NOT create decode
authority, scheduler authority, AUTHORIZED_PASS, PROMOTE, prefetch PASS, or
token-1 PASS. A higher authority layer may consume or revoke based on this
result, but this source does not manufacture those states.

Current model inventory supersession
------------------------------------
Do not carry forward MOE_GGUF_ON_HOST=0 as model inventory truth. The recorded
DeepSeek-R1 11-shard MoE presence supersedes that discovery-only inventory bit.
Prefetch/token-1 remain NOT_RUN / PASS=0; this policy module does not alter them.

Build (VS x64 Native Tools prompt)
----------------------------------
  ml64 /nologo /c /Fo Deep2FixedGatePolicy.obj Deep2FixedGatePolicy.asm

No link is required to consume the object from Deep2. No external library calls
exist in the object.

ScreenPilot / RawrXD Standalone Native E2E Source Drop
========================================================

PATCH BASE
----------
This patched standalone HTML was generated from the user's saved source for:
  https://screenpilot.tech/gui/ide_chatbot_standalone.html

The live public URL could not be fetched from this execution environment, so
the saved standalone source was used as the authoritative patch base.

Preserved Engine Explorer inventory:
  subsystems        : 33
  file entries      : 91
  endpoint entries  : 86
  unique route pats : 60

END-TO-END PATH
---------------
HTML standalone chat
  -> /api/native/generation/prepare
  -> runtime GGUF profile OR existing ModelBridge_* authority
  -> x64 MASM Safe Decode normalization
  -> x64 MASM Tensor Bunny Hop policy preparation
  -> request_id + PREPARED receipt
  -> existing /v1/chat/completions or /api/generate
  -> real Deep2 engine boundary:
       RawrNative_ReceiptEngineEnter()
       RawrNative_ReceiptFirstToken()
       RawrNative_ReceiptComplete()
  -> /api/native/receipt/<id>
  -> browser proof label

Engine Explorer
  -> existing EngineAPI.SUBSYSTEMS (all 33 preserved)
  -> native route registry
  -> UNDECLARED / DECLARED / ATTACHED
  -> Probe
  -> Run actual endpoint
  -> render actual JSON response in chat

WHY RUNTIME MODEL REGISTRATION EXISTS
-------------------------------------
The retained static model_bridge_x64 profile table is useful for known profile
families but is not the authoritative identity source for every real GGUF.
Kimi-K2 is not represented by an exact static profile in the retained table.

After real GGUF metadata/topology resolution, register the exact runtime model:

  RawrNative_RegisterRuntimeModel(exactName, &profileInfo);

This is the preferred authority for:
  - Kimi-K2 13/13 Q4_K_M
  - DeepSeek-R1 11/11 Q4_K_M
  - any future sharded model whose exact topology is discovered at runtime

SAFE DECODE
-----------
The browser's current Safe Decode controls are preserved, but the server now
re-normalizes them through rawr_native_policy_x64.asm.

Prepared != executed.

Safe Decode is only an execution claim when the engine receipt reports the
actual applied flags at RawrNative_ReceiptEngineEnter().

TENSOR BUNNY HOP
----------------
MASM validates:
  even
  front
  back
  custom

and prepares a bounded <=256-layer skip mask.

"auto" is deliberately NOT guessed by the bridge. It returns:
  RN_POLICY_HOP_NEEDS_ENGINE

The real engine/query planner must choose the auto plan and mark it in the
execution receipt.

ENGINE EXPLORER
---------------
The old renderer treated endpoint names mainly as terminal/curl shortcuts.
The patched renderer uses the native route registry.

States:
  UNDECLARED = not known to native registry
  DECLARED   = known route pattern, no live server attachment witness
  ATTACHED   = server called RawrNative_RegisterRouteAttachment beside the
               actual installed handler

Do not bulk-mark routes as attached.

FILES
-----
ide_chatbot_standalone_e2e.html
  Full patched standalone page.

screenpilot_native_e2e.js
  The injected browser integration as a separate source file.

engine_endpoint_manifest.json
  Exact 33 / 91 / 86 inventory extracted from the saved standalone source.

native_route_patterns.json
  60 unique endpoint patterns used by native route discovery.

rawr_native_e2e.inc
rawr_native_e2e_abi.h
  Shared ABI.

model_bridge_web_x64.asm
  Adapter around existing ModelBridge_* MASM authority.

rawr_native_policy_x64.asm
  Safe Decode + Tensor Bunny Hop normalization.

rawr_native_receipt_x64.asm
  128-entry native execution receipt ring.

rawr_native_http_adapter.cpp
  /api/native/* implementation; no third-party JSON package.

runtime_model_registration.inl
  Hook for exact GGUF metadata.

rawr_native_engine_hooks.h
  Real engine execution proof hooks.

rawr_native_server_integration.inl
route_attachment_checklist.inl
  complete_server/tool_server integration guidance.

build_native_web_bridge.cmd
CMakeLists.native_e2e.txt
  Build integration.

NATIVE HTTP ENDPOINTS
---------------------
GET  /api/native/capabilities
GET  /api/native/routes
POST /api/native/route/probe
GET  /api/native/model-bridge/status
GET  /api/native/safe-decode/status
GET  /api/native/tensor-hop/status
POST /api/native/generation/prepare
GET  /api/native/receipt/<id>
GET  /api/native/receipt/latest

PROOF CLASSIFICATION
--------------------
PREPARED / NOT EXECUTED
  qpc_engine_enter == 0

ENGINE ENTERED / NO TOKEN
  qpc_engine_enter != 0
  qpc_first_token == 0

STREAMING
  qpc_first_token != 0
  qpc_end == 0

EXECUTED
  qpc_end != 0
  engine_status == 0

ENGINE FAIL
  qpc_end != 0
  engine_status != 0

VALIDATION PERFORMED HERE
-------------------------
- JavaScript syntax: node --check PASS
- HTTP adapter C++ syntax: clang++ syntax-only PASS using Win32 ABI stubs
- ABI structure sizes:
    RawrNativeProfileInfo    40 bytes
    RawrNativePolicyRequest 104 bytes
    RawrNativePolicy         72 bytes
    RawrNativeReceipt        72 bytes
- Engine Explorer source inventory:
    33 subsystems / 91 files / 86 endpoint entries
- Patched HTML contains one native E2E injection marker

ML64 cannot be executed in this Linux environment. The included Windows build
script is the physical-host compilation gate.

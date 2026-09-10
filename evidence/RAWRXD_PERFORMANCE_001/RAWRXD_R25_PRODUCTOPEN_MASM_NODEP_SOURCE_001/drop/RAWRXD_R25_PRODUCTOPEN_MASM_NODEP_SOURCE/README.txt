RAWRXD_R25_PRODUCTOPEN_MASM_NODEP_SOURCE

Source-only x64 MASM drop for R25 ProductOpenSession fail-closed GGUF tensor proof.

Files:
  drop/r25_productopen_masm.asm
  drop/r25_productopen_masm.inc
  drop/r25_productopen_bridge.hpp
  drop/build_r25_masm.bat

Claims:
  SOURCE_ONLY=1
  DEP_EXTERNAL=0
  CRT_DEP=0
  LLAMA_CPP_DEP=0
  OLLAMA_DEP=0
  DOC_ONLY=0
  PRODUCTOPEN_GATE=GGUF tensors>0 + embed/head tensor names
  HTTP_EQ_PRODUCTOPEN=0
  ONESHOT_EQ_IDE=0
  PROMOTE=0

Wire rule:
  Headless loadModel may set READY=1 only when R25_ProductOpenGguf returns 0 and proof.product_open==1.

No performance pass is claimed.

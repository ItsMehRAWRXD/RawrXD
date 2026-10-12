RawrXD 5-BLOCK PARITY CLOSURE DROP
==================================

Purpose
-------
Close the five remaining major gates without adding third-party runtime
dependencies and without reopening frozen HexMag/controller semantics.

Blocks
------
1. Canonical Win32IDE configure/compile/link closure.
2. P1 promoted binary freeze + product evidence gate.
3. Tokenizer exactness (special tokens + SentencePiece metaspace + GGUF vocab).
4. Deep2 L10 -> FINAL_NORM -> LOGITS numerical parity scoring.
5. Exact multi-token parity + agentic product smoke certification.

Dependency policy
-----------------
No Boost, Qt, Python packages, llama.cpp linkage, Ollama, JSON library,
regex library, or package-manager dependency is introduced by this drop.

Required environment:
  - Existing RawrXD repository.
  - CMake + a C++17 compiler for the small cert tools.
  - PowerShell 7/Windows PowerShell for orchestration.
  - A GGUF model for tokenizer certification.
  - Existing Deep2/reference tensor dumps for numerical parity.
  - Existing RawrXD agent/IDE runtime for final agentic smoke.

Frozen authority
----------------
Do NOT modify:
  HexMag runtime controller sequencing
  FinalizePolicy
  NEED_INPUT semantics
  Copilot ownership/exclusivity
  evidence/HEXMAG_IDE_RUNTIME_CERT_FREEZE/FREEZE.txt
  evidence/HEXMAG_IDE_RUNTIME_CERT_FREEZE/AUTHORITY.txt

Recommended execution order
---------------------------
  scripts\Close-1-Win32IDE.ps1
  scripts\Close-2-P1Product.ps1
  scripts\Close-3-Tokenizer.ps1
  scripts\Close-4-Deep2.ps1
  scripts\Close-5-FinalParity.ps1

The scripts are fail-closed: a missing prerequisite does not get converted
into PASS.

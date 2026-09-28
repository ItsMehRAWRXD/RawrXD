Receipt: RAWRXD_DEEP2_UNIFIED_DECODE_FREEZE_001
=================================================
Date: 2026-06-12
Commit Authority: Phase 1 Closure — CPUInferenceEngine fully excised

1. Deep2 Sole Production Decode Authority
   - forwardTokenAllLayers(float* hidden, size_t seqLen) is PRIVATE in Deep2Engine.h
   - generateUnified() is the ONLY public generation path
   - decodeContinuousOne() is the ONLY permitted decode state advance function
   - All bypass scaffolding (CPUInferenceEngine.cpp, manual embed+forward+advance
     sequences in main.cpp, etc.) has been removed from the build graph.

2. Build Verification
   - MSVC 19.44.35228.0, Release, C++20/23
   - rawrxd.exe linked successfully: F:\~dev\rawrxd\build\bin\Release\rawrxd.exe
   - Zero compile errors / zero link errors on target rawrxd
   - Smoke test (--help, no-args) exits clean with code 0.

3. Remaining Known Compromises (Non-blocking for Phase 1)
   - SsVkDecodeBind forward path is stubbed with (void)seq; see
     Deep2Engine_SsVkDecodeBind.cpp.  It must be migrated to the RWR
     state machine (generateUnified → rwrWrite → decodeContinuousOne)
     before any SS-VK decode bind becomes live.
   - Compression codecs (gzip, lz4) are stubbed because zlib/lz4 headers are
     absent in this Windows build environment.  They will be re-enabled when
     the dependency is present.
   - QueueState now uses std::unique_ptr<std::mutex> to satisfy MSVC
     move-constructibility requirements for std::vector::resize.

4. Architecture Gate
   - No code may call forwardTokenAllLayers from outside Deep2Engine.cpp.
   - No code may instantiate CPUInferenceEngine.
   - Any new inference entry point must route through generateUnified.

Signed-off-by: Phase 1 Auditor

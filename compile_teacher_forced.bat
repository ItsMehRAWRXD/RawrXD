@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
copy /Y "F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp" "F:\rawrxd\tmp_build\teacher_forced_main.cpp" >nul
echo int main(int argc, char* argv[]) { >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     if (argc < 4) { std::fprintf(stderr, "Usage: %%s <gguf_path> <evidence_dir> <tokens...>\n", argv[0]); return 1; } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::string ggufPath = argv[1]; >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::string evidenceDir = argv[2]; >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::vector<uint32_t> tokens; >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     for (int i = 3; i < argc; ++i) { tokens.push_back(static_cast<uint32_t>(std::stoul(argv[i]))); } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     if (tokens.empty()) { std::fprintf(stderr, "No tokens provided\n"); return 1; } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "=============================================================================\n"); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "RAWRXD_MODELGENIE_TEACHER_FORCED_DECODE\n"); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "=============================================================================\n\n"); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     MG::ModelGenome genome; >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     if (!LoadModelGenomeFromEvidence(evidenceDir, genome)) { >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         std::fprintf(stderr, "ERROR: Failed to load ModelGenome\n"); return 1; } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::string originalHash = genome.computeCanonicalHash(); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "Original canonical hash: %%s\n", originalHash.c_str()); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "\n=== Teacher-forced decode (%%zu tokens) ===\n", tokens.size()); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "Input history: "); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     for (auto t : tokens) std::fprintf(stderr, "%%u ", t); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "\n\n"); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     IRExecutor executor(ggufPath, tokens[0]); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     for (size_t step = 0; step < tokens.size(); ++step) { >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         uint32_t input_token = tokens[step]; >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         executor.SetTokenId(input_token); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         executor.ClearArena(); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         std::fprintf(stderr, "\n--- Step %%zu (position %%zu), input token: %%u ---\n", step, executor.Position(), input_token); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         bool success = executor.Execute(); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         uint32_t predictedToken = executor.SampleToken(); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         const std::vector<float>* logits = executor.GetLogits(); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         bool logitsFinite = true; >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         if (logits) { for (float v : *logits) { if (!std::isfinite(v)) { logitsFinite = false; break; } } } else { logitsFinite = false; } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         std::fprintf(stderr, "Predicted token: %%u, Logits finite: %%d, Ops: %%u/%%u\n", predictedToken, logitsFinite ? 1 : 0, executor.Dispatched(), executor.Visited()); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         if (!success || !logitsFinite) { std::fprintf(stderr, "ERROR: Execution failed at step %%zu\n", step); return 1; } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         char fname[512]; >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         sprintf_s(fname, "F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\native_tf_logits_pos%%zu.bin", step); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         if (logits && !logits->empty()) { std::ofstream f(fname, std::ios::binary); f.write(reinterpret_cast<const char*>(logits->data()), logits->size() * sizeof(float)); f.close(); std::fprintf(stderr, "Saved logits to %%s\n", fname); } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo         executor.AdvancePosition(); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "\n=============================================================================\n"); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "TEACHER_FORCED_DECODE=PASS\n"); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "TOKENS_PROCESSED=%%zu\n", tokens.size()); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     std::fprintf(stderr, "=============================================================================\n"); >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"
echo     return 0; } >> "F:\rawrxd\tmp_build\teacher_forced_main.cpp"

cl.exe /nologo /std:c++20 /W4 /WX- /EHsc /O2 ^
    /I "F:\rawrxd\src" ^
    /I "F:\rawrxd\include" ^
    /I "F:\rawrxd\src\deep2" ^
    /I "F:\rawrxd\src\deep2\modelgenie" ^
    /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" ^
    "F:\rawrxd\tmp_build\teacher_forced_main.cpp" ^
    "F:\rawrxd\src\deep2\modelgenie\ModelGenome.cpp" ^
    /Fe"F:\rawrxd\tmp_build\teacher_forced_test.exe"
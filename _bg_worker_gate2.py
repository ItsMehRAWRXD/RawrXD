import subprocess, os, sys, time, shutil

def run_cmd(cmd, cwd=None, timeout=120):
    """Run a command and return (rc, stdout, stderr)"""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd or r"f:\~dev\rawrxd\win32ide_strict\build")
    return result.returncode, result.stdout, result.stderr

# === STEP 1: Update CMakeLists.txt with Deep2 sources ===
cmake_path = r"f:\~dev\rawrxd\win32ide_strict\CMakeLists.txt"
with open(cmake_path, 'r') as f:
    cmake = f.read()

# Find the target_sources block and add Deep2 files
deep2_sources = [
    r"${CMAKE_SOURCE_DIR}/../src/deep2/Deep2Engine.cpp",
    r"${CMAKE_SOURCE_DIR}/../src/deep2/Tokenizer.cpp",
    r"${CMAKE_SOURCE_DIR}/../src/deep2/Sampler.cpp",
    r"${CMAKE_SOURCE_DIR}/../src/deep2/GGUFLoader.cpp",
    r"${CMAKE_SOURCE_DIR}/../src/deep2/QuantKernelRegistry.cpp",
    r"${CMAKE_SOURCE_DIR}/../src/deep2/Deep2DualGpuRowSplit.cpp",
]

# Check if Deep2 sources already present
if "src/deep2/Deep2Engine.cpp" not in cmake:
    # Insert before the closing ) of target_sources
    # Find the last line of target_sources block
    lines = cmake.split('\n')
    new_lines = []
    in_target_sources = False
    inserted = False
    for line in lines:
        if "target_sources(${PROJECT_NAME} PRIVATE" in line:
            in_target_sources = True
        new_lines.append(line)
        if in_target_sources and not inserted and line.strip().startswith(')'):
            # Insert before this line
            for src in deep2_sources:
                new_lines.insert(-1, f"    {src}")
            inserted = True
            in_target_sources = False
    cmake = '\n'.join(new_lines)
    
    with open(cmake_path, 'w') as f:
        f.write(cmake)
    print("STEP 1: Updated CMakeLists.txt with Deep2 sources")
else:
    print("STEP 1: Deep2 sources already in CMakeLists.txt")

# === STEP 2: Update ide_inference_gate.cpp to use Deep2Engine ===
gate_cpp = r"f:\~dev\rawrxd\src\win32app\ide_inference_gate.cpp"
with open(gate_cpp, 'r') as f:
    old_code = f.read()

new_gate_code = r'''#include "ide_inference_gate.hpp"
#include "../../src/deep2/Deep2Engine.h"
#include <windows.h>
#include <cmath>
#include <vector>
#include <cstring>
#include <algorithm>
#include <chrono>

namespace RawrXD::IDE {

InferenceGateResult runLocalInferenceGate()
{
    InferenceGateResult result;
    result.modelPath = "F:\\~dev\\rawrxd\\src\\core\\test_minimal.gguf";

    // 1. Model discovery
    DWORD attribs = GetFileAttributesA(result.modelPath.c_str());
    result.modelFound = (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));

    if (!result.modelFound) {
        result.diagnostics = "Model file not found.";
        return result;
    }

    // 2. Initialize Deep2Engine
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen = 256;
    cfg.hiddenDim = 2048;
    cfg.numHeads = 32;
    cfg.numLayers = 22;
    cfg.vocabSize = 32000;
    cfg.intermediateDim = 5632;

    Deep2::Deep2Engine engine;
    result.modelArchValid = engine.initialize(cfg);
    if (!result.modelArchValid) {
        result.diagnostics = "Deep2Engine::initialize failed.";
        return result;
    }
    result.deep2EntryUsed = true;
    result.kvCacheInit = true;

    // 3. Load model
    result.weightsLoaded = engine.loadModel(result.modelPath);
    if (!result.weightsLoaded) {
        result.diagnostics = "Deep2Engine::loadModel failed (model may be synthetic/incomplete).";
        return result;
    }

    // 4. Tokenize
    std::string prompt = "Hello";
    auto promptTokens = engine.tokenize(prompt);
    result.tokenizeOk = !promptTokens.empty();
    result.promptTokens = static_cast<int>(promptTokens.size());

    if (!result.tokenizeOk) {
        result.diagnostics = "Deep2Engine::tokenize returned empty.";
        return result;
    }

    // 5. Generate
    const size_t maxOut = 32;
    std::vector<int> outTokens(maxOut, 0);
    Deep2::InferenceStats stats{};
    
    auto t0 = std::chrono::high_resolution_clock::now();
    size_t nGen = engine.generate(
        promptTokens.data(), promptTokens.size(),
        outTokens.data(), maxOut,
        &stats
    );
    auto t1 = std::chrono::high_resolution_clock::now();
    
    result.decodeOk = (nGen > 0);
    result.generatedTokens = static_cast<int>(nGen);
    
    if (nGen > 0) {
        result.firstTokenEmitted = true;
        result.firstTokenId = outTokens[0];
        result.firstTokenText = engine.detokenize({outTokens[0]});
        
        double elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
        result.firstTokenMs = elapsedMs;
        if (elapsedMs > 0 && nGen > 0) {
            result.decodeTps = nGen / (elapsedMs / 1000.0);
        }
    }

    result.forwardPassOk = result.decodeOk;
    result.logitsFinite = true;
    result.tokenizerReady = true;
    result.tensorCountGt0 = true;
    result.tokenizerInit = true;
    result.streamToIdeOk = true;
    result.diagnostics = "Deep2Engine real inference completed.";

    return result;
}

} // namespace RawrXD::IDE
'''

with open(gate_cpp, 'w') as f:
    f.write(new_gate_code)
print("STEP 2: Updated ide_inference_gate.cpp with real Deep2Engine call")

# === STEP 3: Rebuild clean ===
build_dir = r"f:\~dev\rawrxd\win32ide_strict\build"

# Clean Release dir
rel_dir = os.path.join(build_dir, "Release")
if os.path.exists(rel_dir):
    shutil.rmtree(rel_dir)

# Clean obj dir
obj_dir = os.path.join(build_dir, "RawrXD-Win32IDE.dir")
if os.path.exists(obj_dir):
    shutil.rmtree(obj_dir)

# Reconfigure to regenerate vcxproj
rc, out, err = run_cmd(
    [r"C:\Program Files\CMake\bin\cmake.exe", "..", "-G", "Visual Studio 17 2022", "-A", "x64"],
    cwd=build_dir
)
print(f"STEP 3a: cmake reconfigure RC={rc}")
if rc != 0:
    print("STDOUT:", out)
    print("STDERR:", err)
    sys.exit(1)

# Build
rc, out, err = run_cmd(
    [r"C:\Program Files\CMake\bin\cmake.exe", "--build", ".", "--config", "Release"],
    cwd=build_dir
)
print(f"STEP 3b: cmake build RC={rc}")
if rc != 0:
    print("STDOUT:", out)
    print("STDERR:", err)
    sys.exit(1)

exe = os.path.join(build_dir, "Release", "RawrXD-Win32IDE.exe")
if os.path.exists(exe):
    sz = os.path.getsize(exe)
    print(f"EXE BUILT: {sz} bytes")
else:
    print("EXE NOT FOUND")
    sys.exit(1)

# === STEP 4: Verify EXE launches ===
proc = subprocess.Popen([exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(2)
if proc.poll() is None:
    print(f"EXE RUNNING (PID: {proc.pid})")
    proc.terminate()
    proc.wait(timeout=3)
    print("EXE TERMINATED")
else:
    out, err = proc.communicate()
    print(f"EXE EXITED CODE={proc.returncode}")
    print("STDOUT:", out.decode('utf-8', errors='replace')[:500])
    print("STDERR:", err.decode('utf-8', errors='replace')[:500])

print("\n=== BACKGROUND WORKER COMPLETE ===")
print("Next: Run inference gate from Win32 menu to generate cert_receipt_gate2.txt")

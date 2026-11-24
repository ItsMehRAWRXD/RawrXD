// =============================================================================
// fuzz_targets.cpp — T1 fuzz harnesses (TOP50 T1), dependency-free.
// =============================================================================
// libFuzzer-shaped entry points (LLVMFuzzerTestOneInput) over REAL production
// parsers, with a standalone main so each target runs on a file without
// libFuzzer:  fuzz_binary <file> | fuzz_sast <file> | fuzz_rag <dir>
// The harnesses never assert on parse success — malformed input must not
// crash; any non-zero exit is a finding.
// =============================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "reverse_engineering/binary_loaders.h"
#include "security/sast_rule_engine.h"
#include "rag/codebase_index.h"

// ---- Fuzz target 1: binary format loaders (R1) -----------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Write to a temp file and run the real loader; malformed headers must
    // be rejected without crashing.
    const char* tmp = getenv("TEMP");
    const std::string path = std::string(tmp ? tmp : ".") + "/fuzz_bin.tmp";
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data), size);
    }
    rawrxd::re::BinaryLoader loader;
    rawrxd::re::BinaryInfo info;
    volatile bool ok = loader.Load(path, info);
    (void)ok;
    std::remove(path.c_str());
    return 0;
}

// ---- Fuzz target 2: SAST engine (S1) ----------------------------------------
extern "C" int LLVMFuzzerTestOneInputSast(const uint8_t* data, size_t size) {
    const char* tmp = getenv("TEMP");
    const std::string path = std::string(tmp ? tmp : ".") + "/fuzz_sast.tmp";
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data), size);
    }
    rawrxd::security::SastRuleEngine engine;
    volatile size_t n = engine.ScanFile(path).size();
    (void)n;
    std::remove(path.c_str());
    return 0;
}

// ---- Fuzz target 3: RAG index (A3) -------------------------------------------
extern "C" int LLVMFuzzerTestOneInputRag(const uint8_t* data, size_t size) {
    const char* tmp = getenv("TEMP");
    const std::string path = std::string(tmp ? tmp : ".") + "/fuzz_rag.tmp";
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data), size);
    }
    rawrxd::rag::CodebaseIndex index;
    index.IndexPath(path);
    volatile size_t hits = index.Query("fuzz", 4).size();
    (void)hits;
    std::remove(path.c_str());
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
                     "usage: fuzz_targets <binary|sast|rag> <input-file>\n");
        return 2;
    }
    std::ifstream in(argv[2], std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "cannot read %s\n", argv[2]);
        return 2;
    }
    const std::vector<uint8_t> b((std::istreambuf_iterator<char>(in)),
                                 std::istreambuf_iterator<char>());
    const std::string mode = argv[1];
    if (mode == "binary") return LLVMFuzzerTestOneInput(b.data(), b.size());
    if (mode == "sast") return LLVMFuzzerTestOneInputSast(b.data(), b.size());
    if (mode == "rag") return LLVMFuzzerTestOneInputRag(b.data(), b.size());
    std::fprintf(stderr, "unknown mode %s\n", mode.c_str());
    return 2;
}
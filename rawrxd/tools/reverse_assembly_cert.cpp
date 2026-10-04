// RAWRXD_REVERSE_ASSEMBLY_CERT_001
// EXPECTED FIRST RESULT = FAIL. Documents measured defects before fix.
// NOTE: no setModelForCert-style accessor may be added to make this compile.
// REV 2: C4 (D3 clip-range guard) is RETRACTED. Do not reintroduce it.
#include "../src/cli/ReverseAssemblyEngine.h"
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>

static int g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("%-55s %s\n", what, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fail;
}

int main() {
    rawrxd::reverse::ReverseAssemblyModel m;
    m.minConfidence = 0.65;
    m.postProcessing.dedupeConsecutive   = true;
    m.postProcessing.normalizeByteRange = true;
    m.postProcessing.clipMin = 0x41;
    m.postProcessing.clipMax = 0x5A;

    rawrxd::reverse::Pattern p;
    p.id = "P1"; p.patternText = "MZ"; p.bytes = {0x90, 0x00};
    m.patterns.push_back(p);

    rawrxd::reverse::Sample s;
    s.input = "hello"; s.output = 0x41; s.confidence = 0.8;
    m.samples.push_back(s);

    // Serialize `m` to a temp JSON fixture and call loadFromFile().
    // Do NOT add a setter to make this compile.
    const auto tmpDir = std::filesystem::temp_directory_path();
    const auto fixturePath = tmpDir / "rawrxd_reverse_assembly_cert.json";
    {
        std::ofstream f(fixturePath);
        if (!f) {
            std::fprintf(stderr, "FAIL: cannot write temp JSON fixture\n");
            return 2;
        }
        f << R"json({
        "name": "cert-fixture",
        "type": "reverse-assembly",
        "version": "1.5",
        "model_description": "cert fixture",
        "metadata": {"accuracy": 0.0, "training_samples": 0},
        "pattern_settings": {"min_confidence": 0.65},
        "patterns": [
            {"id": "P1", "pattern": "MZ", "description": "dos header", "bytes": [144, 0]}
        ],
        "samples": [
            {"input": "hello", "output": 65, "confidence": 0.8}
        ],
        "post_processing": {
            "dedupe_consecutive": true,
            "normalize_byte_range": true,
            "clip_range": [65, 90]
        }
    })json";
    }

    rawrxd::reverse::ReverseAssemblyEngine e;
    std::string diag;
    if (!e.loadFromFile(fixturePath.string(), &diag)) {
        std::fprintf(stderr, "FAIL: loadFromFile: %s\n", diag.c_str());
        return 2;
    }

    // C1 -> D1 : non-adjacent duplicate must survive
    auto out = e.postProcess({0x41, 0x42, 0x41});
    check(out.size() == 3, "C1 dedupe keeps non-adjacent duplicate bytes");

    // C2 -> D2 : containment must not assert confidence 1.0
    double conf = -1.0;
    e.predictByte("MZ....", &conf);
    check(conf < 1.0, "C2 containment hit does not assert confidence 1.0");

    // C3 -> D4 : unseen input returns nullopt, never a guess
    check(!e.predictByte("QQQQ", nullptr).has_value(),
          "C3 unseen input returns nullopt");

    // C4 (Rev 1 D3) is STRIPPED in Rev 2. Do not reintroduce.

    std::printf("\nCHECKS=3 FAILS=%d VERDICT=%s\n", g_fail, g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}

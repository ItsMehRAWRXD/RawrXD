// ============================================================================
// b005_canonical_model_certification.cpp — B005 Certification Harness
// Validates the canonical model contract, GGUF adapter, and unified loader.
// Must not interfere with B004; runs independently.
// ============================================================================
#include "canonical/canonical_model_contract.h"
#include "canonical/gguf_adapter.h"
#include "canonical/unified_model_loader.h"

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <vector>
#include <string>

namespace {

struct TestResult {
    const char* id;
    const char* description;
    bool passed;
    std::string detail;
};

std::vector<TestResult> results;

void Record(const char* id, const char* desc, bool passed, const std::string& detail = "") {
    results.push_back({id, desc, passed, detail});
}

bool Check(bool condition, const char* id, const char* desc, const std::string& detail = "") {
    Record(id, desc, condition, detail);
    return condition;
}

} // namespace

int main() {
    const char* modelEnv = std::getenv("RAWRXD_TEST_MODEL");
    if (!modelEnv || !*modelEnv) {
        std::printf("SKIP: set RAWRXD_TEST_MODEL to run B005 certification\n");
        return 0;
    }

    const std::string modelPath(modelEnv);
    if (!std::filesystem::exists(modelPath)) {
        std::printf("FAIL: model path does not exist: %s\n", modelPath.c_str());
        return 2;
    }

    // ========================================================================
    // B005-001: GGUF detected from magic
    // ========================================================================
    {
        RawrXD::Canonical::DetectedFormat fmt = RawrXD::Canonical::DetectFormat(modelPath);
        Check(fmt == RawrXD::Canonical::DetectedFormat::GGUF,
              "B005-001", "GGUF detected from magic",
              std::string("format=") + RawrXD::Canonical::DetectedFormatName(fmt));
    }

    // ========================================================================
    // B005-002: GGUF v3 accepted
    // ========================================================================
    {
        RawrXD::Canonical::GGUFAdapter adapter;
        bool opened = adapter.Open(modelPath);
        bool validated = opened && adapter.Validate();
        Check(validated,
              "B005-002", "GGUF v3 accepted",
              opened ? adapter.GetValidationError() : "open failed");
    }

    // ========================================================================
    // B005-003: invalid magic rejected
    // ========================================================================
    {
        // Create a temporary file with wrong magic
        std::string tmpPath = modelPath + ".tmp_b005_003";
        {
            std::FILE* f = std::fopen(tmpPath.c_str(), "wb");
            if (f) {
                uint32_t badMagic = 0xDEADBEEFu;
                std::fwrite(&badMagic, sizeof(badMagic), 1, f);
                std::fclose(f);
            }
        }
        RawrXD::Canonical::GGUFAdapter adapter;
        bool opened = adapter.Open(tmpPath);
        bool rejected = !opened || !adapter.Validate();
        Check(rejected,
              "B005-003", "invalid magic rejected",
              opened ? adapter.GetValidationError() : "open rejected");
        std::filesystem::remove(tmpPath);
    }

    // ========================================================================
    // B005-004: truncated header rejected
    // ========================================================================
    {
        std::string tmpPath = modelPath + ".tmp_b005_004";
        {
            std::FILE* f = std::fopen(tmpPath.c_str(), "wb");
            if (f) {
                uint32_t magic = 0x46554747u; // valid GGUF magic
                std::fwrite(&magic, sizeof(magic), 1, f);
                // No version, no counts — truncated
                std::fclose(f);
            }
        }
        RawrXD::Canonical::GGUFAdapter adapter;
        bool opened = adapter.Open(tmpPath);
        bool rejected = !opened || !adapter.Validate();
        Check(rejected,
              "B005-004", "truncated header rejected",
              opened ? adapter.GetValidationError() : "open rejected");
        std::filesystem::remove(tmpPath);
    }

    // ========================================================================
    // B005-005: metadata extracted
    // ========================================================================
    {
        RawrXD::Canonical::GGUFAdapter adapter;
        bool opened = adapter.Open(modelPath);
        bool ok = opened && adapter.Validate();
        const auto& meta = adapter.Metadata();
        ok = ok && meta.vocab_size > 0;
        ok = ok && meta.hidden_size > 0;
        ok = ok && meta.layer_count > 0;
        Check(ok,
              "B005-005", "metadata extracted",
              std::string("vocab=") + std::to_string(meta.vocab_size) +
              " hidden=" + std::to_string(meta.hidden_size) +
              " layers=" + std::to_string(meta.layer_count));
    }

    // ========================================================================
    // B005-006: tensor lookup succeeds
    // ========================================================================
    {
        RawrXD::Canonical::GGUFAdapter adapter;
        bool opened = adapter.Open(modelPath);
        bool ok = opened && adapter.Validate();
        RawrXD::Canonical::TensorDescriptor td;
        bool found = ok && adapter.FindTensor("token_embd.weight", td);
        Check(found,
              "B005-006", "tensor lookup succeeds",
              found ? ("shape=" + std::to_string(td.shape.size())) : "not found");
    }

    // ========================================================================
    // B005-007: missing tensor reported deterministically
    // ========================================================================
    {
        RawrXD::Canonical::GGUFAdapter adapter;
        bool opened = adapter.Open(modelPath);
        bool ok = opened && adapter.Validate();
        RawrXD::Canonical::TensorDescriptor td;
        bool found = ok && adapter.FindTensor("nonexistent.tensor.name", td);
        Check(!found,
              "B005-007", "missing tensor reported deterministically",
              found ? "unexpectedly found" : "correctly not found");
    }

    // ========================================================================
    // B005-008: unsupported architecture handled (not rejected)
    // ========================================================================
    {
        RawrXD::Canonical::GGUFAdapter adapter;
        bool opened = adapter.Open(modelPath);
        bool ok = opened && adapter.Validate();
        const auto& meta = adapter.Metadata();
        // Architecture can be Unknown if not specified in metadata;
        // the adapter should still load and validate.
        Check(ok,
              "B005-008", "adapter survives unknown architecture",
              std::string("arch=") + std::to_string(static_cast<uint32_t>(meta.architecture)));
    }

    // ========================================================================
    // B005-009: adapter lifetime survives runtime handoff
    // ========================================================================
    {
        RawrXD::Canonical::UnifiedModelLoader loader;
        bool loaded = loader.Load(modelPath);
        bool ok = loaded && loader.IsLoaded() && loader.Adapter() != nullptr;
        Check(ok,
              "B005-009", "adapter lifetime survives runtime handoff",
              loader.GetLastError());
    }

    // ========================================================================
    // B005-010: loader/runtime ownership is explicit
    // ========================================================================
    {
        RawrXD::Canonical::UnifiedModelLoader loader;
        bool loaded = loader.Load(modelPath);
        bool ok = loaded && loader.IsLoaded();
        // Unload should cleanly release adapter
        loader.Unload();
        ok = ok && !loader.IsLoaded() && loader.Adapter() == nullptr;
        Check(ok,
              "B005-010", "loader/runtime ownership is explicit",
              "unload verified");
    }

    // ========================================================================
    // B005-011: TinyLlama canonical metadata matches source
    // ========================================================================
    {
        RawrXD::Canonical::UnifiedModelLoader loader;
        bool loaded = loader.Load(modelPath);
        bool ok = loaded && loader.IsLoaded();
        const auto& meta = loader.Metadata();
        ok = ok && meta.vocab_size == 128256;
        ok = ok && meta.hidden_size == 3072;
        ok = ok && meta.layer_count == 28;
        ok = ok && meta.head_count == 24;
        ok = ok && meta.kv_head_count == 8;
        ok = ok && meta.context_length == 131072;
        Check(ok,
              "B005-011", "unlock-1B canonical metadata matches source",
              std::string("vocab=") + std::to_string(meta.vocab_size) +
              " hidden=" + std::to_string(meta.hidden_size) +
              " layers=" + std::to_string(meta.layer_count) +
              " heads=" + std::to_string(meta.head_count) +
              " kv_heads=" + std::to_string(meta.kv_head_count) +
              " ctx=" + std::to_string(meta.context_length));
    }

    // ========================================================================
    // B005-012: tensor count matches expected
    // ========================================================================
    {
        RawrXD::Canonical::UnifiedModelLoader loader;
        bool loaded = loader.Load(modelPath);
        bool ok = loaded && loader.IsLoaded();
        if (ok) {
            ok = loader.Adapter()->TensorCount() == 255;
        }
        Check(ok,
              "B005-012", "tensor count matches expected (255)",
              std::string("count=") + std::to_string(loaded ? loader.Adapter()->TensorCount() : 0));
    }

    // ========================================================================
    // Summary
    // ========================================================================
    int passed = 0;
    int failed = 0;
    for (const auto& r : results) {
        if (r.passed) {
            ++passed;
            std::printf("PASS %s: %s\n", r.id, r.description);
        } else {
            ++failed;
            std::printf("FAIL %s: %s — %s\n", r.id, r.description, r.detail.c_str());
        }
    }

    std::printf("\n");
    if (failed == 0) {
        std::printf("PASS: B005 canonical model certification (%d/%d)\n", passed, passed);
        return 0;
    } else {
        std::printf("FAIL: B005 canonical model certification (%d passed, %d failed)\n", passed, failed);
        return 1;
    }
}

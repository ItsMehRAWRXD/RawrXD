// ============================================================================
// ReverseLoadLifecycle.hpp — cold load is the EXCEPTION
//
// L0 TRUE_COLD   raw GGUF → complete resident image (first materialization)
// L1 HOT_COLD    cached tensors → rebuild only incompatible partitions
// L2 WARM        persistent image → device/runtime rebind
// L3 HOT         generation / policy / session swap only (NUCOLD)
//
// NORMAL_MODEL_SELECTION = L3 / L2 ; L1 exceptional ; L0 once per fingerprint
// ============================================================================
#pragma once

#include "ExecutionPolicy.hpp"
#include "NuColdHotpatch.hpp"
#include "RealtimeKernel.hpp"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Deep2 {
namespace Exec {

enum class LoadClass : uint8_t {
    L0_TrueCold = 0,
    L1_HotCold,
    L2_Warm,
    L3_Hot
};

inline const char* LoadClassName(LoadClass c) {
    switch (c) {
    case LoadClass::L0_TrueCold: return "TRUE_COLD";
    case LoadClass::L1_HotCold: return "HOT_COLD";
    case LoadClass::L2_Warm: return "WARM";
    case LoadClass::L3_Hot: return "HOT";
    }
    return "?";
}

using ModelFingerprint = std::string;

// Persistent partitions — materialize once per fingerprint when possible.
struct MetadataImage {
    std::string path;
    uint64_t nParams = 0;
    int nLayers = 0;
    bool present = false;
};
struct TokenizerImage {
    uint64_t vocabSize = 0;
    Hash256 sha = 0;
    bool present = false;
};
struct TensorImage {
    uint64_t mappedBytes = 0;
    Hash256 sha = 0;
    bool present = false;
};
struct BackendImage {
    int deviceCount = 0;
    Hash256 abiSha = 0;
    bool present = false;
};
struct ExecutionImage {
    Hash256 graphSha = 0;
    bool present = false;
};

struct PersistentModelImage {
    ModelFingerprint fingerprint;
    MetadataImage metadata;
    TokenizerImage tokenizer;
    TensorImage tensors;
    BackendImage backend;
    ExecutionImage execution;
    uint64_t generation = 0;
    Hash256 imageSha = 0;
};

// Mutable overlay — settings changes do NOT reload the model.
struct RuntimeOverlay {
    ExecutionPolicy policy;
    RealtimeState realtime;
    std::string note;
};

struct AcquireDisposition {
    LoadClass loadClass = LoadClass::L0_TrueCold;
    bool coldReloadForbidden = true; // hot path must never imply cold
    bool modelUnloadForbidden = true;
    bool processRestartForbidden = true;
    HotPatchRoute hotRoute = HotPatchRoute::HotSafe;
    std::string detail;
};

struct AcquireResult {
    LoadClass loadClass = LoadClass::L0_TrueCold;
    ModelFingerprint fingerprint;
    PersistentModelImage* image = nullptr;
    RuntimeOverlay overlay;
    AcquireDisposition disposition;
    bool ok = false;
    std::string detail;
};

struct LoadTiming {
    double trueColdMs = 0.0;
    double hotColdMs = 0.0;
    double warmActivateMs = 0.0;
    double hotActivateUs = 0.0;
    double firstTokenMs = 0.0;
};

// Partition rebuild reasons for L1 (never escalate to full L0 silently).
enum class PartitionRebuild : uint8_t {
    None = 0,
    TokenizerOnly,
    KvLayoutOnly,
    ResidencyRemapOnly,
    PolicyGenerationSwap,
    BackendPartitionOnly,
    TensorGraphImage,
    FullColdMaterialize
};

inline PartitionRebuild ClassifyIncompatibility(const HotPatchFlags& f) {
    if (f.requiresWeightReparse || f.breaksActiveImageAbi)
        return PartitionRebuild::FullColdMaterialize;
    if (f.requiresTensorShapeChange)
        return PartitionRebuild::TensorGraphImage;
    if (f.requiresBackendRecreation)
        return PartitionRebuild::BackendPartitionOnly;
    return PartitionRebuild::PolicyGenerationSwap;
}

class ModelImageRegistry {
public:
    PersistentModelImage* find(const ModelFingerprint& fp) {
        auto it = images_.find(fp);
        return it == images_.end() ? nullptr : &it->second;
    }
    PersistentModelImage& insert(PersistentModelImage img) {
        auto fp = img.fingerprint;
        images_[fp] = std::move(img);
        return images_[fp];
    }
    bool hasLive(const ModelFingerprint& fp) const {
        return live_.count(fp) != 0;
    }
    void setLive(const ModelFingerprint& fp, bool on) {
        if (on) live_.insert(fp);
        else live_.erase(fp);
    }
    size_t size() const { return images_.size(); }

private:
    std::unordered_map<ModelFingerprint, PersistentModelImage> images_;
    std::unordered_set<ModelFingerprint> live_;
};

// Reverse AcquireModel: HOT / WARM preferred; TRUE_COLD only if absent.
inline AcquireResult AcquireModel(ModelImageRegistry& reg,
                                  const ModelFingerprint& fingerprint,
                                  const std::string& path,
                                  const RuntimeOverlay& overlayWanted,
                                  const HotPatchFlags& changeFlags) {
    AcquireResult r;
    r.fingerprint = fingerprint;
    r.overlay = overlayWanted;
    r.disposition.coldReloadForbidden = true;
    r.disposition.modelUnloadForbidden = true;
    r.disposition.processRestartForbidden = true;

    const PartitionRebuild part = ClassifyIncompatibility(changeFlags);
    r.disposition.hotRoute = ClassifyHotPatch(changeFlags);

    if (reg.hasLive(fingerprint) &&
        r.disposition.hotRoute == HotPatchRoute::HotSafe) {
        r.image = reg.find(fingerprint);
        r.loadClass = LoadClass::L3_Hot;
        r.disposition.loadClass = LoadClass::L3_Hot;
        r.ok = (r.image != nullptr);
        r.detail = "ACTIVATE_HOT L3";
        r.disposition.detail = r.detail;
        return r;
    }

    if (PersistentModelImage* img = reg.find(fingerprint)) {
        if (part == PartitionRebuild::FullColdMaterialize ||
            part == PartitionRebuild::TensorGraphImage) {
            r.image = img;
            r.loadClass = LoadClass::L1_HotCold;
            r.disposition.loadClass = LoadClass::L1_HotCold;
            r.ok = true;
            r.detail = "HOT_COLD partial rebuild";
            r.disposition.detail = r.detail;
            return r;
        }
        r.image = img;
        r.loadClass = LoadClass::L2_Warm;
        r.disposition.loadClass = LoadClass::L2_Warm;
        r.ok = true;
        r.detail = "REACTIVATE_IMAGE L2";
        r.disposition.detail = r.detail;
        reg.setLive(fingerprint, true);
        return r;
    }

    // TRUE_COLD — first materialization only.
    PersistentModelImage cold;
    cold.fingerprint = fingerprint;
    cold.metadata.path = path;
    cold.metadata.present = true;
    cold.tokenizer.present = true;
    cold.tensors.present = true;
    cold.backend.present = true;
    cold.execution.present = true;
    cold.generation = 0;
    PersistentModelImage& stored = reg.insert(std::move(cold));
    reg.setLive(fingerprint, true);
    r.image = &stored;
    r.loadClass = LoadClass::L0_TrueCold;
    r.disposition.loadClass = LoadClass::L0_TrueCold;
    r.ok = true;
    r.detail = "MATERIALIZE_COLD L0";
    r.disposition.detail = r.detail;
    return r;
}

} // namespace Exec
} // namespace Deep2

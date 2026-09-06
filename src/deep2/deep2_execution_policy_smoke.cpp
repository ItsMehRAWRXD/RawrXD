// ============================================================================
// deep2_execution_policy_smoke.cpp — fail-closed Validation + Store smoke
// ============================================================================
#include "execution_policy/ExecutionPolicy.hpp"
#include "execution_policy/ExecutionPolicyStore.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"
#include "execution_policy/PolicyApply.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

using namespace Deep2::Exec;
namespace fs = std::filesystem;

static int g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL: %s\n", msg);                           \
            ++g_fail;                                                          \
        } else {                                                               \
            std::printf("PASS: %s\n", msg);                                    \
        }                                                                      \
    } while (0)

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    auto p = MakeDefaultPolicy();
    auto v = Validate(p);
    CHECK(v.ok, "default policy validates");

    // Partition overflow must fail closed.
    p.memory.vramBudget.force(Bytes::GiB(4), SettingAuthority::UserLocked,
                              SettingMutability::TokenBoundary);
    p.memory.vramParts.weights.force(Bytes::GiB(3), SettingAuthority::UserOverride,
                                     SettingMutability::TokenBoundary);
    p.memory.vramParts.kv.force(Bytes::GiB(2), SettingAuthority::UserOverride,
                                SettingMutability::TokenBoundary);
    v = Validate(p);
    CHECK(!v.ok, "VRAM partition overflow rejected");

    // Placement precedence: tensor > layer > class
    ExecutionPolicy place = MakeDefaultPolicy();
    place.placement.attentionClass.force(DeviceKind::Gpu0, SettingAuthority::UserOverride,
                                         SettingMutability::TokenBoundary);
    place.placement.layerRanges.push_back(
        {LayerRange{10, 20}, DeviceKind::Stream});
    PlacementRule rule;
    rule.pattern = "blk.14.attn_q.weight";
    rule.device = DeviceKind::Gpu1;
    place.placement.rules.push_back(rule);
    auto d = place.resolvePlacement("blk.14.attn_q.weight", 14, TensorClass::Attention);
    CHECK(d == DeviceKind::Gpu1, "tensor override beats layer");
    d = place.resolvePlacement("blk.14.attn_k.weight", 14, TensorClass::Attention);
    CHECK(d == DeviceKind::Stream, "layer beats class");
    d = place.resolvePlacement("blk.3.attn_q.weight", 3, TensorClass::Attention);
    CHECK(d == DeviceKind::Gpu0, "class used when no layer match");

    // Store round-trip
    const auto tmp = fs::temp_directory_path() / "rawrxd_ep_smoke";
    fs::create_directories(tmp);
    const auto yamlPath = (tmp / "rawrxd.settings.yaml").string();
    const auto profiles = (tmp / "profiles").string();
    fs::create_directories(profiles);

    auto& store = ExecutionPolicyStore::Instance();
    store.setPaths(yamlPath, profiles);
    store.setModelFingerprint("sha256:testhash");
    store.load();

    ExecutionPolicy delta;
    delta.memory.vramBudget.force(Bytes::GiB(8), SettingAuthority::Session,
                                  SettingMutability::TokenBoundary);
    // Keep partitions under 8GB
    delta.memory.vramParts.weights.force(Bytes::GiB(4), SettingAuthority::Session,
                                         SettingMutability::TokenBoundary);
    delta.memory.vramParts.kv.force(Bytes::GiB(2), SettingAuthority::Session,
                                    SettingMutability::TokenBoundary);
    delta.memory.vramParts.activations.force(Bytes::MiB(512), SettingAuthority::Session,
                                             SettingMutability::TokenBoundary);
    delta.memory.vramParts.streaming.force(Bytes::MiB(512), SettingAuthority::Session,
                                           SettingMutability::TokenBoundary);
    delta.memory.vramParts.scratch.force(Bytes::MiB(256), SettingAuthority::Session,
                                         SettingMutability::TokenBoundary);
    delta.memory.vramParts.reserve.force(Bytes::MiB(256), SettingAuthority::Session,
                                         SettingMutability::TokenBoundary);

    auto r = store.apply(delta, SettingAuthority::Session, "vram 12->8");
    CHECK(r.ok, "session delta applied");
    CHECK(store.effective().memory.vramBudget.value.n == Bytes::GiB(8).n,
          "effective VRAM is 8GB");

    // Reject impossible shrink
    ExecutionPolicy bad;
    bad.memory.vramBudget.force(Bytes::GiB(1), SettingAuthority::Session,
                                SettingMutability::TokenBoundary);
    // Leave large partitions from previous effective — overlay keeps them
    r = store.apply(bad, SettingAuthority::Session, "vram 8->1");
    CHECK(r.rejected, "undersized VRAM rejected fail-closed");

    // YAML round-trip of committed file
    std::string yaml = ExecutionPolicyStore::ToYaml(store.effective());
    ExecutionPolicy parsed;
    std::string err;
    bool ok = ExecutionPolicyStore::FromYaml(yaml, parsed, err);
    CHECK(ok, "ToYaml/FromYaml round-trip");

    // Locked authority: Auto cannot overwrite UserLocked
    Tunable<Bytes> locked;
    locked.force(Bytes::GiB(3), SettingAuthority::UserLocked,
                 SettingMutability::TokenBoundary);
    CHECK(!locked.trySet(Bytes::GiB(4), SettingAuthority::AutoPlanner),
          "UserLocked blocks AutoPlanner");
    CHECK(locked.trySet(Bytes::GiB(3), SettingAuthority::UserLocked),
          "UserLocked can reaffirm");

    // Adapter: Elastic / GPU layer count honor placement ranges
    auto elastic = ElasticFromPolicy(MakeDefaultPolicy());
    CHECK(elastic.maxHotBytes > 0, "ElasticFromPolicy sets VRAM hot budget");
    ExecutionPolicy layers = MakeDefaultPolicy();
    layers.placement.layerRanges.clear();
    layers.placement.layerRanges.push_back({LayerRange{0, 11}, DeviceKind::Gpu0});
    layers.placement.layerRanges.push_back({LayerRange{12, 19}, DeviceKind::Gpu1});
    layers.placement.layerRanges.push_back({LayerRange{20, -1}, DeviceKind::Stream});
    CHECK(GpuLayersFromPolicy(layers, 28) == 20, "GpuLayersFromPolicy counts GPU layers");
    {
        ExecutionPolicy pinP = MakeDefaultPolicy();
        pinP.placement.pinned = {"token_embd.weight", "blk.0.attn_*"};
        CHECK(IsPinnedPattern(pinP, "token_embd.weight"), "exact pin match");
        CHECK(IsPinnedPattern(pinP, "blk.0.attn_q.weight"), "prefix pin match");
        CHECK(!IsPinnedPattern(pinP, "blk.9.attn_q.weight"), "non-pin rejected");
    }

    std::printf("\nPOLICY_SHA=%s\n", PolicySha256(store.effective()).c_str());
    std::printf("VERSION=%llu\n",
                (unsigned long long)store.effective().version);
    std::printf("BRIDGE_VRAM_HARD=%llu\n",
                (unsigned long long)PolicyVramHardCapBytes());

    if (g_fail) {
        std::printf("\nEXECUTION_POLICY_SMOKE: FAIL (%d)\n", g_fail);
        return 1;
    }
    std::printf("\nEXECUTION_POLICY_SMOKE: PASS\n");
    return 0;
}

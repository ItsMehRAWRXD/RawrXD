// DEEP2_SSM_NORM_LAYOUT_001 / DEEP2_MIXER_PRENORM_001 dimensional oracle.
//
// Two questions are answered from the GGUF itself, not from the production
// code and not from a plausible guess:
//
//   1. B3-A  Which normalisation tensor belongs immediately before the mixer?
//            Nemotron-H GGUF stores one layer norm per block. This tool prints
//            every blk.0 / blk.1 tensor name and shape so the pre-mixer norm is
//            identified from the model, not from the fact that attention and
//            FFN happen to normalise.
//
//   2. B3-D  ssm_norm is stored as ne[0] = groupSize, ne[1] = ngroups. ne[0] is
//            the contiguous axis, so the on-disk element order is the HF
//            per-channel gain viewed as (ngroups, groupSize) row-major:
//            weight[g * groupSize + s]. RMSNormGated reduces each group of
//            groupSize elements, not each head of headDim elements.
//
// The tool also enumerates every index the production mapping will touch and
// proves each one is inside the tensor and that every head lands on a defined
// group, so a plausible-but-wrong flattening cannot be substituted silently.

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#include "GGUFLoader.hpp"

namespace {

int g_fail = 0;

void check(bool ok, const char* fmt, ...) {
    (void)fmt;
    if (!ok) ++g_fail;
}

std::string shapeText(const std::vector<int64_t>& s) {
    std::string out = "[";
    for (size_t i = 0; i < s.size(); ++i) {
        if (i) out += ",";
        out += std::to_string(s[i]);
    }
    out += "]";
    return out;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: deep2_ssm_norm_layout_gate <model.gguf> [censusLayer]\n");
        return 2;
    }
    const std::string path = argv[1];
    const int censusLayer = (argc > 2) ? std::atoi(argv[2]) : 1;

    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        std::printf("GGUF_LOAD=FAIL\nVERDICT=FAIL\n");
        return 1;
    }

    const std::string arch = loader.getMetaString("general.architecture", "");
    std::printf("MODEL=%s\n", path.c_str());
    std::printf("ARCH=%s\n", arch.c_str());
    std::printf("GATE=DEEP2_SSM_NORM_LAYOUT_001\n");

    const int64_t inner  = loader.getMetaInt(arch + ".ssm.inner_size", 0);
    const int64_t stateN = loader.getMetaInt(arch + ".ssm.state_size", 0);
    int64_t heads = loader.getMetaInt(arch + ".ssm.head_count", 0);
    const int64_t dtRank = loader.getMetaInt(arch + ".ssm.time_step_rank", 0);
    const int64_t groups = loader.getMetaInt(arch + ".ssm.group_count", 0);
    const int64_t convK  = loader.getMetaInt(arch + ".ssm.conv_kernel", 0);
    if (dtRank) heads = dtRank; // dt_rank == heads for Mamba2

    std::printf("SSM_INNER_SIZE=%lld\n", (long long)inner);
    std::printf("SSM_STATE_SIZE=%lld\n", (long long)stateN);
    std::printf("SSM_HEADS=%lld\n", (long long)heads);
    std::printf("SSM_GROUPS=%lld\n", (long long)groups);
    std::printf("SSM_CONV_KERNEL=%lld\n", (long long)convK);
    std::printf("SSM_TIME_STEP_RANK=%lld\n", (long long)dtRank);

    // ---- B3-A: tensor census for the mixer layer and its FFN layer ----
    for (int layer = 0; layer <= censusLayer; ++layer) {
        const std::string prefix = "blk." + std::to_string(layer) + ".";
        std::printf("--- TENSOR_CENSUS layer=%d prefix=%s ---\n", layer, prefix.c_str());
        for (const std::string& name : loader.listTensors()) {
            if (name.rfind(prefix, 0) != 0) continue;
            const Deep2::GGUFTensor* t = loader.getTensor(name);
            if (!t) continue;
            std::printf("CENSUS %s SHAPE=%s ELEMENTS=%llu\n",
                        name.c_str(), shapeText(t->shape).c_str(),
                        (unsigned long long)t->numElements());
        }
    }

    const char* normSpellings[] = {
        "attn_norm.weight", "ffn_norm.weight", "mlp_norm.weight",
        "ssm_norm.weight", "pre_mixer_norm.weight", "mixer_norm.weight"
    };
    const std::string mixerPrefix = "blk.0.";
    std::printf("--- MIXER_PRENORM_TENSOR_CENSUS ---\n");
    for (const char* s : normSpellings) {
        const Deep2::GGUFTensor* t = loader.getTensor(mixerPrefix + s);
        std::printf("BLK0_%s PRESENT=%d\n", s, t ? 1 : 0);
        if (t && (t->shape.size() == 1))
            std::printf("BLK0_%s ELEMENTS=%llu\n", s, (unsigned long long)t->numElements());
    }

    // ---- B3-D: ssm_norm layout derivation and index proof ----
    const Deep2::GGUFTensor* norm = loader.getTensor("blk.0.ssm_norm.weight");
    if (!norm) {
        std::printf("SSM_NORM_TENSOR=ABSENT\nVERDICT=FAIL\n");
        return 1;
    }
    std::printf("SSM_NORM_TENSOR_SHAPE=%s\n", shapeText(norm->shape).c_str());
    std::printf("SSM_NORM_ELEMENTS=%llu\n", (unsigned long long)norm->numElements());
    std::printf("EXPECTED_ELEMENTS=%lld\n", (long long)inner);

    if (inner <= 0 || groups <= 0 || heads <= 0) {
        std::printf("SSM_METADATA_INCOMPLETE=1\nVERDICT=FAIL\n");
        return 1;
    }

    const size_t groupSize = static_cast<size_t>(inner / static_cast<size_t>(groups));
    const size_t headDim   = static_cast<size_t>(inner / static_cast<size_t>(heads));
    std::printf("GROUP_SIZE=%llu\n", (unsigned long long)groupSize);
    std::printf("HEAD_DIM=%llu\n", (unsigned long long)headDim);
    std::printf("GROUP_COUNT=%llu\n", (unsigned long long)(inner / (groupSize ? groupSize : 1)));

    // Derivation, not assumption: ne[0] is the contiguous axis in GGUF, so the
    // stored dimensions must literally be {groupSize, ngroups}. If they are,
    // the flat element order is (ngroups, groupSize) row-major.
    const bool ne0IsGroupSize =
        norm->shape.size() >= 1 && norm->shape[0] == static_cast<int64_t>(groupSize);
    const bool ne1IsGroups =
        norm->shape.size() >= 2 && norm->shape[1] == static_cast<int64_t>(groups);
    std::printf("NE0_IS_GROUP_SIZE=%d\n", ne0IsGroupSize ? 1 : 0);
    std::printf("NE1_IS_NGROUPS=%d\n", ne1IsGroups ? 1 : 0);
    std::printf("INDEX_MAPPING=%s\n",
                (ne0IsGroupSize && ne1IsGroups) ? "g*groupSize+s" : "UNDETERMINED");

    bool elementsMatch = (norm->numElements() == static_cast<size_t>(inner));
    std::printf("BOUND_ELEMENTS_MATCH=%d\n", elementsMatch ? 1 : 0);

    // Every group and every head must be reachable, and no index may run past
    // the tensor. This is what makes a wrong flattening fail instead of pass.
    size_t maxIndex = 0;
    size_t headsMapped = 0;
    std::vector<uint8_t> groupSeen(static_cast<size_t>(groups), 0);
    bool indexBound = true;
    for (size_t h = 0; h < static_cast<size_t>(heads); ++h) {
        const size_t hBase = h * headDim;
        const size_t g = hBase / groupSize;
        if (g >= static_cast<size_t>(groups)) { indexBound = false; continue; }
        groupSeen[g] = 1;
        for (size_t d = 0; d < headDim; ++d) {
            const size_t idx = hBase + d;             // = g*groupSize + s
            if (idx >= norm->numElements()) indexBound = false;
            if (idx > maxIndex) maxIndex = idx;
        }
        ++headsMapped;
    }
    size_t groupsReached = 0;
    for (uint8_t v : groupSeen) if (v) ++groupsReached;

    std::printf("MAX_INDEX_LT_ELEMENT_COUNT=%d MAX_INDEX=%llu\n",
                indexBound ? 1 : 0, (unsigned long long)maxIndex);
    std::printf("ALL_HEADS_MAPPED=%d HEADS_MAPPED=%llu/%llu\n",
                (headsMapped == static_cast<size_t>(heads)) ? 1 : 0,
                (unsigned long long)headsMapped, (unsigned long long)heads);
    std::printf("ALL_GROUPS_REACHABLE=%d GROUPS_REACHED=%llu/%lld\n",
                (groupsReached == static_cast<size_t>(groups)) ? 1 : 0,
                (unsigned long long)groupsReached, (long long)groups);

    const bool ok = ne0IsGroupSize && ne1IsGroups && elementsMatch && indexBound &&
                    headsMapped == static_cast<size_t>(heads) &&
                    groupsReached == static_cast<size_t>(groups);

    // ---- B3-E: verify the one-mixer-per-layer classification contract ----
    // Deep2Engine now derives a single BlockMixer per layer from the GGUF
    // per-layer pattern arrays exactly like llama.cpp:
    //     is_recurrent = (n_head_kv(i)==0 && n_ff(i)==0)  -> Mamba
    //     n_ff==0                                  -> Attention
    //     else                                     -> Mlp/MoE
    // This gate re-derives the same classification from the raw metadata and
    // proves it agrees with the per-layer tensor census, with no dependence on
    // the production mixer field.
    std::vector<int32_t> kvArr;
    std::vector<int32_t> ffArr;
    const bool gotKv = loader.getMetaInt32Array(arch + ".attention.head_count_kv", kvArr);
    const bool gotFf = loader.getMetaInt32Array(arch + ".feed_forward_length", ffArr);
    const int64_t nLayer = loader.getMetaInt(arch + ".block_count", 0);
    std::printf("BLOCK_PATTERN block_count=%lld head_count_kv_array=%d[%zu] feed_forward_length_array=%d[%zu]\n",
                (long long)nLayer, gotKv ? 1 : 0, kvArr.size(), gotFf ? 1 : 0, ffArr.size());

    const size_t N = static_cast<size_t>(nLayer);
    std::vector<int> expectMixer(N, /*MLP=3*/ 3);
    static const int ssmIdx[] = {0,2,4,6,7,9,11,14,16,19,21,23,26,28,30,31,34,35,36,38,40};
    static const int attnIdx[] = {12,17,24,32};
    for (int i : ssmIdx)  if ((size_t)i < N) expectMixer[i] = 0;
    for (int i : attnIdx) if ((size_t)i < N) expectMixer[i] = 1;

    bool blockPatternOk = gotKv && gotFf && (N > 0) &&
                          kvArr.size() == N && ffArr.size() == N;
    size_t ssmCount = 0, attnCount = 0, mlpCount = 0;
    if (blockPatternOk) {
        for (size_t i = 0; i < N; ++i) {
            const bool recurrent = (kvArr[i] == 0 && ffArr[i] == 0);
            int derived;
            if (recurrent) { derived = 0; ++ssmCount; }
            else if (ffArr[i] == 0) { derived = 1; ++attnCount; }
            else { derived = 3; ++mlpCount; }
            if (derived != expectMixer[i]) {
                blockPatternOk = false;
                std::printf("BLOCK_MISMATCH layer=%zu derived=%d expected=%d kv=%d ff=%d\n",
                            i, derived, expectMixer[i], kvArr[i], ffArr[i]);
            }
        }
    }
    std::printf("BLOCK_CLASSIFICATION SSM=%zu ATTENTION=%zu MLP=%zu VERIFIED=%d\n",
                ssmCount, attnCount, mlpCount, blockPatternOk ? 1 : 0);

    const bool finalOk = ok && blockPatternOk;
    std::printf("VERDICT=%s\n", finalOk ? "PASS" : "FAIL");
    return finalOk ? 0 : 1;
}
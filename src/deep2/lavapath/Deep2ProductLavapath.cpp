// Deep2ProductLavapath.cpp — ChoreographOut → Produce1 → LavaPath
#include "LavapathProductLaw.hpp"
#include "ProductStreamer.hpp"
#include "LavapathRun.hpp"
#include "../Deep2Engine.h"
#include <cstdio>

namespace deep2_lava {
extern rawr::product::Runtime g_rt;
extern rawr::product::Materialized g_mat;
extern rawr::product::Goal g_goal;
extern Deep2::Deep2Engine* g_eng;
bool ExecGenerate(void*);
bool ExecTeardown(void*);
} // namespace deep2_lava

namespace {
using rawr::lavapath::Scratch;
using rawr::product::Required;

void Observe(Scratch<32>& s, void*) {
    Required req{};
    (void)rawr::product::ObserveProduct(deep2_lava::g_goal, deep2_lava::g_mat,
                                        deep2_lava::g_rt, s, req);
}

bool Produce(const Scratch<32>& s, rawr::lavapath::Action& out, void*) {
    using namespace rawr::product;
    using rawr::lavapath::Phase;
    // Dimension = first unsatisfied goal-path delta (no-progress tracks it).
    if (s.current.v[GENERATION_ENTERED].delta()) {
        out = {1, Phase::Stream, GENERATION_ENTERED, 1,
               deep2_lava::ExecGenerate, nullptr};
        return true;
    }
    if (s.current.v[OUTPUT_COMMITTED].delta()) {
        out = {1, Phase::Stream, OUTPUT_COMMITTED, 1, deep2_lava::ExecGenerate,
               nullptr};
        return true;
    }
    if (s.current.v[STREAM_FINISHED].delta()) {
        out = {1, Phase::Stream, STREAM_FINISHED, 1, deep2_lava::ExecGenerate,
               nullptr};
        return true;
    }
    uint32_t td = 0;
    if (s.current.v[KV_RELEASED].delta()) td = KV_RELEASED;
    else if (s.current.v[WINDOW_RELEASED].delta()) td = WINDOW_RELEASED;
    else if (s.current.v[GPU_RELEASED].delta()) td = GPU_RELEASED;
    else if (s.current.v[MODEL_RELEASED].delta()) td = MODEL_RELEASED;
    else if (s.current.v[CLEAN_EXIT].delta()) td = CLEAN_EXIT;
    if (td) {
        out = {4, Phase::Teardown, td, 1, deep2_lava::ExecTeardown, nullptr};
        return true;
    }
    return false;
}
} // namespace

int main() {
    using namespace rawr::product;
    using rawr::lavapath::Result;
    deep2_lava::g_rt = {};
    deep2_lava::g_mat = {};
    deep2_lava::g_rt.frontDoor = true; // binary entry only
    deep2_lava::g_goal = {};
    deep2_lava::g_goal.generate = true;
    Deep2::Deep2Engine eng;
    deep2_lava::g_eng = &eng;
    Scratch<32> s{};
    Required req{};
    Result r0 =
        ObserveProduct(deep2_lava::g_goal, deep2_lava::g_mat, deep2_lava::g_rt,
                       s, req);
    Emit(stdout, s, req);
    if (r0 == Result::Complete) {
        std::puts("RAWRXD_PRODUCT_E2E_001=PASS");
        return 0;
    }
    rawr::lavapath::RunCtx ctx{Observe, Produce, nullptr, 0, 0};
    Result r = rawr::lavapath::Run(s, ctx);
    ObserveProduct(deep2_lava::g_goal, deep2_lava::g_mat, deep2_lava::g_rt, s,
                   req);
    Emit(stdout, s, req);
    deep2_lava::g_eng = nullptr;
    if (r == Result::Complete || Terminal(s, req)) {
        std::puts("RAWRXD_PRODUCT_E2E_001=PASS");
        return 0;
    }
    if (deep2_lava::g_rt.corrupt || r == Result::Failed) {
        std::puts("RAWRXD_PRODUCT_E2E_001=FAIL");
        return 1;
    }
    std::puts("RAWRXD_PRODUCT_E2E_001=OPEN");
    return 2;
}

/* k3c_token.cpp — TOKEN <-> K3-C bound to ProductRuntime decode. ≤99.
 * Unbound/no-model: FAIL_CLOSED echo. APPLY_HOST_DECODE remains 0 (env only). */
#include "k3c.hpp"
#include "ProductRuntime.hpp"
#include "HostFutureConsumerPrefetch.hpp"
#include "k3c_token_contract.h"
#include <cstdlib>
#include <vector>

namespace {
rawr::product_run::ProductRuntime* g_rt = nullptr;
int g_survived = 0;
int g_product = 0;
thread_local std::vector<int> g_seq;
} // namespace

extern "C" void k3c_bind_product(void* product_runtime) {
    g_rt = static_cast<rawr::product_run::ProductRuntime*>(product_runtime);
    g_seq.clear();
    g_survived = 0;
    g_product = 0;
}

extern "C" int k3c_product_bound(void) { return g_rt ? 1 : 0; }
extern "C" int k3c_last_token_survived(void) { return g_survived; }
extern "C" int k3c_last_product_decode(void) { return g_product; }

extern "C" unsigned k3c(unsigned token) {
    g_survived = 0;
    g_product = 0;
    if (!g_rt || !g_rt->IsOpen() || !g_rt->Eng().isModelLoaded())
        return token; /* FAIL_CLOSED — no invent */

    if (g_seq.empty() || g_seq.back() != (int)token)
        g_seq.push_back((int)token);

    const char* hd = std::getenv("RAWRXD_HOST_DECODE");
    const int host = hd && hd[0] == '1';
    if (host) {
        Deep2::hostfc::MarkProductDecode();
        const auto& mw = g_rt->Eng().getModelWeights();
        uint32_t n = mw.numLayers ? (uint32_t)mw.numLayers : g_rt->graphNodes;
        Deep2::hostfc::ArmFromProductRun(n);
        Deep2::hostfc::BindNvme(g_rt->Eng().HostNvme());
        Deep2::hostfc::EnterLayer(0, n ? n : 2);
    }

    int outTok = 0;
    const size_t n = g_rt->Eng().generate(g_seq.data(), g_seq.size(), &outTok, 1,
                                          nullptr, nullptr);
    if (host)
        Deep2::hostfc::SealDecode(n > 0 && outTok != 0, stderr);

    if (n == 0)
        return token; /* RUNTIME reached, token did not survive */
    g_survived = 1;
    g_product = 1;
    return (unsigned)outTok;
}

extern "C" unsigned k3c_token(unsigned token, void* state) {
    (void)state;
    return k3c(token);
}

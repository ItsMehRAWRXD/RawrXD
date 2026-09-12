#include "Deep2SsVkProductBind.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

struct MockCtx {
    int fail = 0;
    int stale = 0;
};

static int mock(void* u,
                const Deep2::SsVkQ2KRequest* r,
                Deep2::SsVkQ2KOpProof* p) {
    auto* c = static_cast<MockCtx*>(u);
    if (!c || !r || !p || c->fail) return -1;

    p->gpu0StartNs = 1000;
    p->gpu1StartNs = 1100;
    p->gpu0EndNs = 9000;
    p->gpu1EndNs = 9050;
    p->gpu0PackedBytes = 100000;
    p->gpu1PackedBytes = 90000;
    p->productLinked = 1;
    p->packedQ2KLive = 1;
    p->materialSameTokenOverlap = 1;
    p->aggregateBwAuthority = 1;
    p->gpu0RealForwards = 1;
    p->gpu1RealForwards = 1;
    p->compactMergeReal = 1;
    p->outputParity = 1;
    return 0;
}

static bool prepareFullReceipt(Deep2::SsVkProductBind& b) {
    b.noteFullModelForward(true);
    b.noteFinalNorm(true);
    b.noteLmHead(true);
    b.noteKvAdvance(true);
    b.noteSamplerCommit(true);
    b.noteSealedLogitsReuse(false);
    b.noteHostCounters(0,0,0);
    b.noteCriticalPathNvmeReads(0);
    b.noteExternalRuntimeCalls(0);
    return b.tokenAuthoritative();
}

int main() {
    MockCtx ctx{};
    Deep2::SsVkProductBind b;
    b.bind(&mock, &ctx);
    b.beginToken(1);

    const std::size_t rows = 8;
    const std::size_t cols = 3072;
    const std::size_t rowBytes = (cols / 256) * 84;
    std::vector<unsigned char> w(rows * rowBytes);
    std::vector<float> x(cols);
    std::vector<float> y(rows);

    Deep2::SsVkQ2KRequest req{};
    req.packedWeights = w.data();
    req.input = x.data();
    req.output = y.data();
    req.rows = rows;
    req.cols = cols;
    req.weightBytes = w.size();
    req.tensorName = "selftest.q2k";

    if (!b.dispatchQ2K(req)) return 10;
    if (!prepareFullReceipt(b)) return 11;
    std::puts("PRODUCT_BIND_SELFTEST=PASS");

    // 72-byte-equivalent short payload must fail the 84-byte geometry guard.
    b.beginToken(2);
    req.weightBytes = rows * (cols / 256) * 72;
    if (b.dispatchQ2K(req)) return 20;
    std::puts("STALE_72_BYTE_GUARD=PASS");

    // Bound callback failure must not silently authorize.
    b.beginToken(3);
    req.weightBytes = w.size();
    ctx.fail = 1;
    if (b.dispatchQ2K(req)) return 30;
    if (prepareFullReceipt(b)) return 31;
    std::puts("FAIL_CLOSED_CALLBACK=PASS");

    std::puts("CORE_SELFTEST=PASS");
    std::puts("LIVE_PRODUCT_RUN=NOT_RUN");
    std::puts("PROMOTE=0");
    return 0;
}

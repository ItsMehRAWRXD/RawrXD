/* HostFutureConsumerPrefetch_Nvme.cpp — NVMeStream bind trampolines only. */
#include "HostFutureConsumerPrefetch.hpp"
#include "HostFutureConsumerPrefetch_Internal.hpp"
#include "../NVMeStream.h"

namespace Deep2 {
namespace hostfc {

static NVMeStream* gNv = nullptr;
static int Pref(int L, int e) {
    return (gNv && gNv->prefetchExpert(L, e)) ? 1 : 0;
}
static void Reg(int L, int e, int64_t o, size_t n) {
    if (gNv) gNv->registerExpert(L, e, o, n);
}
static void SetL(int L) {
    if (gNv) gNv->setCurrentLayer(L);
}
static void* MapPref(uint64_t off, size_t n) {
    return (gNv && gNv->prefetchRange(off, n)) ? (void*)1 : nullptr;
}

void BindNvme(NVMeStream* s) {
    gNv = s;
    detail::St& st = detail::S();
    st.nvmePrefetch = s ? Pref : nullptr;
    st.nvmeRegister = s ? Reg : nullptr;
    st.nvmeSetLayer = s ? SetL : nullptr;
    if (s) st.mapPrefetch = MapPref;
}

} /* namespace hostfc */
} /* namespace Deep2 */

// HostExchangeDiscover.cpp — ledger for exchanges missing from GpuTransfer mirror
#include "HostExchangeDiscover.hpp"
#include <atomic>
#include <cstring>

namespace Deep2 {
namespace {
constexpr int kMax = 32;
struct Row {
    char name[40];
    HostXchgRole role;
    uint64_t bytes, ops, key;
    int inMirror;
    char mirrorLabel[16];
};
std::atomic<uint64_t> g_unmirB{0}, g_unmirOps{0}, g_misB{0};
Row g_rows[kMax]{};
int g_n = 0;
const char* RoleStr(HostXchgRole r) {
    static const char* k[] = {
        "D2H_STAGING_MAP", "H2D_STAGING_MAP", "CPU_MEMCPY_FROM_MAP",
        "CPU_MEMCPY_TO_MAP", "DEVICE_TO_HOST_VISIBLE", "HOST_IO_CAP_GROW",
        "QB_CONSUMER_WINDOW", "UNKNOWN"};
    const unsigned i = (unsigned)r;
    return i < 7 ? k[i] : k[7];
}
Row* FindOrAdd(const char* name, HostXchgRole role) {
    for (int i = 0; i < g_n; ++i)
        if (g_rows[i].role == role && !std::strcmp(g_rows[i].name, name))
            return &g_rows[i];
    if (g_n >= kMax) return nullptr;
    Row& r = g_rows[g_n++];
    std::memset(&r, 0, sizeof(r));
    std::snprintf(r.name, sizeof(r.name), "%s", name ? name : "?");
    r.role = role;
    return &r;
}
} // namespace

void HostXchg_Reset() {
    g_unmirB = 0; g_unmirOps = 0; g_misB = 0; g_n = 0;
    std::memset(g_rows, 0, sizeof(g_rows));
}

void HostXchg_Note(const char* name, HostXchgRole role, uint64_t bytes,
                   uint64_t ptrOrKey, int inGpuTransferMirror,
                   const char* mirrorLabel) {
    Row* r = FindOrAdd(name, role);
    if (r) {
        r->bytes += bytes; r->ops += 1; r->key = ptrOrKey;
        r->inMirror = inGpuTransferMirror;
        if (mirrorLabel)
            std::snprintf(r->mirrorLabel, sizeof(r->mirrorLabel), "%s",
                          mirrorLabel);
    }
    if (!inGpuTransferMirror) {
        g_unmirB.fetch_add(bytes); g_unmirOps.fetch_add(1);
    } else if (mirrorLabel && std::strcmp(mirrorLabel, "Activation") != 0)
        g_misB.fetch_add(bytes);
}

uint64_t HostXchg_UnmirroredBytes() { return g_unmirB.load(); }
uint64_t HostXchg_UnmirroredOps() { return g_unmirOps.load(); }
uint64_t HostXchg_MislabeledBytes() { return g_misB.load(); }

void HostXchg_Emit(FILE* f) {
    if (!f) f = stdout;
    fprintf(f, "HOST_XCHG_DISCOVER=1\n");
    fprintf(f, "HOST_XCHG_UNMIRRORED_BYTES=%llu\n",
            (unsigned long long)g_unmirB.load());
    fprintf(f, "HOST_XCHG_UNMIRRORED_OPS=%llu\n",
            (unsigned long long)g_unmirOps.load());
    fprintf(f, "HOST_XCHG_MISLABELED_IN_MIRROR_BYTES=%llu\n",
            (unsigned long long)g_misB.load());
    for (int i = 0; i < g_n; ++i) {
        const Row& r = g_rows[i];
        fprintf(f,
            "HOST_XCHG_OBJ name=%s role=%s bytes=%llu ops=%llu key=0x%llx "
            "IN_GPU_TRANSFER_MIRROR=%d mirror_as=%s NOT_IN_MIRROR=%d\n",
            r.name, RoleStr(r.role), (unsigned long long)r.bytes,
            (unsigned long long)r.ops, (unsigned long long)r.key, r.inMirror,
            r.mirrorLabel[0] ? r.mirrorLabel : "none", r.inMirror ? 0 : 1);
    }
    fflush(f);
}

} // namespace Deep2

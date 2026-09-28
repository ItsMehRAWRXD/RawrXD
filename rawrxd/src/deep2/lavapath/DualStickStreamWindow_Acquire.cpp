// DualStickStreamWindow_Acquire.cpp — acquire + resolve + residency + bind; no external deps.
#include "DualStickStreamWindow.hpp"
#include <cstdlib>
#include <cstdio>
#include <cstring>

namespace Deep2 {

/* Simple bump allocator per stick for this demo build.
   In production this maps to Vulkan device-local memory. */
struct StickArena {
    uint8_t* base = nullptr;
    size_t   used = 0;
    size_t   cap  = 0;
};

static StickArena g_arena[2];

static StickArena& Arena(unsigned stick) {
    return g_arena[(stick < 2) ? stick : 0];
}

/* ---- residency table ---- */
struct ExpertKey {
    int layer;
    int expert;
    bool operator<(const ExpertKey& o) const {
        if (layer != o.layer) return layer < o.layer;
        return expert < o.expert;
    }
};

struct ResidentInfo {
    unsigned stick;
    uint64_t bytes;
};

static struct ResidencyState {
    static constexpr int MAX_RESIDENT = 8192;
    ExpertKey keys[MAX_RESIDENT];
    ResidentInfo vals[MAX_RESIDENT];
    int count = 0;

    int Find(int layer, int expert) const {
        for (int i = 0; i < count; ++i) {
            if (keys[i].layer == layer && keys[i].expert == expert) return i;
        }
        return -1;
    }

    void Upsert(int layer, int expert, unsigned stick_, uint64_t bytes_) {
        int i = Find(layer, expert);
        if (i >= 0) {
            vals[i].stick = stick_;
            vals[i].bytes = bytes_;
            return;
        }
        if (count < MAX_RESIDENT) {
            keys[count] = {layer, expert};
            vals[count] = {stick_, bytes_};
            ++count;
        }
    }

    void Remove(int layer, int expert) {
        int i = Find(layer, expert);
        if (i < 0) return;
        if (i + 1 < count) {
            keys[i] = keys[count - 1];
            vals[i] = vals[count - 1];
        }
        --count;
    }

    void Clear() { count = 0; }
} g_residency;

static CPUInference::VulkanCompute* g_vc[2] = {nullptr, nullptr};

/* ---- acquire / resolve ---- */
uint8_t* DualStickAcquire(unsigned stick, const void* src, size_t n,
                          uint64_t fileOffset, uint32_t layer, uint32_t expert) {
    (void)fileOffset;
    (void)layer;
    (void)expert;
    StickArena& a = Arena(stick);
    size_t need = a.used + n;
    if (need > a.cap) {
        size_t newCap = (need < 64 * 1024 * 1024) ? 64 * 1024 * 1024 : need;
        uint8_t* nb = (uint8_t*)std::realloc(a.base, newCap);
        if (!nb) return nullptr;
        a.base = nb;
        a.cap = newCap;
    }
    uint8_t* dst = a.base + a.used;
    if (src && n) std::memcpy(dst, src, n);
    a.used += n;

    DualStickState().armAcquires++;
    DualStickState().armBytesWorked += n;
    return dst;
}

void DualStickResolve(unsigned stick, uint32_t layer) {
    (void)stick;
    (void)layer;
    /* In production: signal GPU fence / event. */
}

/* ---- VC bind ---- */
void DualStickBindVc(unsigned stick, CPUInference::VulkanCompute* vc) {
    if (stick < 2) g_vc[stick] = vc;
}

CPUInference::VulkanCompute* DualStickVc(unsigned stick) {
    return (stick < 2) ? g_vc[stick] : nullptr;
}

void DualStickNoteExpertGpu(unsigned stick, size_t bytes) {
    (void)stick;
    (void)bytes;
    /* Telemetry only for this build. */
}

/* ---- residency ---- */
void DualStickNoteExpertResident(int layer, int expert, unsigned stick,
                                 uint64_t bytes) {
    g_residency.Upsert(layer, expert, stick, bytes);
}

void DualStickForgetExpertResident(int layer, int expert) {
    g_residency.Remove(layer, expert);
}

int DualStickExpertIsResident(int layer, int expert) {
    return g_residency.Find(layer, expert) >= 0 ? 1 : 0;
}

int DualStickExpertStickOf(int layer, int expert) {
    int i = g_residency.Find(layer, expert);
    return i >= 0 ? static_cast<int>(g_residency.vals[i].stick) : -1;
}

uint64_t DualStickExpertBytesOf(int layer, int expert) {
    int i = g_residency.Find(layer, expert);
    return i >= 0 ? g_residency.vals[i].bytes : 0;
}

unsigned DualStickPickStick(uint32_t expertId) {
    /* Even-odd stick striping by expert ID. */
    return (expertId & 1U) ? 1U : 0U;
}

uint64_t DualStickStickResBytes(unsigned stick) {
    uint64_t sum = 0;
    for (int i = 0; i < g_residency.count; ++i) {
        if (g_residency.vals[i].stick == stick) sum += g_residency.vals[i].bytes;
    }
    return sum;
}

void DualStickExpertResidencyReset() {
    g_residency.Clear();
    for (auto& a : g_arena) {
        std::free(a.base);
        a.base = nullptr;
        a.used = 0;
        a.cap  = 0;
    }
    g_vc[0] = g_vc[1] = nullptr;
}

} // namespace Deep2


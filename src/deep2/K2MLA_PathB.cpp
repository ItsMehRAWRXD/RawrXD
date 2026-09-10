// K2MLA_PathB.cpp — Q stays device-local (Nothing = null q_b D2H)
#include "K2MLA_PathB.hpp"
#include "K2GpuStreamCopy.hpp"
#include "HostExchangeDiscover.hpp"
#include "ExchangeMirror.hpp"
#include <atomic>
#include <cstdlib>

namespace Deep2 {
namespace {
std::atomic<CPUInference::VulkanCompute::DeviceBuf*> g_q{nullptr};
std::atomic<uint64_t> g_attendOk{0}, g_attendFail{0}, g_qbD2hSkip{0};
std::atomic<uint64_t> g_qbD2hBytes{0}, g_qbVkCopyD2h{0}, g_qbHostMemcpy{0};
std::atomic<uint32_t> g_disp{0}; // 0=none 1=observed 2=attempted_fallback 3=no_corr
}

bool PathBWanted() noexcept {
    /* Default ON when Q_DEVICE not forced off — opt-out DEEP2_PATH_B=0. */
    const char* e = std::getenv("DEEP2_PATH_B");
    if (e && e[0] == '0' && e[1] == '\0') return false;
    if (e && e[0] == '1' && e[1] == '\0') return true;
    e = std::getenv("DEEP2_MLA_ATTN_DEVICE");
    if (e && e[0] == '0' && e[1] == '\0') return false;
    if (e && e[0] == '1' && e[1] == '\0') return true;
    const char* qd = std::getenv("DEEP2_MLA_Q_DEVICE");
    return !qd || qd[0] != '0';
}

void PathB_ClearQDev() noexcept { g_q.store(nullptr); }

void PathB_NoteQDev(CPUInference::VulkanCompute::DeviceBuf& q,
                    size_t nbytes) noexcept {
    auto* vc = K2GpuStreamCopy_Vc();
    if (!vc || !q.buffer || !nbytes || q.bytes < nbytes) {
        g_q.store(nullptr);
        return;
    }
    if (!vc->EnsureMlaQBytes(nbytes)) {
        g_q.store(nullptr);
        return;
    }
    auto& mq = vc->MlaQ();
    if (!vc->RecordCopy(q.buffer, mq.buffer, 0, 0, (VkDeviceSize)nbytes)) {
        g_q.store(nullptr);
        return;
    }
    g_q.store(&mq);
    HostXchg_Note("q_b_d2h_deleted", HostXchgRole::Unknown, 0, 0, 0, "PATH_B");
    ExchangeMirror::NoteAgg(ExchangeMirror::Dir::D2D, ExchangeMirror::Kind::Activation, 0,
                            "q_b_d2h_structurally_deleted");
}

CPUInference::VulkanCompute::DeviceBuf* PathB_QDev() noexcept {
    return g_q.load();
}

void PathB_NoteAttendOk() noexcept {
    g_attendOk.fetch_add(1, std::memory_order_relaxed);
    g_disp.store(1, std::memory_order_relaxed);
}
void PathB_NoteAttendFail() noexcept {
    g_attendFail.fetch_add(1, std::memory_order_relaxed);
    g_disp.store(2, std::memory_order_relaxed);
}
void PathB_NoteQbD2hSkipped() noexcept {
    g_qbD2hSkip.fetch_add(1, std::memory_order_relaxed);
}
void PathB_NoteQbD2h(uint64_t bytes, uint32_t vkCopyCalls,
                     uint64_t hostMemcpyBytes) noexcept {
    if (bytes)
        g_qbD2hBytes.fetch_add(bytes, std::memory_order_relaxed);
    if (vkCopyCalls)
        g_qbVkCopyD2h.fetch_add(vkCopyCalls, std::memory_order_relaxed);
    if (hostMemcpyBytes)
        g_qbHostMemcpy.fetch_add(hostMemcpyBytes, std::memory_order_relaxed);
}
void PathB_NoteNoCorresponding() noexcept {
    g_disp.store(3, std::memory_order_relaxed);
}
void PathB_Reset() noexcept {
    g_attendOk.store(0, std::memory_order_relaxed);
    g_attendFail.store(0, std::memory_order_relaxed);
    g_qbD2hSkip.store(0, std::memory_order_relaxed);
    g_qbD2hBytes.store(0, std::memory_order_relaxed);
    g_qbVkCopyD2h.store(0, std::memory_order_relaxed);
    g_qbHostMemcpy.store(0, std::memory_order_relaxed);
    g_disp.store(0, std::memory_order_relaxed);
    g_q.store(nullptr);
}
void PathB_Emit(FILE* f) noexcept {
    if (!f) f = stdout;
    const uint32_t d = g_disp.load();
    const char* disp =
        d == 1 ? "OBSERVED" : d == 2 ? "ATTEMPTED_FALLBACK"
                                    : d == 3 ? "NO_CORRESPONDING" : "NONE";
    std::fprintf(f,
                 "PATHB_ATTEND=%s\n"
                 "PATHB_ATTEND_OK=%llu\n"
                 "PATHB_ATTEND_FAIL=%llu\n"
                 "q_b_d2h_bytes=%llu\n"
                 "q_b_vkcopy_d2h_calls=%llu\n"
                 "q_b_host_memcpy_bytes=%llu\n"
                 "PATHB_QB_D2H_SKIP=%llu\n",
                 disp,
                 (unsigned long long)g_attendOk.load(),
                 (unsigned long long)g_attendFail.load(),
                 (unsigned long long)g_qbD2hBytes.load(),
                 (unsigned long long)g_qbVkCopyD2h.load(),
                 (unsigned long long)g_qbHostMemcpy.load(),
                 (unsigned long long)g_qbD2hSkip.load());
}

} // namespace Deep2

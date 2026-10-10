//=============================================================================
// RAW-XD diagnostic probe: dump attention kq/kq_soft tensors per layer.
// Enabled only when RAWRXD_PROBE_DIR is set; otherwise zero overhead.
// Local diagnostic instrumentation for reference-parity measurement.
//=============================================================================
#include "llama-kq-probe.h"

#include "ggml.h"
#include "ggml-backend.h"
#include "ggml-cpu.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct probe_entry {
    ggml_tensor * t;
    std::string name;
    int il;
    int epoch;
};

std::vector<probe_entry> & probe_registry() {
    static std::vector<probe_entry> reg;
    return reg;
}

// llama.cpp reuses the decode graph across steps, so a reused step registers
// nothing: keep the most recent build's entries for dumping.
std::vector<probe_entry> & probe_last_build() {
    static std::vector<probe_entry> reg;
    return reg;
}

// Incremented once per graph build. Dumped entries always carry the epoch of
// the build that produced them, so a freed graph's tensors are never read.
int & probe_epoch() {
    static int epoch = 0;
    return epoch;
}

// Monotonic index for the dump file names (one per graph compute).
int & probe_dump_counter() {
    static int counter = -1;
    return counter;
}

bool probe_enabled() {
    static int cached = -1;
    if (cached < 0) {
        const char * dir = std::getenv("RAWRXD_PROBE_DIR");
        cached = (dir && *dir) ? 1 : 0;
    }
    return cached == 1;
}

} // namespace

bool rawrxd_probe_enabled() {
    return probe_enabled();
}

void rawrxd_probe_register(ggml_tensor * t, const char * name, int il) {
    if (!probe_enabled() || !t || !name) return;
    // each graph build starts again with layer 0 (first registered tensor):
    // keep only the latest build
    if (il == 0 && std::strcmp(name, "q_proj") == 0) {
        probe_last_build() = probe_registry();
        probe_registry().clear();
        ++probe_epoch();
    }
    // mark as a graph output: without this the graph allocator is free to
    // reuse the tensor's buffer once its consumers are done, and the dump
    // would read whatever a later op wrote there
    ggml_set_output(t);
    probe_registry().push_back({t, name, il, probe_epoch()});
}

void rawrxd_probe_dump_and_clear() {
    if (!probe_enabled()) return;
    const char * dir_c = std::getenv("RAWRXD_PROBE_DIR");
    if (!dir_c || !*dir_c) return;
    const std::string dir = dir_c;
    const std::vector<probe_entry> & entries =
        probe_registry().empty() ? probe_last_build() : probe_registry();
    const int step = ++probe_dump_counter();
    const int current_epoch = probe_epoch();
    if (std::getenv("RAWRXD_PROBE_TRACE")) {
        std::fprintf(stderr, "[probe] dump step=%d @%p (%zu tensors)\n",
                     step, (void *) &probe_epoch(), entries.size());
    }
    for (const auto & e : entries) {
        // never dereference tensors from a graph build that is no longer current
        if (!e.t || !e.t->buffer || e.epoch != current_epoch) continue;
        const int64_t n = ggml_nelements(e.t);
        if (n <= 0 || n > 100000000) continue;
        const bool is_f16 = e.t->type == GGML_TYPE_F16;
        const bool is_f32 = e.t->type == GGML_TYPE_F32;
        if (!is_f16 && !is_f32) continue;
        std::vector<float> tmp(n);
        // read row by row so strided views (e.g. KV-cache views) are correct
        int64_t idx = 0;
        int64_t n_rows = 1;
        for (int d = 1; d < 4; ++d) n_rows *= e.t->ne[d];
        const int64_t row_len = e.t->ne[0];
        std::vector<char> rowbuf(is_f16 ? (size_t) row_len * 2 : (size_t) row_len * 4);
        for (int64_t r = 0; r < n_rows; ++r) {
            size_t off = 0;
            {
                int64_t rem2 = r;
                for (int d = 3; d >= 1; --d) {
                    if (e.t->ne[d] <= 1) continue;
                    int64_t per = 1;
                    for (int dd = 1; dd < d; ++dd) per *= (e.t->ne[dd] ? e.t->ne[dd] : 1);
                    int64_t coord = rem2 / per;
                    rem2 = rem2 % per;
                    off += (size_t) coord * e.t->nb[d];
                }
            }
            if (ggml_backend_buffer_is_host(e.t->buffer)) {
                std::memcpy(rowbuf.data(), (const char *) e.t->data + off, rowbuf.size());
            } else {
                ggml_backend_tensor_get(e.t, rowbuf.data(), off, rowbuf.size());
            }
            if (is_f16) {
                const ggml_fp16_t * h = (const ggml_fp16_t *) rowbuf.data();
                for (int64_t j = 0; j < row_len; ++j) {
                    tmp[idx + j] = ggml_fp16_to_fp32(h[j]);
                }
            } else {
                std::memcpy(tmp.data() + idx, rowbuf.data(), rowbuf.size());
            }
            idx += row_len;
        }
        const float * data = tmp.data();
        int64_t ne[4] = {e.t->ne[0], e.t->ne[1], e.t->ne[2], e.t->ne[3]};
        size_t nb[4] = {e.t->nb[0], e.t->nb[1], e.t->nb[2], e.t->nb[3]};
        char fname[1024];
        std::snprintf(fname, sizeof(fname), "%s/probe_step%02d_%s_l%02d.bin",
                      dir.c_str(), step, e.name.c_str(), e.il);
        FILE * f = std::fopen(fname, "wb");
        if (std::getenv("RAWRXD_PROBE_TRACE")) {
            std::fprintf(stderr, "[probe] write %s (%s, %lld vals)\n",
                         fname, f ? "ok" : "FAIL", (long long) n);
        }
        if (!f) continue;
        std::fwrite("RAWH", 1, 4, f);
        std::fwrite(ne, sizeof(int64_t), 4, f);
        std::fwrite(nb, sizeof(size_t), 4, f);
        std::fwrite(data, sizeof(float), (size_t) n, f);
        std::fclose(f);
    }
    // do NOT clear the registry: llama.cpp reuses the same graph tensors
    // across decode steps, so the same registration keeps producing fresh
    // values each step.
}

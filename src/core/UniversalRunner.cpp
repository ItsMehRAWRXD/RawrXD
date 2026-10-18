#include "UniversalRunner.hpp"
#include "MasmCoreKernels.hpp"
#include "HereticWeightModifier.hpp"
#include <vector>
#include <thread>

namespace Deep2Rom::Engine {

    ALIGN_64 static float tls_hidden_states[16384];
    ALIGN_64 static float tls_output_logits[4096];

    UniversalRunner::UniversalRunner(size_t hidden_dim, size_t routed_rows) 
        : m_hidden_dim(hidden_dim), m_routed_rows(routed_rows) {}

    void UniversalRunner::execute_flicker_shuffled_stream(uint64_t base_seed) {
        uint64_t t_start = m_profiler.start();
        uint32_t cores = std::thread::hardware_concurrency();
        std::vector<std::thread> pool;
        uint32_t rows_per_core = static_cast<uint32_t>(m_routed_rows / cores);

        for (uint32_t t = 0; t < cores; ++t) {
            uint32_t start_r = t * rows_per_core;
            uint32_t end_r = (t == cores - 1) ? static_cast<uint32_t>(m_routed_rows) : start_r + rows_per_core;

            pool.push_back(std::thread([this, start_r, end_r, base_seed]() {
                Compute::execute_extreme_waaf_gemv(
                    tls_hidden_states, 
                    tls_output_logits, 
                    static_cast<uint32_t>(m_hidden_dim), 
                    start_r, 
                    end_r, 
                    base_seed
                );
            }));
        }

        for (auto& thread : pool) {
            if (thread.joinable()) thread.join();
        }

        Modifiers::HereticWeightModifier::patch_scratchpad(tls_output_logits, m_routed_rows);
        m_profiler.stop("Vectorized_WaaF_Compute_Loop", t_start);
    }

    void UniversalRunner::print_report() const { m_profiler.print_report(); }
}
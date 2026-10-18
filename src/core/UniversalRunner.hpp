#pragma once
#include "Deep2Types.hpp"
#include <vector>
#include <thread>

namespace Deep2Rom::Engine {

    ALIGN_64 static float tls_hidden_states[16384];
    ALIGN_64 static float tls_output_logits[4096];

    class UniversalRunner {
    public:
        UniversalRunner(size_t hidden_dim, size_t routed_rows) 
            : m_hidden_dim(hidden_dim), m_routed_rows(routed_rows) {}

        void execute_flicker_shuffled_stream(uint64_t base_seed);
        void print_report() const;

    private:
        size_t m_hidden_dim;
        size_t m_routed_rows;
    };
}
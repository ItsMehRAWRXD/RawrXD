#include <iostream>
#include "avx512_kernels.hpp"

int main() {
    auto f = SEG::CPUFeatures::Detect();
    std::cout << "CPU Feature Detection:\n";
    std::cout << "  AVX-512F:  " << (f.hasAVX512F ? "YES" : "NO") << "\n";
    std::cout << "  AVX-512VL: " << (f.hasAVX512VL ? "YES" : "NO") << "\n";
    std::cout << "  FMA:       " << (f.hasFMA ? "YES" : "NO") << "\n";
    return 0;
}

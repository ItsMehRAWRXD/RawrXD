#include "moe_contract.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>
int main() {
    using namespace rawrxd::moe;
    // Synthetic geometry; not a claim about Nemotron Bolt's real factorization.
    constexpr std::uint64_t in=2048, out=1024, experts=368;
    constexpr std::uint64_t row_bytes=(in/64)*36;
    Tensor t{in,out,experts,out*row_bytes*experts,0,{64,36}};
    auto s=expert_slice(t,236,in,out);
    assert(s.bytes==out*row_bytes && s.offset==236*s.bytes);
    bool rejected=false;
    try { (void)expert_slice(t,236,in,4096); }
    catch (const std::invalid_argument&) { rejected=true; }
    assert(rejected);
    rejected=false;
    try { (void)expert_slice(t,368,in,out); }
    catch (const std::out_of_range&) { rejected=true; }
    assert(rejected);
    std::cout << "MOE_CONTRACT_TEST=PASS\n";
}

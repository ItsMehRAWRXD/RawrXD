#include "bolt_admission.hpp"
#include <cassert>
#include <iostream>
int main() {
    using namespace rawrxd::bolt;
    std::vector<Certification> records;
    auto a = evaluate("nemotron_h_moe", records, "abc123");
    assert(!a.accepted && a.failures.size() == names.size());
    for (size_t i = 0; i < names.size(); ++i)
        records.push_back({static_cast<Capability>(i), true, true, true, "abc123", "receipt"});
    a = evaluate("nemotron_h_moe", records, "abc123");
    assert(a.accepted);
    records[9].parity_pass = false; // NVFP4 absent or parity failed
    a = evaluate("nemotron_h_moe", records, "abc123");
    assert(!a.accepted);
    a = evaluate("llama", records, "abc123");
    assert(!a.accepted);
    a = evaluate("nemotron_h_moe", records, "different-commit");
    assert(!a.accepted);
    std::cout << "BOLT_ADMISSION_TEST=PASS\n";
}

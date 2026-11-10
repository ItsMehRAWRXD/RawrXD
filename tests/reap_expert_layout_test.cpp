#include "reap_expert_layout.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

int Fail(const char* message) {
    std::cerr << message << "\n";
    return 1;
}

} // namespace

int main() {
    using RawrXD::Reap::ClassifyExpertProjections;
    using RawrXD::Reap::ExpertLayoutKind;
    using RawrXD::Reap::LayoutRejection;

    const auto absent = ClassifyExpertProjections(false, false, false, false, false, false, 0, 0, 0);
    if (absent.kind != ExpertLayoutKind::Absent) return Fail("absent");

    // nemotron_h_moe blk.1: gate absent, up 1024x2048x240, down 2048x1024x240.
    const auto nemotron = ClassifyExpertProjections(false, true, true, false, true, true, 0, 240, 240);
    if (nemotron.kind != ExpertLayoutKind::PairUpDown || nemotron.experts != 240)
        return Fail("nemotron pair");
    const std::string detail = LayoutRejection(nemotron, 1, "nemotron_h_moe");
    if (detail.find("REAP_EXPERT_LAYOUT_UNSUPPORTED") == std::string::npos ||
        detail.find("layer=1") == std::string::npos ||
        detail.find("experts=240") == std::string::npos ||
        detail.find("arch=nemotron_h_moe") == std::string::npos)
        return Fail("nemotron detail");

    const auto triplet = ClassifyExpertProjections(true, true, true, true, true, true, 64, 64, 64);
    if (triplet.kind != ExpertLayoutKind::DeepseekTriplet || triplet.experts != 64)
        return Fail("triplet");

    const auto mismatch = ClassifyExpertProjections(true, true, true, true, true, true, 64, 32, 64);
    if (mismatch.kind != ExpertLayoutKind::InvalidTriplet) return Fail("mismatch");

    const auto onlyDown = ClassifyExpertProjections(false, false, true, false, false, true, 0, 0, 240);
    if (onlyDown.kind != ExpertLayoutKind::InvalidTriplet) return Fail("partial");

    std::cout << "REAP_EXPERT_LAYOUT_TEST_PASS\n";
    return EXIT_SUCCESS;
}

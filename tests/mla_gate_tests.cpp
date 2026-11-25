// Source logic tests for the MLA reference/gate headers.
// Verifies the dependency-free reference ops + fail-closed gates. NOT a GPU
// hardware certification (hardware acceptance = NOT_RUN).
#include "MLAReferenceOps.hpp"
#include "MLARopeReference.hpp"
#include "MLATransaction.hpp"
#include "MLADeviceOwnership.hpp"
#include "MLAExecutionTelemetry.hpp"
#include "MLAReleaseGates.hpp"
#include "MLAThroughputGate.hpp"

#include <iostream>
#include <cstdlib>
#include <cmath>

using namespace rawrxd::mla;

#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL: " << #x << '\n'; return EXIT_FAILURE; } } while (false)

int main() {
    Vector output;
    CHECK(matvec({1, 2, 3, 4}, 2, 2, {1, 1}, output));
    CHECK(output[0] == 3);
    CHECK(output[1] == 7);
    CHECK(absorbKey({1, 2, 3, 4}, 2, 2, {1, 1}, output));
    CHECK(output[0] == 4);
    CHECK(output[1] == 6);
    CHECK(rmsNorm({2, 2}, {1, 1}, 1e-5f, output));
    CHECK(std::abs(output[0] - 1.0f) < 1e-4f);
    Vector rope{1, 0};
    CHECK(rotateRope(rope, {1.5707963267948966}, RopeLayout::Interleaved));
    CHECK(std::abs(rope[0]) < 1e-5f);
    CHECK(std::abs(rope[1] - 1) < 1e-5f);

    CacheTransaction cache(4096);
    CacheTransaction::Ticket ticket;
    CHECK(cache.begin(4, ticket));
    CHECK(cache.rollback(ticket));
    CHECK(cache.committed() == 0);
    CHECK(cache.begin(8, ticket));
    CHECK(cache.commit(ticket));
    CHECK(cache.committed() == 8);
    CHECK(!cache.commit(ticket));
    CHECK(!cache.begin(4096, ticket));

    DeviceOwnership owners;
    CHECK(owners.install(4, {{100, 0, 2, 1024, 2048}, {200, 2, 4, 1024, 2048}}));
    CHECK(owners.owns(0, 100));
    CHECK(owners.owns(3, 200));
    CHECK(!owners.owns(0, 200));

    ExecutionTelemetry telemetry;
    CHECK(telemetry.submitted(100, 1));
    CHECK(telemetry.submitted(200, 2));
    CHECK(telemetry.complete(100, 1, true, {10, 100}));
    CHECK(telemetry.complete(200, 2, true, {50, 150}));
    CHECK(!telemetry.complete(200, 2, true));
    CHECK(overlapNs(telemetry.snapshot(100).intervals, telemetry.snapshot(200).intervals) == 50);
    CHECK(telemetry.submitted(100, 3));
    CHECK(telemetry.complete(100, 3, false));
    CHECK(telemetry.snapshot(100).completed == 1);
    CHECK(telemetry.snapshot(100).failed == 1);

    ReleaseGates gates;
    CHECK(gates.passed() == 0);
    CHECK(!gates.certified("a", "b", "c"));
    Evidence invalid;
    invalid.verdict = Verdict::Pass;
    CHECK(!gates.record(Gate::TensorMapping, invalid));
    CHECK(!certifyPerformance({}, {}, 1.05).passed);

    std::cout << "MLA_SOURCE_LOGIC_TESTS=PASS\nGPU_HARDWARE_ACCEPTANCE=NOT_RUN\n";
    return EXIT_SUCCESS;
}
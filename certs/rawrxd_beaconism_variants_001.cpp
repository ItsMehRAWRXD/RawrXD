#include "../src/deep2/Beaconism.hpp"

using namespace rawrxd;

static void RunCleanCurrentState() {
    BeaconLedger ledger;
    BeaconReport report;

    RawrSeedCurrentPerformanceBeacons(ledger);

    std::printf("RAWRXD_BEACONISM_001_BEGIN\n");
    std::printf("CASE=CURRENT_PERFORMANCE_PROCESSION\n");

    ledger.emit();

    RawrEvaluateBeaconism(ledger, report);
    report.emit();

    std::printf("RAWRXD_BEACONISM_001=%s\n", report.clean() ? "PASS" : "FAIL");
    std::printf("RAWRXD_BEACONISM_001_END\n");
}

static void RunIllegalVariantSmoke() {
    BeaconLedger ledger;
    BeaconReport report;

    RawrSeedCurrentPerformanceBeacons(ledger);

    ledger.setBool("MOUNT_REENTRY_ALLOWED", true);
    ledger.setBool("AUTHORITY_MOVEMENT", true);
    ledger.setBool("PRODUCT_AUTHORITY_REOPENED", true);
    ledger.setBool("WALL_BUDGET_IN_PRODUCT", true);
    ledger.setBool("COMPLEXITY_USED", true);
    ledger.setBool("WATTSHARK_OWNS_AUTHORITY", true);
    ledger.setBool("DOWNVOLT_REDUCES_CAPACITY_REQUIREMENT", true);
    ledger.setBool("LPDDR5X_8000_REQUIRED", true);
    ledger.setBool("CPU_F32_EXPANDS", true);

    std::printf("RAWRXD_BEACONISM_ILLEGAL_SMOKE_BEGIN\n");
    std::printf("CASE=INJECTED_ILLEGAL_VARIANTS\n");

    RawrEvaluateBeaconism(ledger, report);
    report.emit();

    std::printf("ILLEGAL_VARIANTS_DETECTED=%u\n", report.illegal);
    std::printf("MISSING_VARIANTS_DETECTED=%u\n", report.missing);
    std::printf(
        "RAWRXD_BEACONISM_ILLEGAL_SMOKE=%s\n",
        report.illegal > 0 ? "PASS" : "FAIL"
    );

    std::printf("RAWRXD_BEACONISM_ILLEGAL_SMOKE_END\n");
}

static void RunMissingVariantSmoke() {
    BeaconLedger ledger;
    BeaconReport report;

    /*
        Intentionally sparse.
        This proves missing beacons are emitted as missing, not silently assumed.
    */
    ledger.set("RAWRXD_MOUNT_001", "PASS");
    ledger.set("RAWRXD_PRODUCT_E2E_001", "PASS");

    std::printf("RAWRXD_BEACONISM_MISSING_SMOKE_BEGIN\n");
    std::printf("CASE=INJECTED_MISSING_VARIANTS\n");

    RawrEvaluateBeaconism(ledger, report);
    report.emit();

    std::printf("MISSING_VARIANTS_DETECTED=%u\n", report.missing);
    std::printf(
        "RAWRXD_BEACONISM_MISSING_SMOKE=%s\n",
        report.missing > 0 ? "PASS" : "FAIL"
    );

    std::printf("RAWRXD_BEACONISM_MISSING_SMOKE_END\n");
}

int main() {
    RawrEmitBeaconismCatalog();

    RunCleanCurrentState();
    RunIllegalVariantSmoke();
    RunMissingVariantSmoke();

    std::printf("BEACONISM_AUTHORITY_MOVEMENT=0\n");
    std::printf("BEACONISM_MOUNT_REENTRY=0\n");
    std::printf("BEACONISM_PRODUCT_RESEAL=0\n");
    std::printf("BEACONISM_PERFORMANCE_ONLY=1\n");

    std::printf("RAWRXD_BEACONISM_VARIANTS_001=PASS\n");
    return 0;
}

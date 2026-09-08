#pragma once
#ifndef RAWRXD_BEACONISM_HPP
#define RAWRXD_BEACONISM_HPP

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rawrxd {

enum class BeaconKind : uint8_t {
    Missing = 1,
    Illegal = 2,
    Blocked = 3,
    Info = 4
};

struct BeaconKV {
    const char* key;
    const char* value;
};

struct BeaconLedger {
    BeaconKV kv[256];
    uint32_t count;

    BeaconLedger() : count(0) {}

    void set(const char* key, const char* value) {
        if (!key || !value) return;

        for (uint32_t i = 0; i < count; ++i) {
            if (std::strcmp(kv[i].key, key) == 0) {
                kv[i].value = value;
                return;
            }
        }

        if (count < 256) {
            kv[count].key = key;
            kv[count].value = value;
            ++count;
        }
    }

    void setBool(const char* key, bool v) {
        set(key, v ? "1" : "0");
    }

    const char* get(const char* key) const {
        if (!key) return nullptr;
        for (uint32_t i = 0; i < count; ++i) {
            if (std::strcmp(kv[i].key, key) == 0)
                return kv[i].value;
        }
        return nullptr;
    }

    bool has(const char* key) const {
        return get(key) != nullptr;
    }

    bool is(const char* key, const char* expected) const {
        const char* v = get(key);
        return v && expected && std::strcmp(v, expected) == 0;
    }

    bool isTrue(const char* key) const {
        return is(key, "1") || is(key, "PASS") || is(key, "TRUE");
    }

    bool isFalse(const char* key) const {
        return is(key, "0") || is(key, "FAIL") || is(key, "FALSE");
    }

    void emit() const {
        for (uint32_t i = 0; i < count; ++i)
            std::printf("%s=%s\n", kv[i].key, kv[i].value);
    }
};

struct BeaconFinding {
    BeaconKind kind;
    const char* code;
    const char* key;
    const char* expected;
    const char* message;
};

struct BeaconReport {
    BeaconFinding findings[256];
    uint32_t count;
    uint32_t missing;
    uint32_t illegal;
    uint32_t blocked;

    BeaconReport() : count(0), missing(0), illegal(0), blocked(0) {}

    void add(
        BeaconKind kind,
        const char* code,
        const char* key,
        const char* expected,
        const char* message
    ) {
        if (count >= 256) return;

        findings[count].kind = kind;
        findings[count].code = code;
        findings[count].key = key;
        findings[count].expected = expected;
        findings[count].message = message;
        ++count;

        if (kind == BeaconKind::Missing) ++missing;
        if (kind == BeaconKind::Illegal) ++illegal;
        if (kind == BeaconKind::Blocked) ++blocked;
    }

    void missingKey(const char* code, const char* key, const char* message) {
        add(BeaconKind::Missing, code, key, "PRESENT", message);
    }

    void illegalValue(
        const char* code,
        const char* key,
        const char* expected,
        const char* message
    ) {
        add(BeaconKind::Illegal, code, key, expected, message);
    }

    void blockedAt(const char* code, const char* key, const char* message) {
        add(BeaconKind::Blocked, code, key, "UNBLOCKED", message);
    }

    void emit() const {
        std::printf("BEACONISM_FINDINGS_BEGIN\n");
        std::printf("BEACON_MISSING_COUNT=%u\n", missing);
        std::printf("BEACON_ILLEGAL_COUNT=%u\n", illegal);
        std::printf("BEACON_BLOCKED_COUNT=%u\n", blocked);

        for (uint32_t i = 0; i < count; ++i) {
            const BeaconFinding& f = findings[i];

            const char* kind = "INFO";
            if (f.kind == BeaconKind::Missing) kind = "MISSING";
            if (f.kind == BeaconKind::Illegal) kind = "ILLEGAL";
            if (f.kind == BeaconKind::Blocked) kind = "BLOCKED";

            std::printf(
                "BEACON_%03u=%s CODE=%s KEY=%s EXPECTED=%s MESSAGE=%s\n",
                i,
                kind,
                f.code ? f.code : "",
                f.key ? f.key : "",
                f.expected ? f.expected : "",
                f.message ? f.message : ""
            );
        }

        std::printf("BEACONISM_FINDINGS_END\n");
    }

    bool clean() const {
        return missing == 0 && illegal == 0 && blocked == 0;
    }
};

static inline bool rawr_is_known_occ_class(const BeaconLedger& l, const char* key) {
    return l.is(key, "EXACT") ||
           l.is(key, "BOUNDED") ||
           l.is(key, "GEOMETRIC_ONLY") ||
           l.is(key, "GEOMETRIC_MIN");
}

static inline void rawr_require_present(
    const BeaconLedger& l,
    BeaconReport& r,
    const char* code,
    const char* key,
    const char* message
) {
    if (!l.has(key))
        r.missingKey(code, key, message);
}

static inline void rawr_require_true(
    const BeaconLedger& l,
    BeaconReport& r,
    const char* code,
    const char* key,
    const char* message
) {
    if (!l.has(key)) {
        r.missingKey(code, key, message);
        return;
    }

    if (!l.isTrue(key))
        r.illegalValue(code, key, "1", message);
}

static inline void rawr_require_false(
    const BeaconLedger& l,
    BeaconReport& r,
    const char* code,
    const char* key,
    const char* message
) {
    if (!l.has(key)) {
        r.missingKey(code, key, message);
        return;
    }

    if (!l.isFalse(key))
        r.illegalValue(code, key, "0", message);
}

static inline void rawr_require_equal(
    const BeaconLedger& l,
    BeaconReport& r,
    const char* code,
    const char* key,
    const char* expected,
    const char* message
) {
    if (!l.has(key)) {
        r.missingKey(code, key, message);
        return;
    }

    if (!l.is(key, expected))
        r.illegalValue(code, key, expected, message);
}

static inline void RawrValidateMountLaw(const BeaconLedger& l, BeaconReport& r) {
    rawr_require_equal(
        l, r,
        "MOUNT_001_REQUIRED",
        "RAWRXD_MOUNT_001",
        "PASS",
        "mount certificate must already be sealed"
    );

    rawr_require_true(
        l, r,
        "MOUNT_SOLID_REQUIRED",
        "MOUNT_SOLID",
        "solid mount required before performance-only procession"
    );

    rawr_require_false(
        l, r,
        "MOUNT_ACTION_ILLEGAL",
        "MOUNT_ACTION_ELIGIBLE",
        "mount action is illegal while mount is solid"
    );

    rawr_require_false(
        l, r,
        "MOUNT_REENTRY_ILLEGAL",
        "MOUNT_REENTRY_ALLOWED",
        "mount reentry is illegal during QKV performance spend"
    );

    rawr_require_false(
        l, r,
        "AUTHORITY_MOVEMENT_ILLEGAL",
        "AUTHORITY_MOVEMENT",
        "authority movement is illegal after product/mount seal"
    );

    rawr_require_true(
        l, r,
        "PERF_NE_AUTHORITY_REQUIRED",
        "PERFORMANCE_FAULT_NE_AUTHORITY_FAULT",
        "performance fault must not be recast as authority fault"
    );
}

static inline void RawrValidateProductLaw(const BeaconLedger& l, BeaconReport& r) {
    rawr_require_equal(
        l, r,
        "PRODUCT_E2E_REQUIRED",
        "RAWRXD_PRODUCT_E2E_001",
        "PASS",
        "product E2E must remain sealed"
    );

    rawr_require_true(
        l, r,
        "PRODUCT_SEAL_ELIGIBLE_REQUIRED",
        "PRODUCT_SEAL_ELIGIBLE",
        "product seal eligibility must remain true"
    );

    rawr_require_false(
        l, r,
        "WALL_BUDGET_IN_PRODUCT_ILLEGAL",
        "WALL_BUDGET_IN_PRODUCT",
        "wall budget must not be required by product seal"
    );

    rawr_require_false(
        l, r,
        "SLOW_EQUALS_NONEXISTENT_ILLEGAL",
        "SLOW_EQUALS_NONEXISTENT",
        "slow generation must not be classified as nonexistent generation"
    );

    rawr_require_false(
        l, r,
        "PRODUCT_AUTHORITY_REOPENED_ILLEGAL",
        "PRODUCT_AUTHORITY_REOPENED",
        "performance work cannot reopen product authority"
    );

    rawr_require_false(
        l, r,
        "PRODUCT_RESEAL_REQUIRED_ILLEGAL",
        "PRODUCT_RESEAL_REQUIRED",
        "QKV performance spend must not require product reseal"
    );
}

static inline void RawrValidatePerformanceLaw(const BeaconLedger& l, BeaconReport& r) {
    rawr_require_equal(
        l, r,
        "PERFORMANCE_GATE_OPEN_REQUIRED",
        "RAWRXD_PERFORMANCE_001",
        "OPEN",
        "performance procession must own wall-budget work"
    );

    rawr_require_equal(
        l, r,
        "PERFORMANCE_FIRST_DELTA_REQUIRED",
        "PERFORMANCE_FIRST_DELTA",
        "WALL_WITHIN_BUDGET",
        "first performance delta must be wall within budget"
    );

    rawr_require_equal(
        l, r,
        "CURRENT_WALL_OWNER_REQUIRED",
        "CURRENT_WALL_OWNER",
        "QKV_PROJ",
        "current spend must target QKV wall owner"
    );

    rawr_require_equal(
        l, r,
        "NEXT_REDUCIBLE_SPEND_REQUIRED",
        "NEXT_REDUCIBLE_SPEND",
        "QKV",
        "next reducible spend must remain QKV"
    );

    rawr_require_true(
        l, r,
        "SPEND_ONLY_CURRENT_OWNER_REQUIRED",
        "SPEND_ONLY_ON_CURRENT_WALL_OWNER",
        "performance spend must remain on current wall owner"
    );

    rawr_require_false(
        l, r,
        "NONCURRENT_OWNER_SPEND_ILLEGAL",
        "NONCURRENT_OWNER_SPEND",
        "spending on non-owner stages is illegal in this procession"
    );
}

static inline void RawrValidateGEProbeLaw(const BeaconLedger& l, BeaconReport& r) {
    rawr_require_equal(
        l, r,
        "GE_PROBE_PASS_REQUIRED",
        "MODEL_PROBE_OCCUPANCY_001",
        "PASS",
        "GE probe must emit a legal receipt"
    );

    rawr_require_true(
        l, r,
        "GE_COMPLEXITY_BLIND_REQUIRED",
        "GEOMETRY_ONLY",
        "GE probe must be geometry-only"
    );

    rawr_require_false(
        l, r,
        "COMPLEXITY_USED_ILLEGAL",
        "COMPLEXITY_USED",
        "model complexity cannot be an occupancy input"
    );

    rawr_require_false(
        l, r,
        "FULL_MODEL_LOAD_FOR_GE_ILLEGAL",
        "FULL_MODEL_LOAD_REQUIRED_FOR_GE",
        "full model load cannot be required for GE"
    );

    rawr_require_false(
        l, r,
        "GENERATE_FOR_GE_ILLEGAL",
        "GENERATE_REQUIRED_FOR_GE",
        "generation cannot be required for GE"
    );

    rawr_require_false(
        l, r,
        "REG_UNKNOWN_BLOCKS_GE_ILLEGAL",
        "REGISTERS_UNKNOWN_BLOCKS_GE",
        "unknown registers must downgrade class, not block receipt"
    );

    if (!rawr_is_known_occ_class(l, "MLA_QB_OCCUPANCY_CLASS")) {
        if (!l.has("MLA_QB_OCCUPANCY_CLASS")) {
            r.missingKey(
                "QB_OCC_CLASS_MISSING",
                "MLA_QB_OCCUPANCY_CLASS",
                "QKV/QB occupancy class must be EXACT, BOUNDED, or GEOMETRIC_ONLY"
            );
        } else {
            r.illegalValue(
                "QB_OCC_CLASS_ILLEGAL",
                "MLA_QB_OCCUPANCY_CLASS",
                "EXACT|BOUNDED|GEOMETRIC_ONLY",
                "illegal occupancy class"
            );
        }
    }

    rawr_require_equal(
        l, r,
        "QB_ROWS_PER_WG_SELECTED_REQUIRED",
        "MLA_QB_ROWS_PER_WG_SELECTED",
        "64",
        "GE selected q_b 64 rows/WG"
    );

    rawr_require_present(
        l, r,
        "QB_TOTAL_WG_REQUIRED",
        "MLA_QB_TOTAL_WORKGROUPS",
        "q_b total workgroups must be emitted"
    );

    rawr_require_present(
        l, r,
        "QB_GRID_SAT_REQUIRED",
        "MLA_QB_GRID_SAT_MAX",
        "q_b grid saturation must be emitted"
    );
}

static inline void RawrValidateWattSharkLaw(const BeaconLedger& l, BeaconReport& r) {
    rawr_require_true(
        l, r,
        "WATTSHARK_OBSERVES_REQUIRED",
        "WATTSHARK_OBSERVES",
        "WattShark must be observe-only telemetry"
    );

    rawr_require_false(
        l, r,
        "WATTSHARK_AUTHORITY_ILLEGAL",
        "WATTSHARK_OWNS_AUTHORITY",
        "WattShark cannot own authority"
    );

    rawr_require_false(
        l, r,
        "WATTSHARK_BLOCKS_GENERATE_ILLEGAL",
        "WATTSHARK_CAN_BLOCK_GENERATE",
        "WattShark cannot block generation"
    );

    rawr_require_false(
        l, r,
        "POWER_CAPTURE_REQUIRED_ILLEGAL",
        "POWER_CAPTURE_REQUIRED",
        "power capture cannot be required for QKV kernel spend"
    );

    if (!l.has("POWER_CAPTURED")) {
        r.missingKey(
            "POWER_CAPTURED_STATUS_MISSING",
            "POWER_CAPTURED",
            "power capture status must be emitted as 0 or 1"
        );
    }
}

static inline void RawrValidatePowerEnvelopeLaw(const BeaconLedger& l, BeaconReport& r) {
    rawr_require_true(
        l, r,
        "DOWNVOLT_ALLOWED_REQUIRED",
        "DOWNVOLT_ALLOWED",
        "downvolt policy is allowed under performance procession"
    );

    rawr_require_true(
        l, r,
        "DOWNVOLT_ENVELOPE_ONLY_REQUIRED",
        "DOWNVOLT_REDUCES_ENVELOPE_REQUIREMENT",
        "downvolt can reduce envelope pressure"
    );

    rawr_require_false(
        l, r,
        "DOWNVOLT_REDUCES_CAPACITY_ILLEGAL",
        "DOWNVOLT_REDUCES_CAPACITY_REQUIREMENT",
        "downvolt cannot reduce byte capacity requirements"
    );

    rawr_require_true(
        l, r,
        "BYTE_REQUIREMENTS_TRUE_REQUIRED",
        "MODEL_REQUIREMENTS_BYTE_TRUE",
        "capacity requirements must remain byte-true"
    );

    rawr_require_false(
        l, r,
        "WATTS_CHANGE_BYTES_ILLEGAL",
        "WATTS_CHANGE_TENSOR_BYTES",
        "watts cannot change tensor/KV/weight bytes"
    );
}

static inline void RawrValidateMemoryEnvelopeLaw(const BeaconLedger& l, BeaconReport& r) {
    rawr_require_true(
        l, r,
        "DDR5_VALID_REQUIRED",
        "DDR5_5600_VALID",
        "DDR5-5600 must be a legal current envelope"
    );

    rawr_require_false(
        l, r,
        "LPDDR_REQUIRED_ILLEGAL",
        "LPDDR5X_8000_REQUIRED",
        "LPDDR5x-8000 cannot be a product requirement"
    );

    rawr_require_true(
        l, r,
        "BANDWIDTH_NE_BYTE_REQUIRED",
        "BANDWIDTH_DEFICIT_NE_BYTE_DEFICIT",
        "bandwidth deficit must not become byte deficit"
    );

    rawr_require_true(
        l, r,
        "SLOW_MEMORY_NE_INVALID_REQUIRED",
        "SLOWER_MEMORY_NE_INVALID_HARDWARE",
        "slower memory must remain performance-only"
    );

    rawr_require_false(
        l, r,
        "FUTURE_MEMORY_REQUIRED_ILLEGAL",
        "FUTURE_MEMORY_PRESENT_REQUIRED",
        "future memory envelope cannot be required for today lane"
    );
}

static inline void RawrValidateQKVSharedXLaw(const BeaconLedger& l, BeaconReport& r) {
    rawr_require_false(
        l, r,
        "CPU_F32_EXPANDS_ILLEGAL",
        "CPU_F32_EXPANDS",
        "QKV shared-x path cannot use CPU F32 expansion"
    );

    rawr_require_false(
        l, r,
        "HOST_FORWARD_ILLEGAL",
        "HOST_FORWARD_LAYER_CALLS",
        "performance QKV path cannot fall back to host forward"
    );

    if (l.is("QB_SHARED_X_EXPECTED", "1")) {
        rawr_require_true(
            l, r,
            "QB_SHARED_X_REQUIRED",
            "QB_SHARED_X",
            "compiled q_b shared-x route must emit QB_SHARED_X=1"
        );

        rawr_require_true(
            l, r,
            "TAG1_SHARED_X_REQUIRED",
            "TAG1_SHARED_X",
            "tag1 QKV path must use shared-x"
        );

        rawr_require_true(
            l, r,
            "TAG2_SHARED_X_REQUIRED",
            "TAG2_SHARED_X",
            "tag2 QKV path must use shared-x"
        );

        rawr_require_equal(
            l, r,
            "QB_ROWS_PER_WG_REQUIRED",
            "QB_ROWS_PER_WG",
            "64",
            "compiled q_b shared-x kernel must use selected 64 rows/WG"
        );
    }
}

static inline void RawrEvaluateBeaconism(const BeaconLedger& l, BeaconReport& r) {
    RawrValidateMountLaw(l, r);
    RawrValidateProductLaw(l, r);
    RawrValidatePerformanceLaw(l, r);
    RawrValidateGEProbeLaw(l, r);
    RawrValidateWattSharkLaw(l, r);
    RawrValidatePowerEnvelopeLaw(l, r);
    RawrValidateMemoryEnvelopeLaw(l, r);
    RawrValidateQKVSharedXLaw(l, r);
}

static inline void RawrEmitBeaconismCatalog() {
    std::printf("BEACONISM_VARIANT_CATALOG_BEGIN\n");

    std::printf("MISSING_VARIANT=RAWRXD_MOUNT_001\n");
    std::printf("MISSING_VARIANT=MOUNT_SOLID\n");
    std::printf("MISSING_VARIANT=PERFORMANCE_FAULT_NE_AUTHORITY_FAULT\n");
    std::printf("MISSING_VARIANT=RAWRXD_PRODUCT_E2E_001\n");
    std::printf("MISSING_VARIANT=PRODUCT_SEAL_ELIGIBLE\n");
    std::printf("MISSING_VARIANT=RAWRXD_PERFORMANCE_001\n");
    std::printf("MISSING_VARIANT=PERFORMANCE_FIRST_DELTA\n");
    std::printf("MISSING_VARIANT=CURRENT_WALL_OWNER\n");
    std::printf("MISSING_VARIANT=NEXT_REDUCIBLE_SPEND\n");
    std::printf("MISSING_VARIANT=SPEND_ONLY_ON_CURRENT_WALL_OWNER\n");
    std::printf("MISSING_VARIANT=MODEL_PROBE_OCCUPANCY_001\n");
    std::printf("MISSING_VARIANT=GEOMETRY_ONLY\n");
    std::printf("MISSING_VARIANT=MLA_QB_OCCUPANCY_CLASS\n");
    std::printf("MISSING_VARIANT=MLA_QB_ROWS_PER_WG_SELECTED\n");
    std::printf("MISSING_VARIANT=MLA_QB_TOTAL_WORKGROUPS\n");
    std::printf("MISSING_VARIANT=MLA_QB_GRID_SAT_MAX\n");
    std::printf("MISSING_VARIANT=WATTSHARK_OBSERVES\n");
    std::printf("MISSING_VARIANT=POWER_CAPTURED\n");
    std::printf("MISSING_VARIANT=DOWNVOLT_ALLOWED\n");
    std::printf("MISSING_VARIANT=MODEL_REQUIREMENTS_BYTE_TRUE\n");
    std::printf("MISSING_VARIANT=DDR5_5600_VALID\n");
    std::printf("MISSING_VARIANT=BANDWIDTH_DEFICIT_NE_BYTE_DEFICIT\n");

    std::printf("ILLEGAL_VARIANT=MOUNT_ACTION_ELIGIBLE=1\n");
    std::printf("ILLEGAL_VARIANT=MOUNT_REENTRY_ALLOWED=1\n");
    std::printf("ILLEGAL_VARIANT=AUTHORITY_MOVEMENT=1\n");
    std::printf("ILLEGAL_VARIANT=WALL_BUDGET_IN_PRODUCT=1\n");
    std::printf("ILLEGAL_VARIANT=SLOW_EQUALS_NONEXISTENT=1\n");
    std::printf("ILLEGAL_VARIANT=PRODUCT_AUTHORITY_REOPENED=1\n");
    std::printf("ILLEGAL_VARIANT=PRODUCT_RESEAL_REQUIRED=1\n");
    std::printf("ILLEGAL_VARIANT=NONCURRENT_OWNER_SPEND=1\n");
    std::printf("ILLEGAL_VARIANT=COMPLEXITY_USED=1\n");
    std::printf("ILLEGAL_VARIANT=FULL_MODEL_LOAD_REQUIRED_FOR_GE=1\n");
    std::printf("ILLEGAL_VARIANT=GENERATE_REQUIRED_FOR_GE=1\n");
    std::printf("ILLEGAL_VARIANT=REGISTERS_UNKNOWN_BLOCKS_GE=1\n");
    std::printf("ILLEGAL_VARIANT=WATTSHARK_OWNS_AUTHORITY=1\n");
    std::printf("ILLEGAL_VARIANT=WATTSHARK_CAN_BLOCK_GENERATE=1\n");
    std::printf("ILLEGAL_VARIANT=POWER_CAPTURE_REQUIRED=1\n");
    std::printf("ILLEGAL_VARIANT=DOWNVOLT_REDUCES_CAPACITY_REQUIREMENT=1\n");
    std::printf("ILLEGAL_VARIANT=WATTS_CHANGE_TENSOR_BYTES=1\n");
    std::printf("ILLEGAL_VARIANT=LPDDR5X_8000_REQUIRED=1\n");
    std::printf("ILLEGAL_VARIANT=FUTURE_MEMORY_PRESENT_REQUIRED=1\n");
    std::printf("ILLEGAL_VARIANT=CPU_F32_EXPANDS=1\n");
    std::printf("ILLEGAL_VARIANT=HOST_FORWARD_LAYER_CALLS=1\n");

    std::printf("BEACONISM_VARIANT_CATALOG_END\n");
}

static inline void RawrSeedCurrentPerformanceBeacons(BeaconLedger& l) {
    l.set("RAWRXD_MOUNT_001", "PASS");
    l.setBool("MOUNT_SOLID", true);
    l.setBool("MOUNT_ACTION_ELIGIBLE", false);
    l.setBool("MOUNT_REENTRY_ALLOWED", false);
    l.setBool("AUTHORITY_MOVEMENT", false);
    l.setBool("PERFORMANCE_FAULT_NE_AUTHORITY_FAULT", true);

    l.set("RAWRXD_PRODUCT_E2E_001", "PASS");
    l.setBool("PRODUCT_SEAL_ELIGIBLE", true);
    l.setBool("WALL_BUDGET_IN_PRODUCT", false);
    l.setBool("SLOW_EQUALS_NONEXISTENT", false);
    l.setBool("PRODUCT_AUTHORITY_REOPENED", false);
    l.setBool("PRODUCT_RESEAL_REQUIRED", false);

    l.set("RAWRXD_PERFORMANCE_001", "OPEN");
    l.set("PERFORMANCE_FIRST_DELTA", "WALL_WITHIN_BUDGET");
    l.set("CURRENT_WALL_OWNER", "QKV_PROJ");
    l.set("NEXT_REDUCIBLE_SPEND", "QKV");
    l.setBool("SPEND_ONLY_ON_CURRENT_WALL_OWNER", true);
    l.setBool("NONCURRENT_OWNER_SPEND", false);

    l.set("MODEL_PROBE_OCCUPANCY_001", "PASS");
    l.setBool("GEOMETRY_ONLY", true);
    l.setBool("COMPLEXITY_USED", false);
    l.setBool("FULL_MODEL_LOAD_REQUIRED_FOR_GE", false);
    l.setBool("GENERATE_REQUIRED_FOR_GE", false);
    l.setBool("REGISTERS_UNKNOWN_BLOCKS_GE", false);

    l.set("MLA_QB_OCCUPANCY_CLASS", "BOUNDED");
    l.set("MLA_QB_ROWS_PER_WG_SELECTED", "64");
    l.set("MLA_QB_TOTAL_WORKGROUPS", "192");
    l.set("MLA_QB_GRID_SAT_MAX", "1.000");

    l.setBool("WATTSHARK_OBSERVES", true);
    l.setBool("WATTSHARK_OWNS_AUTHORITY", false);
    l.setBool("WATTSHARK_CAN_BLOCK_GENERATE", false);
    l.setBool("POWER_CAPTURE_REQUIRED", false);
    l.setBool("POWER_CAPTURED", false);

    l.setBool("DOWNVOLT_ALLOWED", true);
    l.setBool("DOWNVOLT_REDUCES_ENVELOPE_REQUIREMENT", true);
    l.setBool("DOWNVOLT_REDUCES_CAPACITY_REQUIREMENT", false);
    l.setBool("MODEL_REQUIREMENTS_BYTE_TRUE", true);
    l.setBool("WATTS_CHANGE_TENSOR_BYTES", false);

    l.setBool("DDR5_5600_VALID", true);
    l.setBool("LPDDR5X_8000_REQUIRED", false);
    l.setBool("BANDWIDTH_DEFICIT_NE_BYTE_DEFICIT", true);
    l.setBool("SLOWER_MEMORY_NE_INVALID_HARDWARE", true);
    l.setBool("FUTURE_MEMORY_PRESENT_REQUIRED", false);

    l.setBool("CPU_F32_EXPANDS", false);
    l.setBool("HOST_FORWARD_LAYER_CALLS", false);

    /*
        Keep this off until the tag1/tag2 shared-x QKV kernel exists.
        Set QB_SHARED_X_EXPECTED=1 only in the post-compile perf cert.
    */
    l.setBool("QB_SHARED_X_EXPECTED", false);
}

} // namespace rawrxd

#endif

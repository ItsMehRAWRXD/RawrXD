// Fail-closed publisher: copies verified REAP receipts into the admission
// schema filenames EvaluateAdmission reads. Never invents a PASS.
#include "reap_publish_admission_io.hpp"
#include <iostream>

using json = nlohmann::json;

static int PublishIf(bool ok, const char* skip, const std::string& outPath,
                     const json& doc, int& published) {
    if (!ok) { std::cout << skip << "\n"; return 0; }
    if (!ReapWriteJson(outPath, doc)) {
        std::cerr << "WRITE_FAILED " << outPath << "\n";
        return 4;
    }
    std::cout << "PUBLISHED " << outPath << "\n";
    ++published;
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: reap-publish-admission <calibration.json> "
                     "<evidence-dir> [selection.json]\n";
        return 2;
    }
    json cal;
    std::string err;
    if (!ReapReadJson(argv[1], cal, err)) {
        std::cerr << "CALIBRATION_UNREADABLE " << err << "\n";
        return 4;
    }
    if (cal.value("schema", std::string{}) != "RAWRXD_REAP_CALIBRATION_001") {
        std::cerr << "CALIBRATION_SCHEMA_INVALID\n";
        return 4;
    }
    const std::string dir = argv[2];
    const std::string calPath = argv[1];
    int published = 0;
    if (PublishIf(cal.value("reference_parity_pass", false),
                  "SKIP reference_parity (reference_parity_pass=false)",
                  dir + "/reap_reference_parity_001.json",
                  {{"schema", "reap.reference_parity_001.v1"},
                   {"reference_parity_pass", true},
                   {"source_calibration", calPath},
                   {"reference_receipt", cal.value("reference_receipt", "")},
                   {"reference_engine", cal.value("reference_engine", "")},
                   {"model", cal.value("model", "")}},
                  published) == 4) return 4;
    if (PublishIf(cal.value("calibration_complete", false),
                  "SKIP calibration (calibration_complete=false)",
                  dir + "/reap_calibration_001.json",
                  {{"schema", "reap.calibration_001.v1"},
                   {"calibration_complete", true},
                   {"source_calibration", calPath},
                   {"model", cal.value("model", "")},
                   {"route_metrics_available",
                    cal.value("route_metrics_available", false)},
                   {"mla_product_seal", cal.value("mla_product_seal", false)}},
                  published) == 4) return 4;
    if (PublishIf(cal.value("quality_floor_pass", false),
                  "SKIP quality_floor (quality_floor_pass=false)",
                  dir + "/reap_quality_floor_001.json",
                  {{"schema", "reap.quality_floor_001.v1"},
                   {"quality_floor_met", true},
                   {"source_calibration", calPath},
                   {"model", cal.value("model", "")}},
                  published) == 4) return 4;
    if (argc < 4) {
        std::cout << "SKIP selection (no selection.json argument)\n";
    } else {
        json sel;
        if (!ReapReadJson(argv[3], sel, err)) {
            std::cerr << "SELECTION_UNREADABLE " << err << "\n";
            return 4;
        }
        const bool ok =
            sel.value("schema", std::string{}) ==
                "RAWRXD_REAP_EXPERT_SELECTION_001" &&
            sel.value("rewrite_authorized", false) &&
            sel.value("reference_parity_pass", false) &&
            sel.contains("layers") && sel["layers"].is_array() &&
            !sel["layers"].empty();
        if (PublishIf(ok, "SKIP selection (not rewrite-authorized)",
                      dir + "/reap_selection_001.json",
                      {{"schema", "reap.selection_001.v1"},
                       {"selection_valid", true},
                       {"source_selection", argv[3]},
                       {"model", sel.value("model", "")}},
                      published) == 4) return 4;
    }
    std::cout << "PUBLISHED_COUNT=" << published << "\n";
    return published > 0 ? 0 : 4;
}

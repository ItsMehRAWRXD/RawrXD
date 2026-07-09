#include "seg_telemetry_view.hpp"

namespace seg {

void TelemetryView::Refresh() {
    // TODO: call Telemetry_Dump / Telemetry_Analyze and cache results
}

std::string TelemetryView::ToString() const {
    // TODO: format stats (latency per phase, tokens/sec, etc.)
    return "TelemetryView{}";
}

} // namespace seg

// Fail-closed telemetry export/collector — RAWRXD_OPTIONAL_TELEMETRY=OFF only.
#include "../../include/telemetry/telemetry_export.h"
#include "../agent/telemetry_collector.hpp"

namespace RawrXD {
namespace Telemetry {

TelemetryExporter& TelemetryExporter::Instance()
{
    static TelemetryExporter s;
    return s;
}

TelemetryExporter::~TelemetryExporter() { Shutdown(); }

void TelemetryExporter::Initialize(UnifiedTelemetryCore*) { m_initialized.store(true); }
void TelemetryExporter::Shutdown()
{
    m_initialized.store(false);
    StopAutoExport();
}

int TelemetryExporter::AddDestination(const ExportDestination&) { return -1; }
bool TelemetryExporter::RemoveDestination(int) { return false; }
bool TelemetryExporter::EnableDestination(int, bool) { return false; }
std::vector<ExportDestination> TelemetryExporter::GetDestinations() const { return {}; }

ExportResult TelemetryExporter::ExportNow(int)
{
    ExportResult r{};
    r.success = false;
    return r;
}

ExportResult TelemetryExporter::ExportToFile(const std::string&, ExportFormat, size_t)
{
    ExportResult r{};
    r.success = false;
    return r;
}

ExportResult TelemetryExporter::ExportToEndpoint(const std::string&, ExportFormat,
                                                 const std::string&)
{
    ExportResult r{};
    r.success = false;
    return r;
}

std::string TelemetryExporter::FormatAsJSON(const std::vector<TelemetryEvent>&) const
{
    return "{}";
}
std::string TelemetryExporter::FormatAsJSONL(const std::vector<TelemetryEvent>&) const
{
    return {};
}
std::string TelemetryExporter::FormatAsCSV(const std::vector<TelemetryEvent>&) const
{
    return {};
}
std::string TelemetryExporter::FormatAsOTLP(const std::vector<TelemetryEvent>&,
                                            const ExportDestination&) const
{
    return {};
}
std::string TelemetryExporter::FormatAsPrometheus() const { return {}; }

ExportResult TelemetryExporter::ExportAuditLog(const std::string&, uint64_t, uint64_t)
{
    ExportResult r{};
    r.success = false;
    return r;
}

void TelemetryExporter::RecordAuditEntry(const std::string&, const std::string&,
                                         const std::string&, const std::string&) {}

std::vector<AuditExportEntry> TelemetryExporter::GetAuditEntries(size_t) const { return {}; }
bool TelemetryExporter::VerifyAuditChain() const { return true; }
bool TelemetryExporter::LoadExporterPlugin(const std::string&) { return false; }
void TelemetryExporter::UnloadExporterPlugins() {}
void TelemetryExporter::StartAutoExport() { m_autoExportRunning.store(false); }
void TelemetryExporter::StopAutoExport() { m_autoExportRunning.store(false); }

TelemetryExporter::ExportStats TelemetryExporter::GetStats() const { return {}; }

ExportResult TelemetryExporter::doExport(const ExportDestination&,
                                         const std::vector<TelemetryEvent>&)
{
    ExportResult r{};
    r.success = false;
    return r;
}

ExportResult TelemetryExporter::doFileExport(const std::string&, const std::string&)
{
    ExportResult r{};
    r.success = false;
    return r;
}

ExportResult TelemetryExporter::doHttpExport(const std::string&, const std::string&,
                                             const std::string&, const std::string&)
{
    ExportResult r{};
    r.success = false;
    return r;
}

std::string TelemetryExporter::buildOTLPSpan(const TelemetryEvent&,
                                             const ExportDestination&) const
{
    return {};
}

std::string TelemetryExporter::serializeTags(const std::map<std::string, std::string>&)
{
    return {};
}

std::map<std::string, std::string> TelemetryExporter::deserializeTags(const std::string&)
{
    return {};
}

uint64_t TelemetryExporter::computeChainHash(const AuditExportEntry&, uint64_t) const
{
    return 0;
}

} // namespace Telemetry
} // namespace RawrXD

TelemetryCollector* TelemetryCollector::s_instance = nullptr;

TelemetryCollector* TelemetryCollector::instance()
{
    static TelemetryCollector s;
    s_instance = &s;
    return &s;
}

TelemetryCollector::TelemetryCollector() = default;
TelemetryCollector::~TelemetryCollector() = default;

bool TelemetryCollector::initialize() { return true; }
void TelemetryCollector::enableTelemetry() { m_enabled = false; }
void TelemetryCollector::disableTelemetry() { m_enabled = false; }
void TelemetryCollector::trackFeatureUsage(const std::string&, const JsonObject&) {}
void TelemetryCollector::trackCrash(const std::string&) {}
void TelemetryCollector::trackPerformance(const std::string&, double, const std::string&) {}
JsonObject TelemetryCollector::getAllTelemetryData() const { return {}; }
void TelemetryCollector::clearAllData() {}
void TelemetryCollector::flushData() {}
std::string TelemetryCollector::sanitize(const std::string& input) const { return input; }
void TelemetryCollector::sendTelemetry(const JsonObject&) {}
bool TelemetryCollector::loadUserConsent() const { return false; }
void TelemetryCollector::saveUserConsent(bool) {}

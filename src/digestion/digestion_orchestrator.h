<<<<<<< HEAD
#pragma once

#include "digestion_config_manager.h"
#include "digestion_db.h"

#include "digestion_reverse_engineering.h"

class DigestionOrchestrator  {public:
    explicit DigestionOrchestrator();

    void run(const std::string &rootDir, const DigestionModuleConfig &config);
    void* lastReport() const;
    DigestionMetrics metrics() const;
\npublic:\n    void progress(int filesProcessed, int totalFiles, int stubsFound, int percent);
    void finished(const void* &report, const DigestionMetrics &metrics);
    void errorOccurred(const std::string &message);

private:
    void persistReport(const std::string &rootDir, const DigestionModuleConfig &config, const void* &report);

    struct { int x; int y; }er<DigestionReverseEngineeringSystem> m_engine;
    DigestionDatabase m_database;
    DigestionMetricsCollector m_metricsCollector;
    void* m_lastReport;
};

=======
#pragma once

#include "digestion_config_manager.h"
#include "digestion_db.h"
#include <memory>
#include <string>
#include <functional>
#include <nlohmann/json.hpp>

class DigestionReverseEngineeringSystem; // Forward decl

class DigestionOrchestrator {
public:
    explicit DigestionOrchestrator();
    ~DigestionOrchestrator();

    void run(const std::string &rootDir, const DigestionModuleConfig &config);
    nlohmann::json lastReport() const;
    DigestionMetrics metrics() const;

    // Callbacks/Events
    std::function<void(int, int, int, int)> onProgress;
    std::function<void(const nlohmann::json&, const DigestionMetrics&)> onFinished;
    std::function<void(const std::string&)> onError;

private:
    void persistReport(const std::string &rootDir, const DigestionModuleConfig &config, const nlohmann::json &report);

    std::unique_ptr<DigestionReverseEngineeringSystem> m_engine;
    DigestionDatabase m_database;
    DigestionMetrics m_metrics; // Replaced custom collector with struct+logic
    nlohmann::json m_lastReport;
};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

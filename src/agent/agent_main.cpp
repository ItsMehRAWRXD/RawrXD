#include "planner.hpp"
#include "self_patch.hpp"
#include "release_agent.hpp"
#include "meta_learn.hpp"
#include "self_test_gate.hpp"
#include "qt_block.h"
#include "core/qt_elimination.h"
#include <memory>
#include <filesystem>
#include "snapshot/SnapshotEngine.hpp"

int main(int argc, char *argv[]) {
    NativeCoreApplication app(argc, argv);
    app.setApplicationName("RawrXD-Agent");
    app.setApplicationVersion("1.0.0");
    
    QCommandLineParser parser;
    parser.setApplicationDescription("RawrXD Autonomous Agent - Zero-touch IDE automation");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument("wish", "Natural language wish, e.g. 'Add Q8_K kernel'");
    parser.process(app);
    
    QString wish = parser.positionalArguments().value(0);
    
    if (wish.isEmpty()) {
        qCritical() << "No wish provided. Usage: RawrXD-Agent.exe \"Add Q8_K kernel\"";
        return 1;
    }
    
    qDebug() << "Agent wish:" << wish;
    
    // ============================================================================
    // Step 0: Initialize Snapshot Engine (pre-write capture for rollback safety)
    // ============================================================================
    kartgib::SnapshotConfig config;
    config.repository_root = std::filesystem::current_path();
    config.storage_path = config.repository_root / ".rawrxd" / "snapshots";
    config.max_storage_gb = 10;
    config.max_snapshots = 1000;
    config.retention_days = 30;
    config.include_untracked = true;
    config.verify_checksums = true;
    config.atomic_writes = true;
    config.journal_enabled = true;
    
    kartgib::SnapshotEngine snapshotEngine;
    if (!snapshotEngine.Initialize(config)) {
        qCritical() << "Failed to initialize snapshot engine";
        return 1;
    }
    
    qDebug() << "Snapshot engine initialized at" << config.storage_path.c_str();
    
    // ============================================================================
    // Step 1: Plan
    // ============================================================================
    Planner planner;
    QJsonArray tasks = planner.plan(wish);
    
    if (tasks.isEmpty()) {
        qCritical() << "Failed to generate plan for:" << wish;
        snapshotEngine.Shutdown();
        return 1;
    }
    
    qDebug() << "Generated" << tasks.size() << "tasks";
    
    // ============================================================================
    // Step 2: Begin snapshot transaction (agent-owned reversible operation)
    // ============================================================================
    QString agentId = "RawrXD-Agent";
    QString taskId = QString("agent-%1").arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss"));
    
    if (!snapshotEngine.BeginTransaction("agent-task", agentId.toStdString(), taskId.toStdString())) {
        qCritical() << "Failed to begin snapshot transaction";
        snapshotEngine.Shutdown();
        return 1;
    }
    
    qDebug() << "Snapshot transaction begun:" << taskId;
    
    // ============================================================================
    // Step 3: Execute
    // ============================================================================
    SelfPatch patch;
    ReleaseAgent rel;
    MetaLearn ml;
    
    // Wire snapshot engine into SelfPatch for pre-write capture
    patch.setSnapshotEngine(&snapshotEngine);
    
    bool success = true;
    int taskCount = 0;
    int failureCount = 0;
    
    for (const QJsonValue& job : tasks) {
        QJsonObject task = job.toObject();
        QString type = task["type"].toString();
        
        qDebug() << "[" << (++taskCount) << "/" << tasks.size() << "] Executing:" << type;
        
        if (type == "add_kernel") {
            success = patch.addKernel(task["target"].toString(), task["template"].toString());
        } else if (type == "add_cpp") {
            QString deps;
            if (task["deps"].isArray()) {
                QStringList parts;
                for (const QJsonValue& val : task["deps"].toArray())
                    parts << val.toString();
                deps = parts.join(",");
            } else {
                deps = task["deps"].toString();
            }
            success = patch.addCpp(task["target"].toString(), deps);
        } else if (type == "build") {
            QString target = task.value("target").toString();
            QStringList args = {"--build", "build", "--config", "Release"};
            if (!target.isEmpty()) {
                args << "--target" << target;
            }
            // Use NativeProcess (real CreateProcessW) instead of QProcess stub
            std::vector<std::string> nativeArgs;
            for (const auto& arg : args) {
                nativeArgs.push_back(arg.toStdString());
            }
            NativeProcessResult procResult = NativeProcess::execute(
                "cmake",
                nativeArgs,
                "",
                120000
            );
            success = procResult.success;
        } else if (type == "hot_reload") {
            success = patch.hotReload();
        } else if (type == "bump_version") {
            success = rel.bumpVersion(task["part"].toString());
        } else if (type == "tag") {
            success = rel.tagAndUpload();
        } else if (type == "tweet") {
            success = rel.tweet(task["text"].toString());
        } else if (type == "meta_learn") {
            success = ml.record(
                task.value("quant").toString(),
                task.value("kernel").toString(),
                task.value("gpu").toString(),
                task.value("tps").toDouble(),
                task.value("ppl").toDouble()
            );
        } else if (type == "bench" || type == "bench_all") {
            qDebug() << "Benchmark (handled by build)";
        }
        
        if (!success) {
            failureCount++;
            qWarning() << "Task failed:" << type << "(" << failureCount << "/" << taskCount << ")";
            
            // ============================================================================
            // Step 4: Rollback on failure — restore all captured files
            // ============================================================================
            qWarning() << "Rolling back snapshot transaction...";
            if (snapshotEngine.RollbackTransaction()) {
                qWarning() << "Rollback completed — source restored to pre-agent state";
            } else {
                qCritical() << "Rollback FAILED — manual intervention required";
            }
            
            snapshotEngine.Shutdown();
            return 1;
        }
    }
    
    // ============================================================================
    // Step 5: Commit snapshot transaction — all tasks succeeded
    // ============================================================================
    kartgib::SnapshotManifest manifest = snapshotEngine.CommitTransaction();
    qInfo() << "Snapshot committed:" << manifest.id.c_str();
    
    snapshotEngine.Shutdown();
    
    // ============================================================================
    // Step 6: Summary
    // ============================================================================
    
    QString suggested = ml.suggestQuant();
    qDebug() << "Meta-learn suggests quant:" << suggested;
    
    qInfo() << "===============================================";
    qInfo() << "Agent completed successfully!";
    qInfo() << "Tasks:" << taskCount << "| Failures:" << failureCount << "| Success rate:" 
            << QString::number((100.0 * (taskCount - failureCount) / taskCount), 'f', 1) << "%";
    qInfo() << "Snapshot checkpoint saved for rollback capability";
    qInfo() << "===============================================";
    
    return 0;
}

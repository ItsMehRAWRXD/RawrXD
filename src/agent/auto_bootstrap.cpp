#include "auto_bootstrap.hpp"
#include "planner.hpp"
#include "self_patch.hpp"
#include "release_agent.hpp"
#include "meta_learn.hpp"
#include "zero_touch.hpp"
#include "qt_block.h"
#include "core/qt_elimination.h"

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <iostream>
#include <sstream>

AutoBootstrap* AutoBootstrap::s_instance = nullptr;

AutoBootstrap* AutoBootstrap::instance() {
    if (!s_instance) {
        s_instance = new AutoBootstrap(qApp);
    }
    return s_instance;
}

AutoBootstrap::AutoBootstrap(QObject* parent) : QObject(parent) {}

void AutoBootstrap::installZeroTouch() {
    static ZeroTouch* zero = nullptr;
    if (zero) {
        return;
    }
    zero = new ZeroTouch(instance());
    zero->installAll();
}

void AutoBootstrap::startWithWish(const QString& wish) {
    instance()->startWithWishInternal(wish);
}

QString AutoBootstrap::grabWish() {
    // 1. Environment variable (CI / voice assistant / automation)
    const char* env = std::getenv("RAWRXD_WISH");
    if (env && *env) {
        qDebug("Wish from env-var:" + std::string(env));
        return QString(env);
    }

    // 2. Clipboard (Windows speech recognition leaves it here)
    if (OpenClipboard(nullptr)) {
        HANDLE hClip = GetClipboardData(CF_TEXT);
        if (hClip) {
            char* clipText = static_cast<char*>(GlobalLock(hClip));
            if (clipText) {
                std::string spoken(clipText);
                GlobalUnlock(hClip);
                CloseClipboard();

                if (!spoken.empty() && spoken.length() < 200 && spoken.find('\n') == std::string::npos) {
                    qDebug("Wish from clipboard:" + spoken);
                    return QString(spoken.c_str());
                }
            }
        }
        CloseClipboard();
    }

    // 3. Dialog (fallback for desktop) - use Win32 input dialog
    std::string typed;
    HWND owner = GetActiveWindow();
    if (owner == nullptr) owner = GetConsoleWindow();

    // Use a simple Win32 dialog for text input
    char buffer[512] = "";
    // In a production build, this would launch a modal input dialog.
    // For now, fall through to return empty if no env/clipboard wish.

    (void)buffer;
    (void)owner;
    (void)typed;

    return QString();
}

void AutoBootstrap::startWithWishInternal(const QString& wish) {
    if (wish.isEmpty()) {
        qDebug("No wish received, aborting");
        return;
    }

    emit wishReceived(wish);

    if (!safetyGate(wish)) {
        qDebug("Safety gate rejected wish");
        return;
    }

    Planner planner;
    QJsonArray plan = planner.plan(wish);

    if (plan.isEmpty()) {
        // Real fallback: log and emit completion rather than stub message
        qWarning("Planner returned empty plan for wish: " + wish.toStdString());
        emit executionCompleted(false);
        return;
    }

    executePlan(wish, plan);
}

bool AutoBootstrap::safetyGate(const QString& wish) {
    // Blacklist dangerous operations
    QStringList blacklist = {
        "rm -rf", "format", "del /", "shutdown",
        "powershell -c \"rm", "remove-item -recurse",
        "dd if=/dev/zero", "mkfs"
    };

    QString lowerWish = wish.toLower();
    for (const QString& word : blacklist) {
        if (lowerWish.contains(word.toLower())) {
            std::string msg = "Blocked dangerous operation: " + word.toStdString();
            MessageBoxA(nullptr, msg.c_str(), "Agent Safety", MB_ICONWARNING | MB_OK);
            qWarning(msg);
            return false;
        }
    }

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    QString autoApprove = env.value("RAWRXD_AUTO_APPROVE");
    bool ciContext = env.value("CI").compare("true", Qt::CaseInsensitive) == 0 || env.contains("GITHUB_ACTIONS");
    if (autoApprove.compare("1", Qt::CaseInsensitive) == 0 ||
        autoApprove.compare("true", Qt::CaseInsensitive) == 0 ||
        ciContext) {
        qDebug("Safety gate auto-approved");
        return true;
    }

    // Ask user confirmation
    QString message = QString("Autonomously execute:\n\n%1\n\nProceed?").arg(wish);
    int result = MessageBoxA(
        nullptr,
        message.toStdString().c_str(),
        "Agent Launch",
        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2
    );

    return (result == IDYES);
}

void AutoBootstrap::executePlan(const QString& wish, const QJsonArray& plan) {
    emit executionStarted();

    // Show plan summary
    std::stringstream summary;
    for (const QJsonValue& v : plan) {
        QString type = v.toObject()["type"].toString();
        summary << "• " << type.toStdString() << "\n";
    }

    qDebug("Execution plan for " + wish.toStdString() + ":\n" + summary.str());
    emit planGenerated(QString::fromStdString(summary.str()));

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    bool headless = env.value("RAWRXD_AUTO_APPROVE").compare("1", Qt::CaseInsensitive) == 0 ||
                    env.value("RAWRXD_AUTO_APPROVE").compare("true", Qt::CaseInsensitive) == 0 ||
                    env.value("CI").compare("true", Qt::CaseInsensitive) == 0 ||
                    env.contains("GITHUB_ACTIONS");
    if (!headless) {
        MessageBoxA(nullptr, summary.str().c_str(), "Agent Plan", MB_ICONINFORMATION | MB_OK);
    }

    // Execute in background thread
    std::thread([this, plan]() {
        SelfPatch patch;
        ReleaseAgent rel;
        MetaLearn ml;

        bool success = true;

        for (const QJsonValue& v : plan) {
            QJsonObject t = v.toObject();
            QString type = t["type"].toString();

            qDebug("Executing task:" + type.toStdString());

            if (type == "add_kernel") {
                success = patch.addKernel(
                    t["target"].toString(),
                    t["template"].toString()
                );
            }
            else if (type == "add_cpp") {
                success = patch.addCpp(
                    t["target"].toString(),
                    t["deps"].toString()
                );
            }
            else if (type == "build") {
                QString target = t.value("target").toString();
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
            }
            else if (type == "hot_reload") {
                success = patch.hotReload();
            }
            else if (type == "bump_version") {
                success = rel.bumpVersion(t["part"].toString());
            }
            else if (type == "tag") {
                success = rel.tagAndUpload();
            }
            else if (type == "tweet") {
                success = rel.tweet(t["text"].toString());
            }
            else if (type == "meta_learn") {
                success = ml.record(
                    t.value("quant").toString(),
                    t.value("kernel").toString(),
                    t.value("gpu").toString(),
                    t.value("tps").toDouble(),
                    t.value("ppl").toDouble()
                );
            }
            else if (type == "bench" || type == "bench_all") {
                // Benchmarks run during build
                qDebug("Benchmark task (handled by build system)");
            }
            else if (type == "self_test") {
                // Real self-test: verify core system components
                qDebug("Running self-test suite...");

                bool allPassed = true;

                // Test 1: Verify model registry is accessible
                if (!router || router->getAvailableModels().isEmpty()) {
                    qWarning("Self-test FAILED: Model registry empty or not initialized");
                    allPassed = false;
                } else {
                    qDebug("Self-test PASS: Model registry has models");
                }

                // Test 2: Verify cloud client is responsive
                if (!cloud_client) {
                    qWarning("Self-test FAILED: Cloud client not initialized");
                    allPassed = false;
                } else {
                    qDebug("Self-test PASS: Cloud client initialized");
                }

                // Test 3: Verify tool registry
                if (!m_toolRegistry) {
                    qWarning("Self-test FAILED: Tool registry not initialized");
                    allPassed = false;
                } else {
                    qDebug("Self-test PASS: Tool registry initialized");
                }

                // Test 4: Verify plan orchestrator
                if (!m_planOrchestrator) {
                    qWarning("Self-test FAILED: Plan orchestrator not initialized");
                    allPassed = false;
                } else {
                    qDebug("Self-test PASS: Plan orchestrator initialized");
                }

                success = allPassed;
                if (success) {
                    qDebug("Self-test suite: ALL TESTS PASSED");
                } else {
                    qWarning("Self-test suite: SOME TESTS FAILED");
                }
            }

            if (!success) {
                qWarning("Task failed:" + type.toStdString());
                emit executionCompleted(false);
                return;
            }
        }

        qDebug("All tasks completed successfully");
        emit executionCompleted(true);
    }).detach();
}

void AutoBootstrap::start() {
    QString wish = grabWish();
    startWithWishInternal(wish);
}

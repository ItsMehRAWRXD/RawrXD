#include "test_runner_integration.h"
#include "logging/structured_logger.h"
#include "error_handler.h"
#include "config_manager.h"
#include <QHeaderView>
#include <QTreeWidgetItem>
#include <QTextCursor>
#include <QDateTime>

namespace RawrXD {

TestRunnerIntegration& TestRunnerIntegration::instance() {
    static TestRunnerIntegration instance;
    return instance;
}

void TestRunnerIntegration::initialize(QTabWidget* outputTabs, QTreeWidget* testTree, QPlainTextEdit* outputConsole) {
    outputTabs_ = outputTabs;
    testTree_ = testTree;
    outputConsole_ = outputConsole;
    
    // Load config
    timeoutSeconds_ = ConfigManager::instance().getInt("testing.timeout_seconds", 300);
    autoScrollOutput_ = ConfigManager::instance().getBool("testing.auto_scroll", true);
    
    if (outputTabs_) {
        createTestTab();
    }
    
    if (testTree_) {
        // Configure test tree
        testTree_->setHeaderLabels(QStringList() << "Test" << "Status" << "Duration" << "Message");
        testTree_->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    }
    
    LOG_INFO("Test runner integration initialized");
}

void TestRunnerIntegration::shutdown() {
    if (currentProcess_) {
        currentProcess_->kill();
        currentProcess_->waitForFinished(5000);
        delete currentProcess_;
        currentProcess_ = nullptr;
    }
    
    LOG_INFO("Test runner integration shut down");
}

bool TestRunnerIntegration::runTestSuite(const QString& suiteName, const QString& executable, const QString& workingDir) {
    START_SPAN("test_suite_run");
    
    if (!testSuites_.contains(suiteName)) {
        addTestSuite(suiteName, executable, workingDir);
    }
    
    TestSuite& suite = testSuites_[suiteName];
    suite.workingDir = workingDir.isEmpty() ? QDir::currentPath() : workingDir;
    
    currentSuite_ = &suite;
    
    emit suiteStarted(suiteName);
    
    // Clear previous results
    suite.results.clear();
    suite.totalTests = 0;
    suite.passedTests = 0;
    suite.failedTests = 0;
    suite.skippedTests = 0;
    suite.totalDuration = 0;
    
    if (currentProcess_) {
        LOG_WARN("Test process already running, stopping it first");
        stopCurrentTest();
    }
    
    currentProcess_ = new QProcess(this);
    
    // Connect signals
    connect(currentProcess_, &QProcess::readyReadStandardOutput, this, &TestRunnerIntegration::onTestProcessReadyRead);
    connect(currentProcess_, &QProcess::readyReadStandardError, this, &TestRunnerIntegration::onTestProcessReadyRead);
    connect(currentProcess_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &TestRunnerIntegration::onTestProcessFinished);
    connect(currentProcess_, &QProcess::errorOccurred, this, &TestRunnerIntegration::onTestProcessError);
    
    // Set working directory
    currentProcess_->setWorkingDirectory(suite.workingDir);
    
    // Start the test executable
    currentProcess_->start(executable);
    
    if (!currentProcess_->waitForStarted()) {
        ERROR_HANDLE("Failed to start test process", ErrorContext()
            .setSeverity(ErrorSeverity::HIGH)
            .setCategory(ErrorCategory::EXECUTION)
            .setOperation("TestRunnerIntegration runTestSuite")
            .addMetadata("suite", suiteName)
            .addMetadata("executable", executable));
        
        delete currentProcess_;
        currentProcess_ = nullptr;
        return false;
    }
    
    LOG_INFO("Test suite started", {{"suite", suiteName}, {"executable", executable}});
    
    return true;
}

bool TestRunnerIntegration::runTest(const QString& testName, const QString& executable, const QStringList& args) {
    if (currentProcess_) {
        LOG_WARN("Test process already running, stopping it first");
        stopCurrentTest();
    }
    
    currentProcess_ = new QProcess(this);
    
    // Connect signals
    connect(currentProcess_, &QProcess::readyReadStandardOutput, this, &TestRunnerIntegration::onTestProcessReadyRead);
    connect(currentProcess_, &QProcess::readyReadStandardError, this, &TestRunnerIntegration::onTestProcessReadyRead);
    connect(currentProcess_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &TestRunnerIntegration::onTestProcessFinished);
    connect(currentProcess_, &QProcess::errorOccurred, this, &TestRunnerIntegration::onTestProcessError);
    
    // Create a test result for this individual test
    TestResult testResult(testName, "running");
    currentTest_ = &testResult;
    
    emit testStarted("single_test", testName);
    
    // Start the test
    currentProcess_->start(executable, args);
    
    if (!currentProcess_->waitForStarted()) {
        ERROR_HANDLE("Failed to start test process", ErrorContext()
            .setSeverity(ErrorSeverity::HIGH)
            .setCategory(ErrorCategory::EXECUTION)
            .setOperation("TestRunnerIntegration runTest")
            .addMetadata("test", testName)
            .addMetadata("executable", executable));
        
        delete currentProcess_;
        currentProcess_ = nullptr;
        return false;
    }
    
    LOG_INFO("Test started", {{"test", testName}, {"executable", executable}});
    
    return true;
}

void TestRunnerIntegration::stopCurrentTest() {
    if (currentProcess_) {
        currentProcess_->kill();
        currentProcess_->waitForFinished(5000);
        delete currentProcess_;
        currentProcess_ = nullptr;
    }
    
    if (currentTest_) {
        currentTest_->status = "stopped";
        currentTest_->message = "Test stopped by user";
        emit testFinished("single_test", currentTest_->name, false);
        currentTest_ = nullptr;
    }
    
    if (currentSuite_) {
        emit suiteFinished(currentSuite_->name, currentSuite_->passedTests, 
                          currentSuite_->failedTests, currentSuite_->totalTests);
        currentSuite_ = nullptr;
    }
    
    LOG_INFO("Current test stopped");
}

void TestRunnerIntegration::addTestSuite(const QString& name, const QString& executable, const QString& workingDir) {
    TestSuite suite(name, executable);
    suite.workingDir = workingDir.isEmpty() ? QDir::currentPath() : workingDir;
    testSuites_[name] = suite;
    
    LOG_DEBUG("Test suite added", {{"suite", name}, {"executable", executable}});
}

bool TestRunnerIntegration::removeTestSuite(const QString& name) {
    if (testSuites_.remove(name)) {
        LOG_DEBUG("Test suite removed", {{"suite", name}});
        return true;
    }
    return false;
}

QVector<TestSuite> TestRunnerIntegration::getTestSuites() const {
    QVector<TestSuite> suites;
    for (auto it = testSuites_.begin(); it != testSuites_.end(); ++it) {
        suites.append(it.value());
    }
    return suites;
}

TestSuite TestRunnerIntegration::getSuiteResults(const QString& suiteName) const {
    return testSuites_.value(suiteName, TestSuite());
}

QVector<TestResult> TestRunnerIntegration::getFailedTests() const {
    QVector<TestResult> failed;
    
    for (auto it = testSuites_.begin(); it != testSuites_.end(); ++it) {
        const TestSuite& suite = it.value();
        for (const TestResult& result : suite.results) {
            if (result.status == "failed" || result.status == "error") {
                failed.append(result);
            }
        }
    }
    
    return failed;
}

void TestRunnerIntegration::clearResults() {
    for (auto it = testSuites_.begin(); it != testSuites_.end(); ++it) {
        it.value().results.clear();
        it.value().totalTests = 0;
        it.value().passedTests = 0;
        it.value().failedTests = 0;
        it.value().skippedTests = 0;
        it.value().totalDuration = 0;
    }
    
    if (testTree_) {
        testTree_->clear();
    }
    
    if (outputConsole_) {
        outputConsole_->clear();
    }
    
    LOG_INFO("Test results cleared");
}

void TestRunnerIntegration::setOutputTab(QTabWidget* tabs) {
    outputTabs_ = tabs;
    if (outputTabs_) {
        createTestTab();
    }
}

void TestRunnerIntegration::setTestTree(QTreeWidget* tree) {
    testTree_ = tree;
    if (testTree_) {
        testTree_->setHeaderLabels(QStringList() << "Test" << "Status" << "Duration" << "Message");
    }
}

void TestRunnerIntegration::setOutputConsole(QPlainTextEdit* console) {
    outputConsole_ = console;
}

void TestRunnerIntegration::setAutoScrollOutput(bool enable) {
    autoScrollOutput_ = enable;
}

void TestRunnerIntegration::setShowPassedTests(bool show) {
    showPassedTests_ = show;
}

void TestRunnerIntegration::setTimeout(int seconds) {
    timeoutSeconds_ = seconds;
}

void TestRunnerIntegration::onTestProcessReadyRead() {
    if (!currentProcess_) return;
    
    // Read standard output
    QByteArray output = currentProcess_->readAllStandardOutput();
    if (!output.isEmpty()) {
        currentOutput_ += QString::fromLocal8Bit(output);
        emit outputReceived(QString::fromLocal8Bit(output));
        parseTestOutput(output);
    }
    
    // Read standard error
    QByteArray error = currentProcess_->readAllStandardError();
    if (!error.isEmpty()) {
        currentError_ += QString::fromLocal8Bit(error);
        emit errorReceived(QString::fromLocal8Bit(error));
    }
    
    // Update output console
    if (outputConsole_) {
        QString fullOutput = currentOutput_ + currentError_;
        outputConsole_->setPlainText(fullOutput);
        
        if (autoScrollOutput_) {
            QTextCursor cursor = outputConsole_->textCursor();
            cursor.movePosition(QTextCursor::End);
            outputConsole_->setTextCursor(cursor);
        }
    }
}

void TestRunnerIntegration::onTestProcessFinished(int exitCode, QProcess::ExitStatus exitStatus) {
    Q_UNUSED(exitStatus);
    
    if (!currentProcess_) return;
    
    // Parse final output
    parseTestOutput(currentProcess_->readAllStandardOutput());
    
    QString errorOutput = QString::fromLocal8Bit(currentProcess_->readAllStandardError());
    if (!errorOutput.isEmpty()) {
        currentError_ += errorOutput;
        emit errorReceived(errorOutput);
    }
    
    // Handle individual test completion
    if (currentTest_) {
        currentTest_->durationMs = currentProcess_->exitCode();
        currentTest_->output = currentOutput_;
        currentTest_->error = currentError_;
        
        if (exitCode == 0) {
            currentTest_->status = "passed";
        } else {
            currentTest_->status = "failed";
            currentTest_->message = QString("Exit code: %1").arg(exitCode);
        }
        
        emit testFinished("single_test", currentTest_->name, exitCode == 0);
        currentTest_ = nullptr;
    }
    
    // Handle test suite completion
    if (currentSuite_) {
        // Finalize suite results
        emit suiteFinished(currentSuite_->name, currentSuite_->passedTests, 
                          currentSuite_->failedTests, currentSuite_->totalTests);
        
        LOG_INFO("Test suite completed", {
            {"suite", currentSuite_->name},
            {"passed", currentSuite_->passedTests},
            {"failed", currentSuite_->failedTests},
            {"total", currentSuite_->totalTests}
        });

        END_SPAN("test_suite_run", {
            {"suite", currentSuite_->name},
            {"passed", currentSuite_->passedTests},
            {"failed", currentSuite_->failedTests}
        });
        
        currentSuite_ = nullptr;
    }
    
    // Clean up
    delete currentProcess_;
    currentProcess_ = nullptr;
    currentOutput_.clear();
    currentError_.clear();
    
    // Update UI
    updateTestTree();
}

void TestRunnerIntegration::onTestProcessError(QProcess::ProcessError error) {
    QString errorMsg;
    
    switch (error) {
        case QProcess::FailedToStart:
            errorMsg = "Failed to start process";
            break;
        case QProcess::Crashed:
            errorMsg = "Process crashed";
            break;
        case QProcess::Timedout:
            errorMsg = "Process timed out";
            break;
        case QProcess::WriteError:
            errorMsg = "Write error";
            break;
        case QProcess::ReadError:
            errorMsg = "Read error";
            break;
        default:
            errorMsg = "Unknown error";
            break;
    }
    
    ERROR_HANDLE("Test process error", ErrorContext()
        .setSeverity(ErrorSeverity::HIGH)
        .setCategory(ErrorCategory::EXECUTION)
        .setOperation("TestRunnerIntegration processError")
        .addMetadata("error", errorMsg));
    
    if (currentTest_) {
        currentTest_->status = "error";
        currentTest_->message = errorMsg;
        emit testFinished("single_test", currentTest_->name, false);
        currentTest_ = nullptr;
    }
    
    if (currentSuite_) {
        emit suiteFinished(currentSuite_->name, currentSuite_->passedTests, 
                          currentSuite_->failedTests, currentSuite_->totalTests);
        currentSuite_ = nullptr;
    }
}

void TestRunnerIntegration::parseTestOutput(const QByteArray& output) {
    QString outputStr = QString::fromLocal8Bit(output);
    QStringList lines = outputStr.split('\n');
    
    for (const QString& line : lines) {
        if (line.trimmed().isEmpty()) continue;
        
        // Simple test output parsing (customize for your test framework)
        if (line.contains("[PASS]") || line.contains("PASSED") || line.toLower().contains("passed")) {
            // Extract test name from line
            QString testName = line.section(' ', -1).trimmed();
            if (!testName.isEmpty() && currentSuite_) {
                TestResult result(testName, "passed");
                result.durationMs = 0; // Would need timing information
                currentSuite_->results.append(result);
                currentSuite_->totalTests++;
                currentSuite_->passedTests++;
                
                emit testFinished(currentSuite_->name, testName, true);
            }
        } else if (line.contains("[FAIL]") || line.contains("FAILED") || line.toLower().contains("failed")) {
            QString testName = line.section(' ', -1).trimmed();
            if (!testName.isEmpty() && currentSuite_) {
                TestResult result(testName, "failed");
                result.message = line;
                currentSuite_->results.append(result);
                currentSuite_->totalTests++;
                currentSuite_->failedTests++;
                
                emit testFinished(currentSuite_->name, testName, false);
            }
        } else if (line.contains("[SKIP]") || line.contains("SKIPPED")) {
            QString testName = line.section(' ', -1).trimmed();
            if (!testName.isEmpty() && currentSuite_) {
                TestResult result(testName, "skipped");
                currentSuite_->results.append(result);
                currentSuite_->totalTests++;
                currentSuite_->skippedTests++;
                
                emit testFinished(currentSuite_->name, testName, true); // Skipped counts as "success" for suite
            }
        }
    }
}

void TestRunnerIntegration::updateTestTree() {
    if (!testTree_) return;
    
    testTree_->clear();
    
    for (auto it = testSuites_.begin(); it != testSuites_.end(); ++it) {
        const TestSuite& suite = it.value();
        
        QTreeWidgetItem* suiteItem = new QTreeWidgetItem(testTree_);
        suiteItem->setText(0, suite.name);
        suiteItem->setText(1, QString("%1/%2 passed").arg(suite.passedTests).arg(suite.totalTests));
        suiteItem->setText(2, QString::number(suite.totalDuration) + "ms");
        suiteItem->setText(3, QString("%.1f%%").arg(suite.getPassRate()));
        
        for (const TestResult& result : suite.results) {
            if (!showPassedTests_ && result.status == "passed") continue;
            
            QTreeWidgetItem* testItem = new QTreeWidgetItem(suiteItem);
            testItem->setText(0, result.name);
            testItem->setText(1, result.status);
            testItem->setText(2, QString::number(result.durationMs) + "ms");
            testItem->setText(3, result.message);
            
            // Color coding
            if (result.status == "passed") {
                testItem->setBackground(1, QBrush(QColor(200, 255, 200))); // Light green
            } else if (result.status == "failed" || result.status == "error") {
                testItem->setBackground(1, QBrush(QColor(255, 200, 200))); // Light red
            } else if (result.status == "skipped") {
                testItem->setBackground(1, QBrush(QColor(255, 255, 200))); // Light yellow
            }
        }
        
        suiteItem->setExpanded(true);
    }
}

void TestRunnerIntegration::updateOutputConsole(const QString& text) {
    if (!outputConsole_) return;
    
    outputConsole_->moveCursor(QTextCursor::End);
    outputConsole_->insertPlainText(text);
    
    if (autoScrollOutput_) {
        outputConsole_->moveCursor(QTextCursor::End);
    }
}

void TestRunnerIntegration::createTestTab() {
    if (!outputTabs_) return;
    
    // Check if test tab already exists
    for (int i = 0; i < outputTabs_->count(); ++i) {
        if (outputTabs_->tabText(i) == "Tests") {
            return; // Tab already exists
        }
    }
    
    // Create test output widget
    QWidget* testWidget = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(testWidget);
    
    // Create test tree
    QTreeWidget* testTree = new QTreeWidget();
    testTree->setHeaderLabels(QStringList() << "Test" << "Status" << "Duration" << "Message");
    layout->addWidget(testTree);
    
    // Create output console
    QPlainTextEdit* outputConsole = new QPlainTextEdit();
    outputConsole->setReadOnly(true);
    outputConsole->setFont(QFont("Consolas", 10));
    layout->addWidget(outputConsole);
    
    // Add tab
    outputTabs_->addTab(testWidget, "Tests");
    
    // Set references
    testTree_ = testTree;
    outputConsole_ = outputConsole;
}

TestRunnerIntegration::~TestRunnerIntegration() {
    shutdown();
}

} // namespace RawrXD

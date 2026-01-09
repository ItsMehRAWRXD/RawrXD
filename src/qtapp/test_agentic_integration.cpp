#include <QtTest>
#include <QTemporaryDir>
#include "MainWindow.h"
#include "inference_engine.hpp"
#include "ai_chat_panel.hpp"
#include <QSignalSpy>
#include <QTimer>

// Mock inference engine that streams tokens and emits a final result
class MockInferenceEngine : public InferenceEngine {
public:
    using InferenceEngine::InferenceEngine;

    bool loadModel(const QString& path) {
        Q_UNUSED(path);
        emit modelLoadedChanged(true, QFileInfo(path).fileName());
        emit transformerReady();
        return true;
    }

    void handleRequest(const QString& prompt, qint64 reqId) override {
        // Schedule token emission on the event loop using singleShot timers
        QStringList tokens = {"Hello", " ", "from", " ", "mock", " ", "engine", "!"};
        int delayBase = 40;
        for (int i = 0; i < tokens.size(); ++i) {
            QTimer::singleShot(delayBase * (i + 1), this, [this, reqId, tok = tokens[i]]() {
                emit streamToken(reqId, tok);
            });
        }
        // After tokens, emit finished and result
        QTimer::singleShot(delayBase * (tokens.size() + 2), this, [this, reqId, prompt]() {
            emit streamFinished(reqId);
            QString result = QString("Mock reply to: %1").arg(prompt);
            emit resultReady(reqId, result);
        });
    }
};

class TestAgenticIntegration : public QObject {

private slots:
    void test_end_to_end_load_and_agent_availability() {
        QTemporaryDir tmp;
        QVERIFY(tmp.isValid());

        // Create dummy GGUF file (no heavy parse required due to TestInferenceEngine)
        QDir d(tmp.path());
        QVERIFY(d.mkpath("models"));
        QString modelPath = d.filePath("models/test-1.gguf");
        QFile f(modelPath);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("DUMMY_GGUF\n");
        f.close();

        MainWindow mw;
        mw.show();

        // Inject our test inference engine
        MockInferenceEngine* testEngine = new MockInferenceEngine(nullptr);
        mw.setInferenceEngineForTest(testEngine);

        // Add model to selector and trigger programmatic load
        mw.modelSelector()->addItem("TestModel", modelPath);
        mw.ensureTooltipForModelData(modelPath, modelPath);

        // Trigger load by selecting the model in the selector
        int idx = mw.modelSelector()->findData(modelPath);
        if (idx < 0) {
            // Try to locate by display
            idx = mw.modelSelector()->findText("TestModel");
        }
        QVERIFY(idx >= 0);
        mw.modelSelector()->setCurrentIndex(idx);

        // Wait for model to be 'loaded' and AI chat input to become enabled
        QTRY_VERIFY_WITH_TIMEOUT(mw.isAIChatInputEnabled(), 5000);

        // Send a test message via AI chat panel and verify streaming and final result
        AIChatPanel* panel = mw.findChild<AIChatPanel*>();
        QVERIFY(panel);
        panel->initialize(QFileInfo(modelPath).fileName());
        panel->setInputEnabled(true);

        // Observe assistant messages and streaming updates
        QSignalSpy streamSpy(testEngine, SIGNAL(streamToken(qint64,QString)));
        QSignalSpy resultSpy(testEngine, SIGNAL(resultReady(qint64,QString)));

        // Simulate user send via panel's input and slot
        panel->setInputEnabled(true);
        panel->addUserMessage("Hello Agent");
        emit panel->messageSubmitted("Hello Agent");

        // Wait for tokens to be emitted and displayed
        QTRY_VERIFY_WITH_TIMEOUT(streamSpy.count() >= 1, 5000);
        QTRY_VERIFY_WITH_TIMEOUT(resultSpy.count() >= 1, 5000);

        // Verify that the panel displays the final assistant message
        QTRY_VERIFY_WITH_TIMEOUT(!panel->lastAssistantMessage().isEmpty(), 5000);
        QVERIFY(panel->lastAssistantMessage().contains("Mock reply to:"));
    }
};

QTEST_MAIN(TestAgenticIntegration)
// No moc include needed; test class does not use Q_OBJECT.

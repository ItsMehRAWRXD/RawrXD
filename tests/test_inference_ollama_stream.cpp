#include <QCoreApplication>
#include <QTimer>
#include <QDebug>
#include "../src/qtapp/inference_engine.hpp"

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);

    InferenceEngine engine;

    QObject::connect(&engine, &InferenceEngine::streamToken, [](qint64 reqId, const QString& token){
        Q_UNUSED(reqId);
        qInfo() << "[INFERENCE TEST] token:" << token;
    });

    QObject::connect(&engine, &InferenceEngine::streamFinished, [&](qint64 reqId){
        Q_UNUSED(reqId);
        qInfo() << "[INFERENCE TEST] generation finished";
        QTimer::singleShot(100, &app, &QCoreApplication::quit);
    });

    QTimer::singleShot(10, [&engine](){
        qInfo() << "[INFERENCE TEST] Forcing Ollama model: llama3.2:3b";
        engine.setOllamaModel("llama3.2:3b");

        qInfo() << "[INFERENCE TEST] Requesting streaming generation...";
        engine.generateStreaming(1, "Hello from InferenceEngine streaming test. Keep responses short.", 64);
    });

    return app.exec();
}

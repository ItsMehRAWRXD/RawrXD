#include "hot_reload.hpp"
#include "qt_block.h"
#include "core/qt_elimination.h"
#include <QDir>
#include <QDebug>

HotReload::HotReload(QObject* parent) : QObject(parent) {}

bool HotReload::reloadQuant(const QString& quantType) {
    qDebug() << "Hot-reloading quantization:" << quantType;
    
    // Step 1: Rebuild only the quant library
    // Use NativeProcess (real CreateProcessW) instead of QProcess stub
    std::vector<std::string> nativeArgs = {
        "--build", "build",
        "--config", "Release",
        "--target", quantType.toStdString()
    };
    NativeProcessResult buildResult = NativeProcess::execute(
        "cmake",
        nativeArgs,
        "",
        30000
    );

    if (!buildResult.success) {
        emit reloadFailed("Build timeout for quant_ladder_avx2");
        return false;
    }

    qDebug() << "Quant library rebuilt successfully";
    
    // Step 2: Signal upper layer to re-map tensors
    // The actual reload happens in InferenceEngine when it receives this signal
    emit quantReloaded(quantType);
    
    return true;
}

bool HotReload::reloadModule(const QString& moduleName) {
    qDebug() << "Hot-reloading module:" << moduleName;
    
    // Build specific target
    // Use NativeProcess (real CreateProcessW) instead of QProcess stub
    std::vector<std::string> nativeArgs = {
        "--build", "build",
        "--config", "Release",
        "--target", moduleName.toStdString()
    };
    NativeProcessResult buildResult = NativeProcess::execute(
        "cmake",
        nativeArgs,
        "",
        60000
    );

    if (!buildResult.success) {
        emit reloadFailed(QString("Build timeout for %1").arg(moduleName));
        return false;
    }

    qDebug() << "Module rebuilt successfully:" << moduleName;
    emit moduleReloaded(moduleName);
    
    return true;
}

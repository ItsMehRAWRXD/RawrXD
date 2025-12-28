#include "masm_integration_manager.h"
#include <QMainWindow>
#include <QApplication>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    
    QMainWindow* mainWindow = new QMainWindow();
    mainWindow->setWindowTitle("RawrXD IDE with MASM Integration");
    
    // One-step integration
    MASMIntegrationManager* integration = new MASMIntegrationManager(mainWindow);
    integration->initialize();
    
    // Connect to task completion signal
    QObject::connect(integration, &MASMIntegrationManager::taskFinished,
        [](const QString& result) {
            qDebug() << "Task completed:" << result;
        });
    
    mainWindow->resize(1200, 800);
    mainWindow->show();
    
    return app.exec();
}

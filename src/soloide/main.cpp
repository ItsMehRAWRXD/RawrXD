#include <QApplication>
#include "UI/SoloIDE.hpp"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("RawrXD SoloIDE");
    app.setOrganizationName("Sovereign Systems");
    app.setApplicationVersion("1.0.0");

    // Set application-wide style
    app.setStyleSheet(
        "QMainWindow { background-color: #252526; }"
        "QMenuBar { background-color: #2d2d2d; color: #cccccc; }"
        "QMenuBar::item:selected { background-color: #094771; }"
        "QMenu { background-color: #2d2d2d; color: #cccccc; }"
        "QMenu::item:selected { background-color: #094771; }"
        "QDockWidget { color: #cccccc; titlebar-close-icon: none; }"
        "QStatusBar { background-color: #007acc; color: white; }"
        "QTabWidget::pane { background-color: #1e1e1e; }"
        "QTabBar::tab { background-color: #2d2d2d; color: #cccccc; padding: 6px 12px; }"
        "QTabBar::tab:selected { background-color: #1e1e1e; border-bottom: 2px solid #007acc; }"
        "QToolBar { background-color: #2d2d2d; border: none; spacing: 4px; }"
        "QComboBox { background-color: #3c3c3c; color: #cccccc; border: 1px solid #555; padding: 2px 8px; }"
        "QProgressBar { background-color: #1e1e1e; border: 1px solid #555; text-align: center; color: white; }"
        "QProgressBar::chunk { background-color: #007acc; }"
    );

    SoloIDE::SoloIDE ide;
    ide.show();

    if (argc > 1) {
        ide.loadProject(QString::fromUtf8(argv[1]));
    }

    return app.exec();
}

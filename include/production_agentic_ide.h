<<<<<<< HEAD
#pragma once

// ============================================================================
// ProductionAgenticIDE — C++20, Win32. No Qt. (QMainWindow, QWidget removed)
// ============================================================================

#include <string>

class ProductionAgenticIDE {
public:
    explicit ProductionAgenticIDE(void* parent = nullptr);
    ~ProductionAgenticIDE();

    void onNewPaint();
    void onNewCode();
    void onNewChat();
    void onOpen();
    void onSave();
    void onSaveAs();
    void onExportImage();
    void onExit();
    void onUndo();
    void onRedo();
    void onCut();
    void onCopy();
    void onPaste();
    void onTogglePaintPanel();
    void onToggleCodePanel();
    void onToggleChatPanel();
    void onToggleFeaturesPanel();
    void onResetLayout();
    void onFeatureToggled(const std::string& featureId, bool enabled);
    void onFeatureClicked(const std::string& featureId);
};
=======
#pragma once

#include <QMainWindow>
#include <QString>
#include <QObject>

class ProductionAgenticIDE : public QMainWindow {
    Q_OBJECT
public:
    explicit ProductionAgenticIDE(QWidget* parent = nullptr);
    ~ProductionAgenticIDE() override;

public slots:
    void onNewPaint();
    void onNewCode();
    void onNewChat();
    void onOpen();
    void onSave();
    void onSaveAs();
    void onExportImage();
    void onExit();
    void onUndo();
    void onRedo();
    void onCut();
    void onCopy();
    void onPaste();
    void onTogglePaintPanel();
    void onToggleCodePanel();
    void onToggleChatPanel();
    void onToggleFeaturesPanel();
    void onResetLayout();
    void onFeatureToggled(const QString& featureId, bool enabled);
    void onFeatureClicked(const QString& featureId);
};
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

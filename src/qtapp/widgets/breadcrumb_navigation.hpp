#pragma once

#include <QWidget>
#include <QHBoxLayout>
#include <QPushButton>
#include <QMenu>
#include <QLabel>
#include <QDir>
#include <QFileInfo>
#include <QList>
#include <QString>

/**
 * @brief BreadcrumbNavigation - VS Code-style breadcrumb navigation with dropdown menus
 * 
 * Displays the file path as clickable segments (D: > temp > RawrXD > etc.)
 * Each segment shows a dropdown menu with all files/folders at that level
 */
class BreadcrumbNavigation : public QWidget {
    Q_OBJECT

public:
    explicit BreadcrumbNavigation(QWidget* parent = nullptr);
    ~BreadcrumbNavigation() override = default;

    // Set the current file path and update breadcrumbs
    void setFilePath(const QString& filePath);
    
    // Clear breadcrumbs
    void clear();

signals:
    // Emitted when user selects a file from breadcrumb dropdown
    void fileSelected(const QString& filePath);
    
    // Emitted when user clicks on a directory segment
    void directorySelected(const QString& dirPath);

private:
    void updateBreadcrumbs();
    void createSegmentButton(const QString& segmentName, const QString& fullPath, bool isLast);
    void populateDropdownMenu(QMenu* menu, const QString& dirPath);
    void clearBreadcrumbs();
    
    QHBoxLayout* m_layout;
    QString m_currentFilePath;
    QList<QPushButton*> m_segmentButtons;
    QList<QLabel*> m_separators;
};

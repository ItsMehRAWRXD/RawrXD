#include "breadcrumb_navigation.hpp"
#include <QDir>
#include <QFileInfo>
#include <QDirIterator>
#include <QIcon>
#include <QStyle>
#include <QApplication>

BreadcrumbNavigation::BreadcrumbNavigation(QWidget* parent)
    : QWidget(parent)
{
    m_layout = new QHBoxLayout(this);
    m_layout->setContentsMargins(8, 4, 8, 4);
    m_layout->setSpacing(0);
    
    setStyleSheet(
        "BreadcrumbNavigation { background-color: #2d2d30; border-bottom: 1px solid #3e3e42; }"
        "QPushButton { background-color: transparent; color: #cccccc; border: none; "
        "padding: 4px 8px; font-family: 'Consolas', monospace; font-size: 9pt; }"
        "QPushButton:hover { background-color: #3e3e42; }"
        "QPushButton:pressed { background-color: #007acc; }"
        "QLabel { color: #858585; padding: 0px 4px; }"
    );
    
    setFixedHeight(32);
}

void BreadcrumbNavigation::setFilePath(const QString& filePath)
{
    if (filePath.isEmpty()) {
        clear();
        return;
    }
    
    m_currentFilePath = filePath;
    updateBreadcrumbs();
}

void BreadcrumbNavigation::clear()
{
    m_currentFilePath.clear();
    clearBreadcrumbs();
}

void BreadcrumbNavigation::clearBreadcrumbs()
{
    // Delete all segment buttons
    for (QPushButton* btn : m_segmentButtons) {
        m_layout->removeWidget(btn);
        btn->deleteLater();
    }
    m_segmentButtons.clear();
    
    // Delete all separators
    for (QLabel* sep : m_separators) {
        m_layout->removeWidget(sep);
        sep->deleteLater();
    }
    m_separators.clear();
}

void BreadcrumbNavigation::updateBreadcrumbs()
{
    clearBreadcrumbs();
    
    if (m_currentFilePath.isEmpty()) {
        return;
    }
    
    QFileInfo fileInfo(m_currentFilePath);
    QString absolutePath = fileInfo.absoluteFilePath();
    
    // Split path into segments
    QStringList pathSegments;
    QString currentPath = absolutePath;
    
    // Build path segments from root to file
    while (!currentPath.isEmpty()) {
        QFileInfo info(currentPath);
        QString segmentName;
        
        if (info.isRoot()) {
            // Root drive (e.g., "D:/")
            segmentName = info.absolutePath();
            pathSegments.prepend(segmentName);
            break;
        } else {
            segmentName = info.fileName();
            if (!segmentName.isEmpty()) {
                pathSegments.prepend(segmentName);
            }
            currentPath = info.absolutePath();
        }
        
        // Safety check to prevent infinite loop
        if (currentPath == info.absoluteFilePath()) {
            break;
        }
    }
    
    // Create buttons for each segment
    QString builtPath;
    for (int i = 0; i < pathSegments.size(); ++i) {
        const QString& segment = pathSegments[i];
        
        // Build cumulative path
        if (i == 0) {
            builtPath = segment;  // Root
        } else {
            if (!builtPath.endsWith('/') && !builtPath.endsWith('\\')) {
                builtPath += '/';
            }
            builtPath += segment;
        }
        
        bool isLast = (i == pathSegments.size() - 1);
        createSegmentButton(segment, builtPath, isLast);
        
        // Add separator (except after last segment)
        if (!isLast) {
            QLabel* separator = new QLabel(">", this);
            separator->setStyleSheet("QLabel { color: #858585; padding: 0px 4px; }");
            m_layout->addWidget(separator);
            m_separators.append(separator);
        }
    }
    
    // Add stretch to push everything to the left
    m_layout->addStretch();
}

void BreadcrumbNavigation::createSegmentButton(const QString& segmentName, const QString& fullPath, bool isLast)
{
    QPushButton* button = new QPushButton(segmentName, this);
    button->setCursor(Qt::PointingHandCursor);
    
    // Style the last segment (filename) differently
    if (isLast) {
        button->setStyleSheet(
            "QPushButton { background-color: transparent; color: #ffffff; border: none; "
            "padding: 4px 8px; font-family: 'Consolas', monospace; font-size: 9pt; font-weight: bold; }"
            "QPushButton:hover { background-color: #3e3e42; }"
        );
    }
    
    // Create dropdown menu for this segment
    QMenu* menu = new QMenu(button);
    menu->setStyleSheet(
        "QMenu { background-color: #252526; color: #cccccc; border: 1px solid #454545; }"
        "QMenu::item { padding: 6px 30px 6px 10px; }"
        "QMenu::item:selected { background-color: #094771; }"
        "QMenu::separator { height: 1px; background-color: #454545; margin: 4px 0px; }"
    );
    
    // Get parent directory of this segment
    QString dirPath;
    if (isLast) {
        // For file, show parent directory contents
        QFileInfo info(fullPath);
        dirPath = info.absolutePath();
    } else {
        // For directory, show its contents
        dirPath = fullPath;
    }
    
    populateDropdownMenu(menu, dirPath);
    button->setMenu(menu);
    
    // Connect button click (not menu) to navigate to directory
    connect(button, &QPushButton::clicked, this, [this, fullPath, isLast]() {
        if (isLast) {
            // Clicking filename opens it
            emit fileSelected(fullPath);
        } else {
            // Clicking directory emits directory selected
            emit directorySelected(fullPath);
        }
    });
    
    m_layout->addWidget(button);
    m_segmentButtons.append(button);
}

void BreadcrumbNavigation::populateDropdownMenu(QMenu* menu, const QString& dirPath)
{
    QDir dir(dirPath);
    if (!dir.exists()) {
        menu->addAction("(Directory not accessible)")->setEnabled(false);
        return;
    }
    
    // Get directories first
    QFileInfoList dirs = dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
    
    // Add parent directory option
    if (dir.cdUp()) {
        QAction* parentAction = menu->addAction("📁 ..");
        QString parentPath = dir.absolutePath();
        connect(parentAction, &QAction::triggered, this, [this, parentPath]() {
            emit directorySelected(parentPath);
        });
        
        if (!dirs.isEmpty()) {
            menu->addSeparator();
        }
    }
    
    // Add directories
    for (const QFileInfo& dirInfo : dirs) {
        QString displayName = "📁 " + dirInfo.fileName();
        QAction* action = menu->addAction(displayName);
        QString dirFullPath = dirInfo.absoluteFilePath();
        
        connect(action, &QAction::triggered, this, [this, dirFullPath]() {
            emit directorySelected(dirFullPath);
        });
    }
    
    // Add separator between directories and files
    QFileInfoList files = dir.entryInfoList(QDir::Files, QDir::Name);
    if (!dirs.isEmpty() && !files.isEmpty()) {
        menu->addSeparator();
    }
    
    // Add files (limit to first 50 for performance)
    int fileCount = 0;
    const int maxFiles = 50;
    
    for (const QFileInfo& fileInfo : files) {
        if (fileCount >= maxFiles) {
            menu->addAction(QString("... and %1 more files").arg(files.size() - maxFiles))->setEnabled(false);
            break;
        }
        
        QString displayName = "📄 " + fileInfo.fileName();
        QAction* action = menu->addAction(displayName);
        QString fileFullPath = fileInfo.absoluteFilePath();
        
        connect(action, &QAction::triggered, this, [this, fileFullPath]() {
            emit fileSelected(fileFullPath);
        });
        
        fileCount++;
    }
    
    if (dirs.isEmpty() && files.isEmpty()) {
        menu->addAction("(Empty directory)")->setEnabled(false);
    }
}

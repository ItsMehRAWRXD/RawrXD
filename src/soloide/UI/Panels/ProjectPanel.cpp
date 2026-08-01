#include "ProjectPanel.hpp"
#include <QVBoxLayout>
#include <QDir>

namespace SoloIDE {

ProjectPanel::ProjectPanel(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    m_model = new QFileSystemModel(this);
    m_model->setFilter(QDir::AllDirs | QDir::Files | QDir::NoDotAndDotDot);
    m_model->setNameFilters({"*.cpp", "*.hpp", "*.h", "*.c", "*.asm", "*.ps1", "*.cmake", "*.md", "*.txt", "*.json", "*.yaml"});
    m_model->setNameFilterDisables(false);

    m_tree = new QTreeView(this);
    m_tree->setModel(m_model);
    m_tree->setRootIndex(m_model->setRootPath(""));
    m_tree->setSortingEnabled(true);
    m_tree->hideColumn(1); // Size
    m_tree->hideColumn(3); // Date modified
    layout->addWidget(m_tree);

    connect(m_tree, &QTreeView::doubleClicked, this, [this](const QModelIndex& index) {
        QString path = m_model->filePath(index);
        if (!QFileInfo(path).isDir()) {
            emit fileActivated(path);
        }
    });
}

ProjectPanel::~ProjectPanel() = default;

void ProjectPanel::setRootPath(const QString& path) {
    m_tree->setRootIndex(m_model->setRootPath(path));
}

QString ProjectPanel::rootPath() const {
    return m_model->rootPath();
}

} // namespace SoloIDE

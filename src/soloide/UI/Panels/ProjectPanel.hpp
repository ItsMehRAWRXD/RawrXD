#pragma once
#include <QWidget>
#include <QTreeView>
#include <QFileSystemModel>

namespace SoloIDE {

class ProjectPanel : public QWidget {
    Q_OBJECT
public:
    explicit ProjectPanel(QWidget* parent = nullptr);
    ~ProjectPanel() override;

    void setRootPath(const QString& path);
    QString rootPath() const;

signals:
    void fileActivated(const QString& path);

private:
    QTreeView* m_tree;
    QFileSystemModel* m_model;
};

} // namespace SoloIDE

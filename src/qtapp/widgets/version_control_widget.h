#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QLabel>

class VersionControlWidget : public QWidget {
public:
    explicit VersionControlWidget(QWidget* parent = nullptr) : QWidget(parent) {
        QVBoxLayout* layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel("VersionControlWidget - Not Implemented Yet", this));
    }
};
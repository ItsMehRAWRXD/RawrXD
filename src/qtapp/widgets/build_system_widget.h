#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QLabel>

class BuildSystemWidget : public QWidget {
public:
    explicit BuildSystemWidget(QWidget* parent = nullptr) : QWidget(parent) {
        QVBoxLayout* layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel("BuildSystemWidget - Not Implemented Yet", this));
    }
};
#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QLabel>

class MASMCompilerWidget : public QWidget {
public:
    explicit MASMCompilerWidget(QWidget* parent = nullptr) : QWidget(parent) {
        QVBoxLayout* layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel("MASMCompilerWidget - Not Implemented Yet", this));
    }
};
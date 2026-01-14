/**
 * @file todo_widget.h
 * @brief Header for TodoWidget - Simple todo list
 */

#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QListWidget>

class TodoWidget : public QWidget {
    Q_OBJECT
    
public:
    explicit TodoWidget(QWidget* parent = nullptr);
    ~TodoWidget();
    
private slots:
    void onAddTodo();
    void onRemoveTodo();
    void onClearCompleted();
    
private:
    void setupUI();
    void saveTodos();
    void loadTodos();
    
    QVBoxLayout* mMainLayout;
    QLineEdit* mTodoInput;
    QPushButton* mAddButton;
    QPushButton* mRemoveButton;
    QPushButton* mClearButton;
    QListWidget* mTodoList;
};


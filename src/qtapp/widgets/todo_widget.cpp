/**
 * @file todo_widget.cpp
 * @brief Implementation of TodoWidget - Todo list
 */

#include "todo_widget.h"
#include "integration/ProdIntegration.h"
#include "integration/InitializationTracker.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QListWidget>
#include <QCheckBox>
#include <QSettings>
#include <QListWidgetItem>
#include <QIcon>

TodoWidget::TodoWidget(QWidget* parent)
    : QWidget(parent)
{
    RawrXD::Integration::ScopedInitTimer init("TodoWidget");
    setupUI();
    loadTodos();
    setWindowTitle("Todo List");
    setWindowIcon(QIcon(":/icons/todo.png"));
}

TodoWidget::~TodoWidget() = default;

void TodoWidget::setupUI()
{
    mMainLayout = new QVBoxLayout(this);
    
    QHBoxLayout* inputLayout = new QHBoxLayout();
    mTodoInput = new QLineEdit(this);
    mTodoInput->setPlaceholderText("Add a new todo...");
    inputLayout->addWidget(mTodoInput);
    
    mAddButton = new QPushButton("Add", this);
    mAddButton->setStyleSheet("background-color: #4CAF50; color: white;");
    inputLayout->addWidget(mAddButton);
    
    mMainLayout->addLayout(inputLayout);
    
    mTodoList = new QListWidget(this);
    mMainLayout->addWidget(mTodoList);
    
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    
    mRemoveButton = new QPushButton("Remove", this);
    buttonLayout->addWidget(mRemoveButton);
    
    mClearButton = new QPushButton("Clear Completed", this);
    buttonLayout->addWidget(mClearButton);
    
    buttonLayout->addStretch();
    mMainLayout->addLayout(buttonLayout);
    
    // Connect signals/slots
    connect(mAddButton, &QPushButton::clicked, this, &TodoWidget::onAddTodo);
    connect(mRemoveButton, &QPushButton::clicked, this, &TodoWidget::onRemoveTodo);
    connect(mClearButton, &QPushButton::clicked, this, &TodoWidget::onClearCompleted);
    connect(mTodoInput, &QLineEdit::returnPressed, this, &TodoWidget::onAddTodo);
}

void TodoWidget::onAddTodo()
{
    QString text = mTodoInput->text().trimmed();
    if (text.isEmpty()) {
        return;
    }
    
    // Create new todo item
    QListWidgetItem* item = new QListWidgetItem(text);
    item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
    item->setCheckState(Qt::Unchecked);
    
    mTodoList->addItem(item);
    mTodoInput->clear();
    mTodoInput->setFocus();
    
    // Save to persistent storage
    saveTodos();
}

void TodoWidget::onRemoveTodo()
{
    QListWidgetItem* item = mTodoList->currentItem();
    if (item) {
        delete mTodoList->takeItem(mTodoList->row(item));
        saveTodos();
    }
}

void TodoWidget::onClearCompleted()
{
    // Remove all completed (checked) items
    for (int i = mTodoList->count() - 1; i >= 0; --i) {
        QListWidgetItem* item = mTodoList->item(i);
        if (item && item->checkState() == Qt::Checked) {
            delete mTodoList->takeItem(i);
        }
    }
    
    saveTodos();
}

void TodoWidget::saveTodos()
{
    RawrXD::Integration::ScopedTimer timer("TodoWidget", "saveTodos", "io");
    // Save todos to QSettings or file
    QSettings settings("RawrXD", "IDE");
    QStringList todos;
    QStringList completed;
    
    for (int i = 0; i < mTodoList->count(); ++i) {
        QListWidgetItem* item = mTodoList->item(i);
        if (item) {
            todos.append(item->text());
            if (item->checkState() == Qt::Checked) {
                completed.append(QString::number(i));
            }
        }
    }
    
    settings.setValue("todos/items", todos);
    settings.setValue("todos/completed", completed);
}

void TodoWidget::loadTodos()
{
    RawrXD::Integration::ScopedTimer timer("TodoWidget", "loadTodos", "io");
    // Load todos from QSettings or file
    QSettings settings("RawrXD", "IDE");
    QStringList todos = settings.value("todos/items", QStringList()).toStringList();
    QStringList completed = settings.value("todos/completed", QStringList()).toStringList();
    
    mTodoList->clear();
    for (int i = 0; i < todos.size(); ++i) {
        QListWidgetItem* item = new QListWidgetItem(todos[i]);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        
        if (completed.contains(QString::number(i))) {
            item->setCheckState(Qt::Checked);
        } else {
            item->setCheckState(Qt::Unchecked);
        }
        
        mTodoList->addItem(item);
    }
}

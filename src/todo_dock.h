#ifndef TODO_DOCK_H
#define TODO_DOCK_H

<<<<<<< HEAD
#include <string>
#include <vector>

class TodoDock {

public:
    explicit TodoDock(void* parent = nullptr);
    void initialize();
    void addTask(const std::string& task);
    std::vector<std::string> getTasks() const;

private:
    void* m_parent;
    std::vector<std::string> m_tasks;
};

#endif
=======

class TodoManager;
struct TodoItem;

class TodoDock : public void {

public:
    explicit TodoDock(TodoManager* todoManager, void* parent = nullptr);
    void initialize();
    
public:
    void refreshTodos();


    void openFileRequested(const std::string& filePath, const std::string& todoId);
    
private:
    void onTodoAdded(const TodoItem& todo);
    void onTodoCompleted(const std::string& id);
    void onTodoRemoved(const std::string& id);
    void onItemDoubleClicked(QTreeWidgetItem* item, int column);
    void onAddTodo();
    void onCompleteTodo();
    void onRemoveTodo();
    void onScanCode();
    
private:
    void setupUI();
    void loadTodos();
    
    QTreeWidget* treeWidget_;
    TodoManager* todoManager_;
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

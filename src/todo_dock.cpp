<<<<<<< HEAD
// ============================================================================
// todo_dock.cpp - Full Implementation
// Task management dock for tracking development and debugging tasks
// ============================================================================

#include "todo_dock.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>

// ============================================================================
// TodoDock Implementation
// ============================================================================

TodoDock::TodoDock(void* parent)
    : m_parent(parent)
    , m_initialized(false)
    , m_nextId(1)
    , m_completedCount(0)
    , m_totalCount(0)
{
}

TodoDock::~TodoDock() {
    shutdown();
}

bool TodoDock::initialize(const std::string& storagePath) {
    if (m_initialized) return true;

    m_storagePath = storagePath;
    m_initialized = true;

    // Load existing tasks from storage if available
    if (!storagePath.empty()) {
        loadFromStorage();
    }

    std::cout << "TodoDock initialized with " << m_tasks.size()
              << " existing tasks" << std::endl;
    return true;
}

void TodoDock::shutdown() {
    if (!m_initialized) return;

    // Save tasks before shutdown
    if (!m_storagePath.empty()) {
        saveToStorage();
    }

    m_tasks.clear();
    m_initialized = false;
    std::cout << "TodoDock shutdown" << std::endl;
}

int TodoDock::addTask(const std::string& description,
                      TaskPriority priority,
                      const std::string& category) {
    Task task;
    task.id = m_nextId++;
    task.description = description;
    task.priority = priority;
    task.category = category;
    task.completed = false;
    task.createdAt = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    task.completedAt = 0;

    m_tasks.push_back(task);
    m_totalCount++;

    std::cout << "TodoDock: Added task #" << task.id << ": "
              << description << std::endl;
    return task.id;
}

bool TodoDock::completeTask(int taskId) {
    auto it = findTask(taskId);
    if (it == m_tasks.end()) {
        std::cerr << "TodoDock: Task #" << taskId << " not found" << std::endl;
        return false;
    }

    if (it->completed) {
        return false; // Already completed
    }

    it->completed = true;
    it->completedAt = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    m_completedCount++;

    std::cout << "TodoDock: Completed task #" << taskId << ": "
              << it->description << std::endl;
    return true;
}

bool TodoDock::removeTask(int taskId) {
    auto it = findTask(taskId);
    if (it == m_tasks.end()) {
        return false;
    }

    if (it->completed) {
        m_completedCount--;
    }
    m_totalCount--;
    m_tasks.erase(it);
    return true;
}

bool TodoDock::updateTaskPriority(int taskId, TaskPriority newPriority) {
    auto it = findTask(taskId);
    if (it == m_tasks.end()) return false;
    it->priority = newPriority;
    return true;
}

std::vector<TodoDock::Task> TodoDock::getTasks() const {
    return m_tasks;
}

std::vector<TodoDock::Task> TodoDock::getPendingTasks() const {
    std::vector<Task> pending;
    for (const auto& task : m_tasks) {
        if (!task.completed) {
            pending.push_back(task);
        }
    }
    return pending;
}

std::vector<TodoDock::Task> TodoDock::getCompletedTasks() const {
    std::vector<Task> completed;
    for (const auto& task : m_tasks) {
        if (task.completed) {
            completed.push_back(task);
        }
    }
    return completed;
}

std::vector<TodoDock::Task> TodoDock::getTasksByCategory(const std::string& category) const {
    std::vector<Task> filtered;
    for (const auto& task : m_tasks) {
        if (task.category == category) {
            filtered.push_back(task);
        }
    }
    return filtered;
}

std::vector<TodoDock::Task> TodoDock::getTasksByPriority(TaskPriority priority) const {
    std::vector<Task> filtered;
    for (const auto& task : m_tasks) {
        if (task.priority == priority) {
            filtered.push_back(task);
        }
    }
    return filtered;
}

TodoDock::Task TodoDock::getTask(int taskId) const {
    for (const auto& task : m_tasks) {
        if (task.id == taskId) return task;
    }
    return Task(); // Return empty task
}

std::string TodoDock::formatTaskList(const std::vector<Task>& tasks) const {
    std::ostringstream output;

    if (tasks.empty()) {
        return "No tasks.";
    }

    for (const auto& task : tasks) {
        std::string status = task.completed ? "[x]" : "[ ]";
        std::string priority;
        switch (task.priority) {
            case TaskPriority::Critical: priority = "CRIT"; break;
            case TaskPriority::High:     priority = "HIGH"; break;
            case TaskPriority::Medium:  priority = "MED";  break;
            case TaskPriority::Low:     priority = "LOW";   break;
            default:                    priority = "NONE"; break;
        }

        output << status << " #" << task.id << " [" << priority << "]";
        if (!task.category.empty()) {
            output << " (" << task.category << ")";
        }
        output << " " << task.description;

        if (task.completed && task.completedAt > 0) {
            output << " [done]";
        }
        output << "\n";
    }

    return output.str();
}

std::string TodoDock::getSummary() const {
    std::ostringstream summary;
    size_t pending = m_totalCount - m_completedCount;

    summary << "TodoDock Summary: " << m_totalCount << " total, "
            << m_completedCount << " completed, "
            << pending << " pending";

    if (m_totalCount > 0) {
        double progress = (static_cast<double>(m_completedCount) / m_totalCount) * 100.0;
        summary << " (" << std::fixed << std::setprecision(1) << progress << "%)";
    }

    return summary.str();
}

void TodoDock::clearCompleted() {
    m_tasks.erase(
        std::remove_if(m_tasks.begin(), m_tasks.end(),
                       [](const Task& t) { return t.completed; }),
        m_tasks.end());
    m_completedCount = 0;
    m_totalCount = m_tasks.size();
}

void TodoDock::clearAll() {
    m_tasks.clear();
    m_completedCount = 0;
    m_totalCount = 0;
}

bool TodoDock::saveToStorage() {
    if (m_storagePath.empty()) return false;

    std::ofstream file(m_storagePath);
    if (!file.is_open()) {
        std::cerr << "TodoDock: Failed to save to " << m_storagePath << std::endl;
        return false;
    }

    file << "# TodoDock Tasks\n";
    file << "# Format: id|status|priority|category|created|completed|description\n";
    file << "TOTAL:" << m_totalCount << "\n";
    file << "COMPLETED:" << m_completedCount << "\n";
    file << "NEXTID:" << m_nextId << "\n";

    for (const auto& task : m_tasks) {
        file << task.id << "|"
             << (task.completed ? "1" : "0") << "|"
             << static_cast<int>(task.priority) << "|"
             << task.category << "|"
             << task.createdAt << "|"
             << task.completedAt << "|"
             << task.description << "\n";
    }

    file.close();
    return true;
}

bool TodoDock::loadFromStorage() {
    if (m_storagePath.empty()) return false;

    std::ifstream file(m_storagePath);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        if (line.rfind("TOTAL:", 0) == 0) {
            m_totalCount = std::stoul(line.substr(6));
        } else if (line.rfind("COMPLETED:", 0) == 0) {
            m_completedCount = std::stoul(line.substr(10));
        } else if (line.rfind("NEXTID:", 0) == 0) {
            m_nextId = std::stoul(line.substr(7));
        } else {
            // Parse task line
            std::istringstream taskLine(line);
            std::string segment;
            std::vector<std::string> parts;

            while (std::getline(taskLine, segment, '|')) {
                parts.push_back(segment);
            }

            if (parts.size() >= 7) {
                Task task;
                task.id = std::stoi(parts[0]);
                task.completed = (parts[1] == "1");
                task.priority = static_cast<TaskPriority>(std::stoi(parts[2]));
                task.category = parts[3];
                task.createdAt = std::stoul(parts[4]);
                task.completedAt = std::stoul(parts[5]);
                task.description = parts[6];
                m_tasks.push_back(task);
            }
        }
    }

    file.close();
    return true;
}

std::vector<TodoDock::Task>::iterator TodoDock::findTask(int taskId) {
    return std::find_if(m_tasks.begin(), m_tasks.end(),
                        [taskId](const Task& t) { return t.id == taskId; });
}
=======
// TODO Dock - UI component for displaying TODO items
#include "todo_dock.h"
#include "todo_manager.h"


TodoDock::TodoDock(TodoManager* todoManager, void* parent) 
    : void(parent), todoManager_(todoManager), treeWidget_(nullptr) {
    // Lightweight constructor - defer Qt widget creation
}

void TodoDock::initialize() {
    if (treeWidget_) return;  // Already initialized
    
    setupUI();
    loadTodos();
    
    // Connect to todo manager signals
// Qt connect removed
// Qt connect removed
// Qt connect removed
}

void TodoDock::setupUI() {
    void* layout = new void(this);
    layout->setContentsMargins(0, 0, 0, 0);
    
    treeWidget_ = nullptr;
    treeWidget_->setHeaderLabels({"Description", "File", "Created", "Status"});
    treeWidget_->setStyleSheet(
        "QTreeWidget { background-color: #252526; color: #d4d4d4; border: none; }"
        "QTreeWidget::item:selected { background-color: #37373d; }");
    
    // Set column widths
    treeWidget_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    treeWidget_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    treeWidget_->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    treeWidget_->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
// Qt connect removed
    layout->addWidget(treeWidget_);
}

void TodoDock::loadTodos() {
    treeWidget_->clear();
    
    std::vector<TodoItem> todos = todoManager_->getTodos();
    for (const TodoItem& todo : todos) {
        QTreeWidgetItem* item = nullptr;
        item->setText(0, todo.description);
        item->setText(1, todo.filePath);
        item->setText(2, todo.created.toString("yyyy-MM-dd hh:mm"));
        item->setText(3, todo.isCompleted ? "Completed" : "Pending");
        item->setData(0, //UserRole, todo.id);
        item->setData(0, //UserRole + 1, todo.isCompleted);
    }
}

void TodoDock::refreshTodos() {
    loadTodos();
}

void TodoDock::onTodoAdded(const TodoItem& todo) {
    QTreeWidgetItem* item = nullptr;
    item->setText(0, todo.description);
    item->setText(1, todo.filePath);
    item->setText(2, todo.created.toString("yyyy-MM-dd hh:mm"));
    item->setText(3, todo.isCompleted ? "Completed" : "Pending");
    item->setData(0, //UserRole, todo.id);
    item->setData(0, //UserRole + 1, todo.isCompleted);
}

void TodoDock::onTodoCompleted(const std::string& id) {
    for (int i = 0; i < treeWidget_->topLevelItemCount(); ++i) {
        QTreeWidgetItem* item = treeWidget_->topLevelItem(i);
        if (item->data(0, //UserRole).toString() == id) {
            item->setText(3, "Completed");
            item->setData(0, //UserRole + 1, true);
            break;
        }
    }
}

void TodoDock::onTodoRemoved(const std::string& id) {
    for (int i = 0; i < treeWidget_->topLevelItemCount(); ++i) {
        QTreeWidgetItem* item = treeWidget_->topLevelItem(i);
        if (item->data(0, //UserRole).toString() == id) {
            delete item;
            break;
        }
    }
}

void TodoDock::onItemDoubleClicked(QTreeWidgetItem* item, int column) {
    std::string filePath = item->text(1);
    if (!filePath.empty()) {
        // Get the TODO ID from the item data
        std::string todoId = item->data(0, //UserRole).toString();
        // signal to open file in editor
        openFileRequested(filePath, todoId);
    }
}

void TodoDock::onAddTodo() {
    bool ok;
    std::string description = QInputDialog::getText(this, "Add TODO", 
        "TODO Description:", void::Normal, "", &ok);
    
    if (ok && !description.empty()) {
        todoManager_->addTodo(description, std::string(), 0);
    }
}

void TodoDock::onCompleteTodo() {
    QTreeWidgetItem* item = treeWidget_->currentItem();
    if (item) {
        std::string todoId = item->data(0, //UserRole).toString();
        todoManager_->completeTodo(todoId);
    }
}

void TodoDock::onRemoveTodo() {
    QTreeWidgetItem* item = treeWidget_->currentItem();
    if (item) {
        std::string todoId = item->data(0, //UserRole).toString();
        todoManager_->removeTodo(todoId);
    }
}

void TodoDock::onScanCode() {
    QMessageBox::information(this, "Scan for TODOs",
        "This feature will scan all project files for TODO comments.\n\n"
        "Implementation in progress...");
}


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

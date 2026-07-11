# Sovereign IDE Training — Module 2: Code Analysis
## Foundation Path — Week 2

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## Learning Objectives

By the end of this module, you will:

- Use static analysis tools effectively
- Understand code metrics and quality indicators
- Apply refactoring techniques
- Work with version control
- Complete a full project workflow

---

## Lesson 1: Static Analysis (Day 8-10)

### 1.1 Understanding Static Analysis

Static analysis examines code without executing it:

- **Syntax checking:** Compiler errors, warnings
- **Style checking:** Code formatting, naming conventions
- **Bug detection:** Potential null pointers, memory leaks
- **Security analysis:** Vulnerability patterns
- **Performance hints:** Inefficient patterns

### 1.2 Running Analysis

**GUI Method:**

1. Analysis → Run Static Analysis (Ctrl+Shift+A)
2. View results in Analysis Panel

**Command Line:**

```powershell
SovereignIDE.exe --analyze --project MyProject
```

### 1.3 Understanding Results

```
Analysis Results for MyProject
==============================

Errors: 0
Warnings: 3
Suggestions: 12

Warning (src/main.cpp:42):
  Potential null pointer dereference
  Variable 'ptr' may be null

Suggestion (src/utils.cpp:15):
  Consider using const reference
  Parameter 'data' could be const std::string&
```

### 1.4 Code Metrics

View metrics via: Analysis → Code Metrics

| Metric | Good | Warning | Critical |
|--------|------|-----------|----------|
| Cyclomatic Complexity | < 10 | 10-20 | > 20 |
| Function Length | < 50 lines | 50-100 | > 100 |
| File Length | < 500 lines | 500-1000 | > 1000 |
| Comment Ratio | > 20% | 10-20% | < 10% |

---

## Lesson 2: Refactoring (Day 11-12)

### 2.1 What is Refactoring?

Refactoring improves code structure without changing behavior:

- **Extract Method:** Move code to new function
- **Rename Symbol:** Safe identifier renaming
- **Inline:** Replace call with body
- **Move:** Relocate code between files

### 2.2 Extract Method Example

**Before:**
```cpp
void processData() {
    // 50 lines of data validation
    // ...
    
    // 30 lines of data transformation
    // ...
    
    // 20 lines of output generation
    // ...
}
```

**After:**
```cpp
void processData() {
    auto data = validateData();
    auto transformed = transformData(data);
    generateOutput(transformed);
}

Data validateData() { /* 50 lines */ }
Data transformData(Data input) { /* 30 lines */ }
void generateOutput(Data data) { /* 20 lines */ }
```

### 2.3 Performing Refactoring

**Extract Method:**

1. Select code block
2. Right-click → Refactor → Extract Method
3. Enter method name: `validateData`
4. Click OK

**Rename Symbol:**

1. Click on variable/function name
2. Right-click → Refactor → Rename
3. Enter new name
4. Press Enter

---

## Lesson 3: Version Control (Day 13-14)

### 3.1 Git Integration

Sovereign IDE has built-in Git support.

**Initialize Repository:**

```
Project → Version Control → Initialize Git Repository
```

**Common Operations:**

| Operation | GUI | Shortcut |
|-----------|-----|----------|
| Stage | Right-click file | Ctrl+Alt+S |
| Commit | VCS → Commit | Ctrl+K |
| Push | VCS → Push | Ctrl+Shift+K |
| Pull | VCS → Pull | Ctrl+T |
| Branch | VCS → Branch | - |

### 3.2 Commit Best Practices

```
Commit Message Format:
[type]: [short description]

[optional body]

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation
- refactor: Code restructuring
- test: Adding tests
- perf: Performance improvement
```

Example:
```
feat: Add user authentication

- Implement login form
- Add password hashing
- Create session management
```

### 3.3 Branching Strategy

```
main
  └── develop
       ├── feature/login
       ├── feature/dashboard
       └── bugfix/memory-leak
```

**Creating a Branch:**

1. VCS → Branch → New Branch
2. Name: `feature/my-feature`
3. Based on: `develop`

---

## Hands-On Project: Task Manager

### Project Requirements

Build a command-line task manager with:

1. Add tasks
2. List tasks
3. Mark tasks complete
4. Delete tasks
5. Save/load from file

### Implementation Steps

**Step 1: Project Setup**

```powershell
SovereignIDE.exe --new-project TaskManager --type console
cd TaskManager
```

**Step 2: Core Data Structure**

```cpp
// include/task.h
#pragma once
#include <string>
#include <vector>

struct Task {
    int id;
    std::string title;
    std::string description;
    bool completed;
    std::string createdAt;
};

class TaskManager {
public:
    void addTask(const std::string& title, 
                 const std::string& description);
    void listTasks() const;
    void completeTask(int id);
    void deleteTask(int id);
    void saveToFile(const std::string& filename) const;
    void loadFromFile(const std::string& filename);
    
private:
    std::vector<Task> tasks;
    int nextId = 1;
};
```

**Step 3: Implementation**

```cpp
// src/task_manager.cpp
#include "task.h"
#include <iostream>
#include <fstream>

void TaskManager::addTask(const std::string& title,
                          const std::string& description) {
    Task task{nextId++, title, description, false, 
               getCurrentTime()};
    tasks.push_back(task);
    std::cout << "Task added: " << title << std::endl;
}

void TaskManager::listTasks() const {
    if (tasks.empty()) {
        std::cout << "No tasks." << std::endl;
        return;
    }
    
    for (const auto& task : tasks) {
        std::cout << "[" << task.id << "] "
                  << (task.completed ? "[X] " : "[ ] ")
                  << task.title << std::endl;
    }
}

// ... implement other methods
```

**Step 4: Main Program**

```cpp
// src/main.cpp
#include "task.h"
#include <iostream>

void showMenu() {
    std::cout << "\nTask Manager\n"
              << "1. Add task\n"
              << "2. List tasks\n"
              << "3. Complete task\n"
              << "4. Delete task\n"
              << "5. Save\n"
              << "6. Load\n"
              << "0. Exit\n"
              << "Choice: ";
}

int main() {
    TaskManager manager;
    int choice;
    
    do {
        showMenu();
        std::cin >> choice;
        
        switch (choice) {
            case 1: /* Add task */ break;
            case 2: manager.listTasks(); break;
            // ... other cases
        }
    } while (choice != 0);
    
    return 0;
}
```

### Project Checklist

- [ ] Code compiles without warnings
- [ ] Static analysis passes
- [ ] Cyclomatic complexity < 10 per function
- [ ] All functions have comments
- [ ] Git repository initialized
- [ ] At least 3 commits with good messages
- [ ] README.md created

---

## Assessment

### Written Exam

1. What is cyclomatic complexity?
2. When should you extract a method?
3. What is the difference between `git commit` and `git push`?
4. Name three code metrics and their thresholds.

### Practical Exam

Complete the Task Manager project:

- ✅ All features working
- ✅ Code analysis score > 80%
- ✅ At least 5 commits
- ✅ Proper documentation

---

## Summary

Module 2 covers:

- ✅ Static analysis tools
- ✅ Code metrics and quality
- ✅ Refactoring techniques
- ✅ Version control with Git
- ✅ Complete project workflow

**Next:** Module 3 — Advanced Coding and Debugging

---

*End of Module 2: Code Analysis*

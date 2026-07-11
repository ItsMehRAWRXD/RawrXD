# Sovereign IDE — Training Module 3
## Developer Path: Core Features

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Difficulty:** Beginner  
**Duration:** 4 hours

---

## 1. Module Overview

This module introduces developers to the core features of the Sovereign IDE. By the end of this module, you will be able to:

- Navigate the IDE interface efficiently
- Use the code editor with advanced features
- Work with projects and workspaces
- Perform basic debugging
- Use version control integration

---

## 2. IDE Interface Navigation

### 2.1 Layout Overview

The Sovereign IDE interface consists of:

```
┌─────────────────────────────────────────────────────────────┐
│ Menu Bar                                                    │
├──────────┬──────────────────────────────────────────────────┤
│          │                                                  │
│ Activity │              Editor Area                         │
│  Bar     │                                                  │
│          │                                                  │
├──────────┤                                                  │
│          │                                                  │
│ Side     │                                                  │
│ Panel    │                                                  │
│          │                                                  │
├──────────┴──────────────────────────────────────────────────┤
│ Status Bar                                                  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Activity Bar

The Activity Bar provides quick access to:

- **Explorer** (`Ctrl+Shift+E`) - File and folder navigation
- **Search** (`Ctrl+Shift+F`) - Global search across files
- **Source Control** (`Ctrl+Shift+G`) - Git integration
- **Run and Debug** (`Ctrl+Shift+D`) - Debugging tools
- **Extensions** (`Ctrl+Shift+X`) - Extension management
- **AI Assistant** (`Ctrl+Shift+A`) - AI-powered features

### 2.3 Command Palette

The Command Palette provides access to all IDE commands:

- **Open:** `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (macOS)
- **Quick Open:** `Ctrl+P` (Windows/Linux) or `Cmd+P` (macOS)

**Practice Exercise:**
1. Open the Command Palette
2. Type ">settings" to access settings
3. Type ">keyboard shortcuts" to view shortcuts

---

## 3. Code Editor Features

### 3.1 Basic Editing

| Feature | Shortcut | Description |
|---------|----------|-------------|
| Cut | `Ctrl+X` | Cut selected text |
| Copy | `Ctrl+C` | Copy selected text |
| Paste | `Ctrl+V` | Paste from clipboard |
| Undo | `Ctrl+Z` | Undo last action |
| Redo | `Ctrl+Y` | Redo last undone action |
| Find | `Ctrl+F` | Find in current file |
| Replace | `Ctrl+H` | Find and replace |
| Go to Line | `Ctrl+G` | Jump to specific line |

### 3.2 Multi-Cursor Editing

Multi-cursor editing allows simultaneous editing at multiple positions:

- **Add cursor above:** `Alt+Up`
- **Add cursor below:** `Alt+Down`
- **Add cursor at next occurrence:** `Ctrl+D`
- **Add cursor at all occurrences:** `Ctrl+Shift+L`

**Example:**
```cpp
// Before: Select "value" and press Ctrl+D multiple times
int value1 = 10;
int value2 = 20;
int value3 = 30;

// After: Type "data" to replace all instances
int data1 = 10;
int data2 = 20;
int data3 = 30;
```

### 3.3 Code Folding

Fold and unfold code blocks:

- **Fold:** `Ctrl+Shift+[`
- **Unfold:** `Ctrl+Shift+]`
- **Fold All:** `Ctrl+K Ctrl+0`
- **Unfold All:** `Ctrl+K Ctrl+J`

### 3.4 IntelliSense

IntelliSense provides intelligent code completion:

- **Trigger:** `Ctrl+Space`
- **Parameter Info:** `Ctrl+Shift+Space`
- **Quick Info:** Hover over symbol

**Practice Exercise:**
1. Create a new C++ file
2. Type `#include <vector>`
3. Type `std::vector<int> vec;`
4. Type `vec.` and press `Ctrl+Space` to see available methods

---

## 4. Project and Workspace Management

### 4.1 Opening Projects

**From File System:**
1. File → Open Folder (`Ctrl+K Ctrl+O`)
2. Select project folder
3. Click "Open"

**From Version Control:**
1. File → Clone Repository
2. Enter repository URL
3. Select local destination
4. Click "Clone"

### 4.2 Workspace Configuration

Workspaces allow multiple projects:

```json
// workspace.sws (Sovereign Workspace)
{
    "folders": [
        {
            "path": "project1",
            "name": "Core Library"
        },
        {
            "path": "project2",
            "name": "Application"
        }
    ],
    "settings": {
        "editor.tabSize": 4
    }
}
```

### 4.3 File Operations

**Explorer Context Menu:**
- New File (`Ctrl+N`)
- New Folder
- Refresh Explorer
- Collapse Folders

**Quick Navigation:**
- **Go to File:** `Ctrl+P`
- **Go to Symbol:** `Ctrl+Shift+O`
- **Go to Definition:** `F12`

---

## 5. Debugging Basics

### 5.1 Starting a Debug Session

1. Open the Run and Debug view (`Ctrl+Shift+D`)
2. Click "create a launch.json file"
3. Select environment (C++, Python, etc.)
4. Configure launch settings

**Example launch.json for C++:**
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug C++",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/build/app",
            "args": [],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb"
        }
    ]
}
```

### 5.2 Breakpoints

| Action | Shortcut | Description |
|--------|----------|-------------|
| Toggle Breakpoint | `F9` | Add/remove breakpoint |
| Conditional Breakpoint | `Shift+F9` | Break when condition is met |
| Logpoint | `Ctrl+Shift+F9` | Log message without breaking |

### 5.3 Debug Controls

| Action | Shortcut | Description |
|--------|----------|-------------|
| Start Debugging | `F5` | Begin debug session |
| Stop Debugging | `Shift+F5` | End debug session |
| Continue | `F5` | Continue execution |
| Step Over | `F10` | Execute next line |
| Step Into | `F11` | Step into function |
| Step Out | `Shift+F11` | Step out of function |

### 5.4 Debug Views

- **Variables:** View and modify variable values
- **Watch:** Monitor specific expressions
- **Call Stack:** View function call hierarchy
- **Breakpoints:** Manage all breakpoints

---

## 6. Version Control Integration

### 6.1 Git Basics

**Initialize Repository:**
1. Open Source Control view (`Ctrl+Shift+G`)
2. Click "Initialize Repository"

**Common Operations:**

| Operation | Command | Description |
|-----------|---------|-------------|
| Stage Changes | `+` icon | Stage selected files |
| Commit | `Ctrl+Enter` | Commit staged changes |
| Push | `...` menu → Push | Push to remote |
| Pull | `...` menu → Pull | Pull from remote |

### 6.2 Branch Management

**Create Branch:**
1. Click branch name in status bar
2. Select "Create new branch"
3. Enter branch name

**Switch Branch:**
1. Click branch name in status bar
2. Select target branch

**Merge Branch:**
1. Switch to target branch
2. Source Control → ... → Merge Branch
3. Select source branch

### 6.3 Diff View

View file differences:

1. Click changed file in Source Control
2. Review changes in diff view
3. Use inline actions to stage/revert changes

---

## 7. Practical Exercises

### Exercise 1: IDE Navigation

**Objective:** Navigate the IDE efficiently

**Steps:**
1. Open the Command Palette and find "Preferences: Open Settings"
2. Use Quick Open to find a file
3. Switch between Activity Bar views
4. Collapse and expand the Side Panel

**Expected Time:** 10 minutes

### Exercise 2: Multi-Cursor Editing

**Objective:** Use multi-cursor features

**Steps:**
1. Create a file with 5 similar lines
2. Use `Alt+Click` to place multiple cursors
3. Type text that appears on all lines
4. Use `Ctrl+D` to select multiple occurrences

**Expected Time:** 15 minutes

### Exercise 3: Debug a Simple Program

**Objective:** Debug a C++ program

**Steps:**
1. Create a simple C++ program with a bug
2. Set a breakpoint
3. Start debugging
4. Step through code
5. Fix the bug

**Sample Code:**
```cpp
#include <iostream>

int main() {
    int sum = 0;
    for (int i = 0; i <= 10; i++) {
        sum += i;  // Set breakpoint here
    }
    std::cout << "Sum: " << sum << std::endl;
    return 0;
}
```

**Expected Time:** 30 minutes

### Exercise 4: Git Workflow

**Objective:** Complete a basic Git workflow

**Steps:**
1. Initialize a Git repository
2. Create and edit a file
3. Stage the changes
4. Commit with a message
5. Create a new branch
6. Make changes and commit
7. Merge back to main

**Expected Time:** 20 minutes

---

## 8. Module Assessment

### Knowledge Check

1. What is the shortcut to open the Command Palette?
2. How do you add multiple cursors?
3. What is the purpose of a workspace?
4. How do you set a conditional breakpoint?
5. What are the steps to commit changes in Git?

### Practical Assessment

Create a simple project that demonstrates:
- File navigation
- Multi-cursor editing
- Debugging session
- Git commit

**Pass Criteria:** Successfully complete all practical exercises

---

## 9. Next Steps

Upon completing this module:

1. Proceed to **Module 4: Developer Path - Advanced Editing**
2. Practice the features learned in this module
3. Explore keyboard shortcuts documentation
4. Join the community forums for questions

---

## Summary

This module covered:

- ✅ IDE interface navigation
- ✅ Code editor features
- ✅ Project and workspace management
- ✅ Basic debugging
- ✅ Version control integration

**Status:** Complete

---

*End of Module 3: Developer Path - Core Features*

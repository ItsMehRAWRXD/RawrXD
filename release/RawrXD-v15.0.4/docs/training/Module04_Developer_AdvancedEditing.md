# Sovereign IDE — Training Module 4
## Developer Path: Advanced Editing

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Difficulty:** Intermediate  
**Duration:** 4 hours

---

## 1. Module Overview

This module covers advanced editing features of the Sovereign IDE. By the end of this module, you will be able to:

- Use advanced search and replace
- Leverage code snippets and templates
- Work with multiple editor groups
- Use refactoring tools
- Customize editor settings

---

## 2. Advanced Search and Replace

### 2.1 Global Search

**Open Global Search:** `Ctrl+Shift+F`

**Search Options:**
- Match Case (`Alt+C`)
- Match Whole Word (`Alt+W`)
- Use Regular Expressions (`Alt+R`)
- Include/Exclude Files

**Example Regex Patterns:**
```regex
// Find all function declarations
^\s*(\w+)\s+(\w+)\s*\([^)]*\)\s*\{

// Find TODO comments
TODO.*$

// Find unused variables
^\s*\w+\s+\w+\s*;\s*$
```

### 2.2 Search and Replace in Files

**Open Replace in Files:** `Ctrl+Shift+H`

**Workflow:**
1. Enter search pattern
2. Enter replacement pattern
3. Preview changes
4. Replace All or Replace Individual

**Example: Rename Variable Across Project**
```
Search: \boldVariable\b
Replace: newVariable
Files to include: *.cpp, *.h
```

### 2.3 Symbol Search

**Go to Symbol in File:** `Ctrl+Shift+O`
**Go to Symbol in Workspace:** `Ctrl+T`

**Symbol Types:**
- Classes
- Functions
- Variables
- Enums
- Macros

---

## 3. Code Snippets and Templates

### 3.1 Built-in Snippets

**Insert Snippet:** `Ctrl+Shift+J`

**Common Snippets:**

| Language | Snippet | Description |
|----------|---------|-------------|
| C++ | `for` | For loop template |
| C++ | `if` | If statement template |
| C++ | `class` | Class definition |
| C++ | `main` | Main function |
| Python | `def` | Function definition |
| Python | `ifmain` | If __name__ == '__main__' |

### 3.2 Custom Snippets

**Create Custom Snippet:**

1. File → Preferences → Configure User Snippets
2. Select language
3. Add snippet definition:

```json
{
    "Print to Console": {
        "prefix": "log",
        "body": [
            "console.log('$1');",
            "$2"
        ],
        "description": "Log output to console"
    },
    "C++ Class Template": {
        "prefix": "class",
        "body": [
            "class ${1:ClassName} {",
            "public:",
            "    ${1:ClassName}();",
            "    ~${1:ClassName}();",
            "",
            "private:",
            "    $2",
            "};"
        ],
        "description": "C++ class template"
    }
}
```

**Snippet Variables:**
- `$1`, `$2`, etc. - Tab stops
- `${1:default}` - Default value
- `$0` - Final cursor position
- `${TM_FILENAME}` - Current filename
- `${CURRENT_YEAR}` - Current year

### 3.3 File Templates

**Create New File from Template:**

1. File → New File from Template
2. Select template
3. Customize placeholders

**Custom Template Example:**
```cpp
// File: templates/cpp_header.h
#ifndef ${TM_FILENAME_BASE/(.*)/${1:/upcase}/}_H
#define ${TM_FILENAME_BASE/(.*)/${1:/upcase}/}_H

namespace ${1:namespace} {

class ${TM_FILENAME_BASE} {
public:
    ${TM_FILENAME_BASE}();
    ~${TM_FILENAME_BASE}();

private:
    $2
};

} // namespace $1

#endif // ${TM_FILENAME_BASE/(.*)/${1:/upcase}/}_H
```

---

## 4. Editor Groups and Layouts

### 4.1 Split Editor

**Split Commands:**

| Command | Shortcut | Description |
|---------|----------|-------------|
| Split Right | `Ctrl+\` | Split editor vertically |
| Split Down | `Ctrl+K Ctrl+\` | Split editor horizontally |
| Close Editor | `Ctrl+W` | Close current editor |
| Close Others | `Ctrl+K W` | Close other editors |

### 4.2 Editor Groups

**Navigate Between Groups:**
- Next Group: `Ctrl+K Ctrl+Right`
- Previous Group: `Ctrl+K Ctrl+Left`
- Move Editor to Group: `Ctrl+K M`

**Layout Presets:**

```
Single:     Vertical Split:    Grid:
┌──────┐    ┌──────┬──────┐     ┌──────┬──────┐
│      │    │      │      │     │      │      │
│  A   │    │  A   │  B   │     │  A   │  B   │
│      │    │      │      │     ├──────┼──────┤
└──────┘    └──────┴──────┘     │  C   │  D   │
                                 │      │      │
                                 └──────┴──────┘
```

### 4.3 Zen Mode

**Enter Zen Mode:** `Ctrl+K Z`

**Features:**
- Distraction-free editing
- Centered layout
- Hidden UI elements
- Fullscreen option

**Exit Zen Mode:** Press `Esc` twice

---

## 5. Refactoring Tools

### 5.1 Rename Symbol

**Rename Symbol:** `F2`

**Supported Symbols:**
- Variables
- Functions
- Classes
- Namespaces
- Files

**Example:**
```cpp
// Before rename
class OldName {
    void method();
};

OldName* obj = new OldName();
obj->method();

// After rename (F2 on OldName, type NewName)
class NewName {
    void method();
};

NewName* obj = new NewName();
obj->method();
```

### 5.2 Extract Method

**Extract Method:** `Ctrl+Shift+R M`

**Steps:**
1. Select code block
2. Trigger Extract Method
3. Enter method name
4. Review parameters
5. Confirm

**Example:**
```cpp
// Before
void processData() {
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += i * i;
    }
    std::cout << sum << std::endl;
}

// After extracting calculation
void processData() {
    int sum = calculateSum();
    std::cout << sum << std::endl;
}

int calculateSum() {
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += i * i;
    }
    return sum;
}
```

### 5.3 Other Refactorings

| Refactoring | Shortcut | Description |
|-------------|----------|-------------|
| Extract Variable | `Ctrl+Shift+R V` | Extract expression to variable |
| Extract Constant | `Ctrl+Shift+R C` | Extract to constant |
| Inline Variable | `Ctrl+Shift+R I` | Replace variable with expression |
| Move Definition | `Ctrl+Shift+R D` | Move to header/source |
| Change Signature | `Ctrl+Shift+R S` | Modify function signature |

---

## 6. Editor Customization

### 6.1 Settings

**Open Settings:** `Ctrl+,`

**Common Settings:**

```json
{
    "editor.fontSize": 14,
    "editor.fontFamily": "Fira Code, Consolas, monospace",
    "editor.lineHeight": 1.5,
    "editor.tabSize": 4,
    "editor.insertSpaces": true,
    "editor.wordWrap": "on",
    "editor.minimap.enabled": true,
    "editor.formatOnSave": true,
    "editor.rulers": [80, 120],
    "editor.renderWhitespace": "selection"
}
```

### 6.2 Keybindings

**Open Keybindings:** `Ctrl+K Ctrl+S`

**Custom Keybinding Example:**
```json
[
    {
        "key": "ctrl+shift+t",
        "command": "workbench.action.terminal.new",
        "when": "editorTextFocus"
    },
    {
        "key": "ctrl+shift+b",
        "command": "workbench.action.tasks.build"
    }
]
```

### 6.3 Color Themes

**Change Theme:** `Ctrl+K Ctrl+T`

**Built-in Themes:**
- Sovereign Dark (default)
- Sovereign Light
- High Contrast
- Custom themes via extensions

---

## 7. Practical Exercises

### Exercise 1: Regex Search and Replace

**Objective:** Use regex to refactor code

**Task:**
1. Open a project with multiple files
2. Find all TODO comments using regex
3. Replace with formatted TODO including date

**Pattern:**
```regex
Search: TODO:\s*(.*)
Replace: TODO ($(CURRENT_YEAR)-$(CURRENT_MONTH)-$(CURRENT_DAY)): $1
```

**Expected Time:** 20 minutes

### Exercise 2: Create Custom Snippets

**Objective:** Create useful code snippets

**Tasks:**
1. Create a C++ class template snippet
2. Create a Python function template snippet
3. Test snippets in new files

**Expected Time:** 30 minutes

### Exercise 3: Multi-Editor Workflow

**Objective:** Work with multiple editor groups

**Tasks:**
1. Open 4 files
2. Create a 2x2 grid layout
3. Navigate between editors
4. Move files between groups

**Expected Time:** 15 minutes

### Exercise 4: Refactoring Practice

**Objective:** Apply refactoring techniques

**Tasks:**
1. Extract a method from existing code
2. Rename a class and verify all references update
3. Extract a constant from magic numbers

**Expected Time:** 30 minutes

---

## 8. Module Assessment

### Knowledge Check

1. What is the shortcut for global search?
2. How do you create a custom snippet?
3. What is Zen Mode and how do you enter it?
4. How do you rename a symbol across the entire project?
5. What is the purpose of editor rulers?

### Practical Assessment

Complete a refactoring task:
1. Take a sample code file
2. Apply at least 3 different refactorings
3. Verify code still compiles/runs

**Pass Criteria:** Successfully complete all exercises

---

## 9. Next Steps

Upon completing this module:

1. Proceed to **Module 5: Developer Path - Debugging**
2. Practice creating your own snippets
3. Explore additional refactoring options
4. Customize your editor settings

---

## Summary

This module covered:

- ✅ Advanced search and replace
- ✅ Code snippets and templates
- ✅ Editor groups and layouts
- ✅ Refactoring tools
- ✅ Editor customization

**Status:** Complete

---

*End of Module 4: Developer Path - Advanced Editing*

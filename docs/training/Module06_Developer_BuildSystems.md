# Sovereign IDE — Training Module 6
## Developer Path: Build Systems

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Difficulty:** Intermediate  
**Duration:** 4 hours

---

## 1. Module Overview

This module covers build system integration in the Sovereign IDE. By the end of this module, you will be able to:

- Configure tasks for building projects
- Integrate with various build systems
- Set up build configurations
- Handle build errors and warnings
- Automate build workflows

---

## 2. Task System

### 2.1 tasks.json Structure

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Build",
            "type": "shell",
            "command": "make",
            "args": ["-j4"],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "shared"
            },
            "problemMatcher": ["$gcc"]
        }
    ]
}
```

### 2.2 Task Types

| Type | Description | Example |
|------|-------------|---------|
| `shell` | Execute shell command | `make`, `cmake` |
| `process` | Run executable directly | Custom build tool |
| ` Sovereign` | Built-in Sovereign tasks | Compile, test |

### 2.3 Task Properties

```json
{
    "label": "Build Debug",
    "type": "shell",
    "command": "cmake",
    "args": [
        "--build",
        "${workspaceFolder}/build",
        "--config",
        "Debug"
    ],
    "options": {
        "cwd": "${workspaceFolder}",
        "env": {
            "CC": "clang",
            "CXX": "clang++"
        }
    },
    "group": "build",
    "dependsOn": ["Configure"],
    "dependsOrder": "sequence"
}
```

---

## 3. CMake Integration

### 3.1 CMake Configuration

**tasks.json for CMake:**
```json
{
    "tasks": [
        {
            "label": "CMake: Configure",
            "type": "shell",
            "command": "cmake",
            "args": [
                "-B", "${workspaceFolder}/build",
                "-S", "${workspaceFolder}",
                "-DCMAKE_BUILD_TYPE=Debug",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
            ],
            "group": "build"
        },
        {
            "label": "CMake: Build",
            "type": "shell",
            "command": "cmake",
            "args": [
                "--build", "${workspaceFolder}/build",
                "--parallel", "4"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "dependsOn": ["CMake: Configure"]
        },
        {
            "label": "CMake: Clean",
            "type": "shell",
            "command": "cmake",
            "args": [
                "--build", "${workspaceFolder}/build",
                "--target", "clean"
            ],
            "group": "build"
        },
        {
            "label": "CMake: Test",
            "type": "shell",
            "command": "ctest",
            "args": [
                "--test-dir", "${workspaceFolder}/build",
                "--output-on-failure"
            ],
            "group": "test"
        }
    ]
}
```

### 3.2 CMake Presets

**CMakePresets.json:**
```json
{
    "version": 3,
    "configurePresets": [
        {
            "name": "default",
            "hidden": true,
            "generator": "Ninja",
            "binaryDir": "${sourceDir}/build"
        },
        {
            "name": "debug",
            "inherits": "default",
            "cacheVariables": {
                "CMAKE_BUILD_TYPE": "Debug"
            }
        },
        {
            "name": "release",
            "inherits": "default",
            "cacheVariables": {
                "CMAKE_BUILD_TYPE": "Release"
            }
        }
    ],
    "buildPresets": [
        {
            "name": "debug",
            "configurePreset": "debug"
        },
        {
            "name": "release",
            "configurePreset": "release"
        }
    ]
}
```

---

## 4. Make Integration

### 4.1 Makefile Tasks

```json
{
    "tasks": [
        {
            "label": "Make: Build",
            "type": "shell",
            "command": "make",
            "args": [
                "-j$(nproc)",
                "CXXFLAGS=-g -O0"
            ],
            "group": "build",
            "problemMatcher": ["$gcc"]
        },
        {
            "label": "Make: Clean",
            "type": "shell",
            "command": "make",
            "args": ["clean"],
            "group": "build"
        },
        {
            "label": "Make: Test",
            "type": "shell",
            "command": "make",
            "args": ["test"],
            "group": "test"
        }
    ]
}
```

### 4.2 Advanced Make Options

```json
{
    "label": "Make: Verbose Build",
    "type": "shell",
    "command": "make",
    "args": [
        "-j4",
        "V=1",
        "2\u003e\u00261"
    ],
    "group": "build",
    "presentation": {
        "clear": true
    }
}
```

---

## 5. Custom Build Scripts

### 5.1 Python Build Script

**build.py:**
```python
#!/usr/bin/env python3
import argparse
import subprocess
import sys

def configure(args):
    cmd = [
        'cmake',
        '-B', 'build',
        '-S', '.',
        f'-DCMAKE_BUILD_TYPE={args.config}'
    ]
    subprocess.run(cmd, check=True)

def build(args):
    cmd = [
        'cmake',
        '--build', 'build',
        '--parallel', str(args.jobs)
    ]
    subprocess.run(cmd, check=True)

def test(args):
    cmd = ['ctest', '--test-dir', 'build', '--output-on-failure']
    subprocess.run(cmd, check=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['configure', 'build', 'test'])
    parser.add_argument('--config', default='Debug')
    parser.add_argument('-j', '--jobs', type=int, default=4)
    args = parser.parse_args()
    
    commands = {
        'configure': configure,
        'build': build,
        'test': test
    }
    
    commands[args](args)

if __name__ == '__main__':
    main()
```

**tasks.json:**
```json
{
    "tasks": [
        {
            "label": "Build: Configure",
            "type": "shell",
            "command": "python",
            "args": ["build.py", "configure", "--config", "Debug"],
            "group": "build"
        },
        {
            "label": "Build: Compile",
            "type": "shell",
            "command": "python",
            "args": ["build.py", "build", "-j", "4"],
            "group": "build"
        }
    ]
}
```

---

## 6. Problem Matchers

### 6.1 Built-in Matchers

| Matcher | Pattern | Languages |
|---------|---------|-----------|
| `$gcc` | GCC/Clang errors | C, C++ |
| `$msCompile` | MSVC errors | C, C++ |
| `$python` | Python errors | Python |
| `$eslint` | ESLint errors | JavaScript |

### 6.2 Custom Problem Matcher

```json
{
    "problemMatcher": {
        "pattern": {
            "regexp": "^(.*):(\\d+):(\\d+):\\s+(error|warning):\\s+(.*)$",
            "file": 1,
            "line": 2,
            "column": 3,
            "severity": 4,
            "message": 5
        },
        "fileLocation": ["relative", "${workspaceFolder}"]
    }
}
```

---

## 7. Build Automation

### 7.1 Pre/Post Build Tasks

```json
{
    "tasks": [
        {
            "label": "Build: Full",
            "dependsOn": [
                "Build: Clean",
                "Build: Configure",
                "Build: Compile",
                "Build: Test"
            ],
            "dependsOrder": "sequence",
            "group": "build"
        }
    ]
}
```

### 7.2 Watch Mode

```json
{
    "tasks": [
        {
            "label": "Build: Watch",
            "type": "shell",
            "command": "nodemon",
            "args": [
                "--watch", "src",
                "--ext", "cpp,h",
                "--exec", "make -j4"
            ],
            "isBackground": true,
            "problemMatcher": {
                "pattern": {
                    "regexp": "."
                },
                "background": {
                    "activeOnStart": true,
                    "beginsPattern": "^Starting",
                    "endsPattern": "^Finished"
                }
            }
        }
    ]
}
```

---

## 8. Practical Exercises

### Exercise 1: CMake Project Setup

**Objective:** Set up CMake build system

**Tasks:**
1. Create CMakeLists.txt
2. Configure tasks.json
3. Build debug and release
4. Run tests

**Expected Time:** 30 minutes

### Exercise 2: Custom Build Script

**Objective:** Create custom build automation

**Tasks:**
1. Write Python build script
2. Configure tasks.json
3. Add problem matcher
4. Test full workflow

**Expected Time:** 40 minutes

### Exercise 3: Multi-Project Build

**Objective:** Build multiple dependent projects

**Tasks:**
1. Create library project
2. Create application project
3. Set up dependency chain
4. Build both projects

**Expected Time:** 35 minutes

---

## 9. Module Assessment

### Knowledge Check

1. What is the purpose of tasks.json?
2. How do you configure a CMake project?
3. What are problem matchers used for?
4. How do you set up task dependencies?
5. What is the difference between shell and process task types?

### Practical Assessment

Set up a complete build system:
1. Create CMakeLists.txt
2. Configure tasks.json
3. Set up problem matchers
4. Create build automation
5. Successfully build and test

**Pass Criteria:** Successfully complete all exercises

---

## 10. Next Steps

Upon completing this module:

1. Proceed to **Module 7: Developer Path - Version Control Advanced**
2. Practice with your own projects
3. Explore additional build systems
4. Learn about CI/CD integration

---

## Summary

This module covered:

- ✅ Task system configuration
- ✅ CMake integration
- ✅ Make integration
- ✅ Custom build scripts
- ✅ Problem matchers
- ✅ Build automation

**Status:** Complete

---

*End of Module 6: Developer Path - Build Systems*

# Sovereign IDE Training — Module 1: Getting Started
## Foundation Path — Week 1

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## Learning Objectives

By the end of this module, you will:

- Install and configure Sovereign IDE
- Create your first project
- Navigate the IDE interface
- Build and run a simple application
- Use basic debugging features

---

## Lesson 1: Installation (Day 1-2)

### 1.1 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10 | Windows 11 / Linux |
| CPU | 4 cores | 8+ cores (AVX2) |
| RAM | 16 GB | 32+ GB |
| GPU | Vulkan 1.2 | RTX 3060+ / RX 6600+ |
| Storage | 50 GB SSD | 200+ GB NVMe |

### 1.2 Installation Steps

#### Step 1: Download Sovereign IDE

```powershell
# Clone from GitHub
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD
```

#### Step 2: Install Dependencies

```powershell
# Install Vulkan SDK
# Download from: https://vulkan.lunarg.com/

# Verify installation
vulkaninfo | Select-String "Vulkan Instance"
```

#### Step 3: Build from Source

```powershell
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build . --config Release -j 16
```

### 1.3 Verification

Launch Sovereign IDE:

```powershell
./build/bin/SovereignIDE.exe --version
```

Expected output:
```
Sovereign IDE v1.0.0
Build: Release
Architecture: x64
Features: Vulkan, MASM, Agentic
```

---

## Lesson 2: IDE Basics (Day 3-4)

### 2.1 Interface Overview

```
┌─────────────────────────────────────────────────────────────┐
│ Menu Bar                                                    │
├──────────────┬──────────────────────────────────────────────┤
│              │                                              │
│  Workspace   │              Editor                          │
│  Browser     │                                              │
│              │                                              │
│              │                                              │
├──────────────┼──────────────────────────────────────────────┤
│  Build       │  Output / Debug Console                      │
│  Console     │                                              │
└──────────────┴──────────────────────────────────────────────┘
```

### 2.2 Creating a Project

**Method 1: GUI**

1. File → New → Project
2. Select "Console Application"
3. Name: "HelloWorld"
4. Location: `C:\Projects\`
5. Click "Create"

**Method 2: Command Line**

```powershell
SovereignIDE.exe --new-project HelloWorld --type console
```

### 2.3 Project Structure

```
HelloWorld/
├── src/
│   └── main.cpp
├── include/
├── build/
├── docs/
├── tests/
└── project.sov
```

### 2.4 Writing Your First Program

Open `src/main.cpp`:

```cpp
#include <iostream>

int main() {
    std::cout << "Hello, Sovereign IDE!" << std::endl;
    return 0;
}
```

---

## Lesson 3: Building and Running (Day 5-7)

### 3.1 Building

**GUI Method:**

1. Build → Build Project (Ctrl+B)
2. Watch Build Console for output

**Command Line:**

```powershell
cd HelloWorld
SovereignIDE.exe --build
```

Expected output:
```
Building HelloWorld...
Compiling main.cpp...
Linking...
Build successful: build/bin/HelloWorld.exe
```

### 3.2 Running

**GUI Method:**

1. Debug → Start Without Debugging (Ctrl+F5)

**Command Line:**

```powershell
./build/bin/HelloWorld.exe
```

Expected output:
```
Hello, Sovereign IDE!
```

### 3.3 Debugging Basics

**Setting a Breakpoint:**

1. Click in left margin of line 5
2. Red dot appears

**Starting Debugger:**

1. Debug → Start Debugging (F5)
2. Execution pauses at breakpoint

**Debug Controls:**

| Key | Action |
|-----|--------|
| F5 | Continue |
| F10 | Step Over |
| F11 | Step Into |
| Shift+F11 | Step Out |
| Shift+F5 | Stop |

---

## Hands-On Exercise

### Exercise 1: Calculator

Create a simple calculator that:

1. Takes two numbers as input
2. Performs addition, subtraction, multiplication, division
3. Displays results

**Starter Code:**

```cpp
#include <iostream>

int main() {
    double a, b;
    
    std::cout << "Enter first number: ";
    std::cin >> a;
    
    std::cout << "Enter second number: ";
    std::cin >> b;
    
    std::cout << "Sum: " << a + b << std::endl;
    std::cout << "Difference: " << a - b << std::endl;
    std::cout << "Product: " << a * b << std::endl;
    
    if (b != 0) {
        std::cout << "Quotient: " << a / b << std::endl;
    } else {
        std::cout << "Cannot divide by zero!" << std::endl;
    }
    
    return 0;
}
```

### Exercise 2: Debug Practice

1. Set breakpoint on line with division
2. Run with debugger
3. Inspect variables `a` and `b`
4. Step through each operation
5. Watch values change

---

## Assessment

### Quiz 1: Installation

1. What is the minimum Vulkan version required?
2. Which build system does Sovereign IDE use?
3. How do you verify the installation?

### Quiz 2: IDE Basics

1. What file extension do Sovereign IDE projects use?
2. What is the keyboard shortcut for building?
3. Where are build outputs placed?

### Practical Assessment

Build and run the calculator exercise with:

- ✅ No build errors
- ✅ Correct output
- ✅ Proper error handling
- ✅ Debug session completed

---

## Additional Resources

- Video Tutorial: "First Steps with Sovereign IDE"
- Sample Project: `examples/HelloWorld/`
- Documentation: `docs/getting-started/`
- Community Forum: https://github.com/ItsMehRAWRXD/RawrXD/discussions

---

## Summary

Module 1 covers:

- ✅ Installation and setup
- ✅ Project creation
- ✅ Basic IDE navigation
- ✅ Building and running
- ✅ Debugging fundamentals

**Next:** Module 2 — Code Analysis and Quality

---

*End of Module 1: Getting Started*

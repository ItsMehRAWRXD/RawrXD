# Sovereign IDE — Training Module 5
## Developer Path: Debugging

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Difficulty:** Intermediate  
**Duration:** 5 hours

---

## 1. Module Overview

This module covers advanced debugging techniques in the Sovereign IDE. By the end of this module, you will be able to:

- Configure complex debug configurations
- Use advanced breakpoint types
- Analyze memory and performance
- Debug multi-threaded applications
- Use remote debugging

---

## 2. Debug Configuration

### 2.1 Launch Configurations

**launch.json Structure:**
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug C++ Application",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/build/app",
            "args": ["--verbose", "--config", "debug"],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [
                {"name": "DEBUG", "value": "1"},
                {"name": "LOG_LEVEL", "value": "debug"}
            ],
            "externalConsole": false,
            "MIMode": "gdb",
            "miDebuggerPath": "/usr/bin/gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
            "preLaunchTask": "build",
            "postDebugTask": "cleanup"
        }
    ]
}
```

### 2.2 Compound Configurations

**Debug Multiple Targets:**
```json
{
    "compounds": [
        {
            "name": "Server/Client",
            "configurations": ["Debug Server", "Debug Client"],
            "stopAll": true
        }
    ]
}
```

### 2.3 Environment Variables

**Setting Environment:**
```json
"environment": [
    {"name": "PATH", "value": "${env:PATH}:/custom/bin"},
    {"name": "LD_LIBRARY_PATH", "value": "${workspaceFolder}/lib"}
]
```

---

## 3. Advanced Breakpoints

### 3.1 Conditional Breakpoints

**Set Condition:** Right-click breakpoint → Edit Breakpoint

**Examples:**
```cpp
// Break only when i > 100
i > 100

// Break on specific iteration
iteration == 50

// Break when pointer is null
ptr == nullptr

// Break on error condition
errorCode != 0

// Complex condition
(user != nullptr) && (user->id == 42)
```

### 3.2 Hit Count Breakpoints

**Break After N Hits:**
```
Hit Count: == 10    // Break on 10th hit
Hit Count: % 5 == 0 // Break every 5th hit
Hit Count: > 100    // Break after 100 hits
```

### 3.3 Logpoints

**Create Logpoint:** Right-click gutter → Add Logpoint

**Log Message Syntax:**
```
Iteration {i}, Value: {value}, Pointer: {ptr}
```

**Example:**
```cpp
// Logpoint message:
Processing item {i}: name={item.name}, id={item.id}

// Output:
Processing item 0: name=foo, id=123
Processing item 1: name=bar, id=456
```

### 3.4 Exception Breakpoints

**Configure Exception Breakpoints:**
1. Open Breakpoints view (`Ctrl+Shift+F9`)
2. Click "+" → Exception Breakpoint
3. Enter exception type

**C++ Exceptions:**
```cpp
// Break on all exceptions
std::exception

// Break on specific exception
std::runtime_error

// Break on access violation (Windows)
AccessViolation
```

---

## 4. Debug Views

### 4.1 Variables View

**Variable Inspection:**
- Primitive values: Displayed inline
- Structures: Expandable tree
- Arrays: Indexed elements
- Pointers: Address and dereferenced value

**Modify Variables:**
1. Right-click variable
2. Select "Set Value"
3. Enter new value

**Watch Expressions:**
```cpp
// Add to Watch:
sum + count
strlen(buffer)
user->getName()
array[0] + array[1]
```

### 4.2 Call Stack

**Navigation:**
- Click frame to switch context
- View local variables per frame
- Restart frame (re-execute function)

**Frame Actions:**
- Copy Call Stack
- Restart Frame
- Toggle between user/system code

### 4.3 Memory View

**Open Memory View:**
1. Debug → Open Memory View
2. Enter address or expression

**Memory Inspection:**
```cpp
// View memory at pointer
&variable
0x7fff12345678
malloc_ptr
```

**Memory Formats:**
- Hexadecimal (default)
- ASCII
- Binary
- Integer (8/16/32/64-bit)
- Float/Double

### 4.4 Disassembly View

**Open Disassembly:**
- Debug → Open Disassembly View
- Or when source unavailable

**Features:**
- Step through assembly
- View registers
- Set breakpoints on instructions
- View memory addresses

---

## 5. Multi-Threaded Debugging

### 5.1 Thread View

**Thread States:**
- Running
- Suspended
- Waiting
- Zombie

**Thread Operations:**
- Switch thread
- Freeze thread
- Resume thread
- Set thread-specific breakpoints

### 5.2 Thread-Specific Breakpoints

**Set Thread Condition:**
```cpp
// Break only in specific thread
GetCurrentThreadId() == 0x1234

// Break in worker threads
threadName == "Worker"
```

### 5.3 Deadlock Detection

**Analyze Deadlocks:**
1. Pause all threads
2. Check Call Stack for each thread
3. Look for circular dependencies
4. Check mutex/lock states

**Example Analysis:**
```cpp
// Thread 1: Holding lockA, waiting for lockB
// Thread 2: Holding lockB, waiting for lockA
// Result: DEADLOCK
```

---

## 6. Performance Debugging

### 6.1 CPU Profiling

**Start Profiling:**
1. Debug → Start Profiling
2. Run scenario
3. Stop profiling
4. Analyze results

**Profile View:**
- Hot path identification
- Function call counts
- Time spent per function
- Flame graph visualization

### 6.2 Memory Profiling

**Memory Analysis:**
1. Debug → Start Memory Profiling
2. Take heap snapshots
3. Compare snapshots
4. Identify leaks

**Memory Metrics:**
- Allocated bytes
- Live objects
- Peak memory usage
- Allocation sites

### 6.3 Performance Breakpoints

**Break on Slow Operations:**
```cpp
// Break if function takes > 100ms
elapsed > 100

// Break on high memory usage
memoryUsed > 1024 * 1024 * 100  // 100MB
```

---

## 7. Remote Debugging

### 7.1 Attach to Remote Process

**Configuration:**
```json
{
    "name": "Remote Attach",
    "type": "cppdbg",
    "request": "attach",
    "program": "/remote/path/to/app",
    "miDebuggerServerAddress": "192.168.1.100:1234",
    "miDebuggerPath": "/usr/bin/gdb",
    "cwd": "${workspaceFolder}",
    "environment": []
}
```

### 7.2 GDB Server

**Start GDB Server:**
```bash
# On remote machine
gdbserver :1234 ./app

# With specific host
gdbserver 192.168.1.100:1234 ./app
```

### 7.3 SSH Debugging

**SSH Tunnel:**
```bash
# Forward debug port
ssh -L 1234:localhost:1234 user@remote-host
```

---

## 8. Practical Exercises

### Exercise 1: Conditional Breakpoints

**Objective:** Use conditional breakpoints effectively

**Task:**
1. Load a sorting algorithm
2. Set breakpoint in loop with condition `i == 5`
3. Observe variable state
4. Change condition to `array[i] > 100`

**Expected Time:** 20 minutes

### Exercise 2: Memory Debugging

**Objective:** Find a memory leak

**Task:**
```cpp
#include <iostream>

void leakyFunction() {
    int* data = new int[100];
    // Missing delete[]
}

int main() {
    for (int i = 0; i < 1000; i++) {
        leakyFunction();
    }
    return 0;
}
```

1. Compile with debug symbols
2. Start memory profiling
3. Run program
4. Identify leak source

**Expected Time:** 30 minutes

### Exercise 3: Multi-Threaded Debugging

**Objective:** Debug race condition

**Task:**
```cpp
#include <thread>
#include <iostream>

int counter = 0;

void increment() {
    for (int i = 0; i < 100000; i++) {
        counter++;  // Race condition here
    }
}

int main() {
    std::thread t1(increment);
    std::thread t2(increment);
    
    t1.join();
    t2.join();
    
    std::cout << "Counter: " << counter << std::endl;
    return 0;
}
```

1. Set breakpoints in both threads
2. Observe interleaving
3. Identify race condition
4. Fix with mutex

**Expected Time:** 40 minutes

### Exercise 4: Performance Profiling

**Objective:** Profile and optimize code

**Task:**
1. Write inefficient algorithm (e.g., O(n²) search)
2. Profile execution
3. Identify bottleneck
4. Optimize and re-profile

**Expected Time:** 45 minutes

---

## 9. Module Assessment

### Knowledge Check

1. How do you set a conditional breakpoint?
2. What is the difference between a breakpoint and a logpoint?
3. How do you view memory at a specific address?
4. What information does the Call Stack provide?
5. How do you debug a multi-threaded application?

### Practical Assessment

Debug a complex application:
1. Set up debug configuration
2. Use conditional breakpoints
3. Analyze memory usage
4. Profile performance
5. Fix at least 2 bugs

**Pass Criteria:** Successfully complete all exercises

---

## 10. Next Steps

Upon completing this module:

1. Proceed to **Module 6: Developer Path - Build Systems**
2. Practice debugging your own projects
3. Explore advanced profiling features
4. Learn about debugging optimized code

---

## Summary

This module covered:

- ✅ Debug configuration
- ✅ Advanced breakpoint types
- ✅ Debug views and inspection
- ✅ Multi-threaded debugging
- ✅ Performance debugging
- ✅ Remote debugging

**Status:** Complete

---

*End of Module 5: Developer Path - Debugging*

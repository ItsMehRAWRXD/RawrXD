# Sovereign Substrate - Integration Examples

This directory contains practical examples showing how to integrate and use the Sovereign Substrate in your applications.

## Available Examples

### 1. API Integration Example (`api_integration_example.cpp`)

Shows how to integrate the Sovereign Substrate into a C++ application.

**Features:**
- Initialize the Sovereign Substrate
- Register custom tools
- Process user requests through the agent
- Execute tools directly
- Handle events
- Graceful shutdown

**Build:**
```bash
g++ -std=c++17 api_integration_example.cpp \
    -I../src \
    -L../build/lib \
    -lsovereign \
    -o api_example
```

**Run:**
```bash
./api_example
```

### 2. WebSocket Client Example (`websocket_client_example.js`)

Shows how to connect to the Control Plane UI from JavaScript/Node.js.

**Features:**
- WebSocket connection management
- Automatic reconnection
- Request/response pattern
- Event subscription
- Error handling

**Usage:**
```javascript
const { SovereignClient } = require('./websocket_client_example.js');

const client = new SovereignClient('ws://localhost:8080');
await client.connect();

// Execute a tool
const result = await client.executeTool('read_file', {
    file_path: 'src/main.cpp'
});

// Execute an intent
const intentResult = await client.executeIntent('analyze_code', {
    target: 'src/main.cpp'
});
```

### 3. Python Integration Example (`python_integration_example.py`)

Shows how to integrate the Sovereign Substrate from Python.

**Features:**
- Async/await support
- Context manager
- High-level API
- Type hints
- Error handling

**Usage:**
```python
from python_integration_example import SovereignSubstrate

async with SovereignSubstrate("http://localhost:8080") as substrate:
    # Read a file
    content = await substrate.read_file("README.md")
    
    # Execute an intent
    result = await substrate.execute_intent("analyze_code", {
        "target": "src/main.cpp"
    })
    
    # Query memory graph
    results = await substrate.query_memory("functions in main")
```

## Quick Start

### Prerequisites

1. Build the Sovereign Substrate:
```bash
cd ..
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

2. Start the Control Plane:
```bash
./demo/demo_sovereign_substrate --server
```

### Running Examples

#### C++ Example
```bash
cd examples
g++ -std=c++17 api_integration_example.cpp -I../src -o api_example
./api_example
```

#### JavaScript Example
```bash
cd examples
node websocket_client_example.js
```

#### Python Example
```bash
cd examples
pip install aiohttp
python python_integration_example.py
```

## Example Scenarios

### Scenario 1: Code Analysis

```cpp
// C++
Intent intent;
intent.action = "analyze_code";
intent.params["target"] = "src/main.cpp";
intent.params["type"] = "complexity";

auto result = kernel.ExecuteIntent(intent);
```

```python
# Python
result = await substrate.execute_intent("analyze_code", {
    "target": "src/main.cpp",
    "type": "complexity"
})
```

### Scenario 2: File Operations

```cpp
// C++
auto result = Tools::TOOL_REGISTRY.Execute(
    "read_file",
    {{"file_path", "config.json"}}
);
```

```python
# Python
content = await substrate.read_file("config.json")
```

### Scenario 3: Git Operations

```cpp
// C++
auto result = Tools::TOOL_REGISTRY.Execute(
    "git_status",
    {{"repo_path", "."}}
);
```

```python
# Python
status = await substrate.git_status(".")
```

### Scenario 4: Memory Graph Query

```cpp
// C++
auto& memory = RepositoryGraph::Instance();
auto results = memory.Query("functions in main");
```

```python
# Python
results = await substrate.query_memory("functions in main")
```

## Integration Patterns

### Pattern 1: Direct Integration

Embed the Sovereign Substrate directly in your application:

```cpp
#include "kernel/AgentKernel.hpp"

class MyApp {
    RawrXD::AgentKernel kernel_;
public:
    void Initialize() {
        kernel_.Initialize();
    }
};
```

### Pattern 2: Service Integration

Connect to a running Sovereign Substrate service:

```python
from python_integration_example import SovereignSubstrate

async with SovereignSubstrate("http://localhost:8080") as substrate:
    # Use the API
    pass
```

### Pattern 3: Plugin Integration

Create a plugin that extends the Sovereign Substrate:

```cpp
class MyPlugin : public RawrXD::Plugin {
    void Initialize() override {
        // Register custom tools
        // Set up event handlers
    }
};
```

## Best Practices

1. **Always validate inputs** before passing to the Sovereign Substrate
2. **Handle errors gracefully** - check result status
3. **Use async operations** for long-running tasks
4. **Subscribe to events** for real-time updates
5. **Save memory graph** periodically for persistence
6. **Monitor telemetry** for performance insights

## Troubleshooting

### Connection Refused

- Ensure the Control Plane is running
- Check the port (default: 8080)
- Verify firewall settings

### Authentication Failed

- Check API key configuration
- Verify permissions
- Review security settings

### Tool Execution Failed

- Check tool parameters
- Verify file paths
- Review tool permissions

## Next Steps

1. Read the [API Documentation](../docs/API.md)
2. Explore the [Tool Reference](../docs/TOOLS.md)
3. Check the [Security Guide](../docs/SECURITY.md)
4. Review the [Architecture](../SOVEREIGN_SUBSTRATE_COMPLETE.md)

## Support

- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Documentation: https://docs.rawrxd.dev
- Discord: https://discord.gg/rawrxd

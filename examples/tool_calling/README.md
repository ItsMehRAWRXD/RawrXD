# Tool Calling Example

Demonstrates how to implement and register custom tools that can be called by RawrXD's agentic framework.

## Features

- **Calculator Tool**: Mathematical operations (add, subtract, multiply, divide)
- **Weather Tool**: Simulated weather lookup by location
- **File System Tool**: File operations (read, write, list, delete)
- **Schema Validation**: Automatic parameter validation
- **Error Handling**: Proper error propagation

## Building

```bash
cd examples/tool_calling
mkdir build && cd build
cmake ..
cmake --build .
```

## Running

```bash
./tool_calling_example
```

## Output

```
RawrXD Tool Calling Example
===========================

✓ Runtime initialized

Registering tools...
  ✓ calculator
  ✓ weather
  ✓ filesystem

Registered Tools:
-----------------
  calculator: Perform mathematical calculations
  weather: Get current weather for a location
  filesystem: Perform file system operations

Tool Call Examples:
------------------

1. Calculator (add 5 + 3):
   Result: 8

2. Weather (San Francisco):
   Weather in San Francisco: 22°C, Partly Cloudy, Wind 15 km/h

3. File System (list /tmp):
   Directory listing for /tmp:
   - file1.txt
   - file2.txt
   - subdir/

4. Error Handling (divide by zero):
   Error (expected): Division by zero

✓ Tool calling example complete
```

## Creating Custom Tools

```cpp
class MyTool : public ITool {
public:
    std::string GetName() const override { return "my_tool"; }
    
    std::string GetDescription() const override {
        return "Description of what my tool does";
    }
    
    ToolSchema GetSchema() const override {
        ToolSchema schema;
        schema.name = "my_tool";
        schema.parameters = {
            {"param1", "string", true, "Required string parameter"},
            {"param2", "number", false, "Optional number parameter"}
        };
        return schema;
    }
    
    Result<std::string> Execute(const ToolArgs& args) override {
        auto param1 = args.GetString("param1");
        if (!param1.IsOk()) {
            return Err<std::string>(ErrorCode::InvalidArgument, "param1 required");
        }
        
        // Tool logic here
        return Ok("Result: " + param1.Value());
    }
};

// Register the tool
auto registry = runtime->GetToolRegistry();
registry->Register(std::make_unique<MyTool>());
```

## Tool Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Tool identifier |
| `description` | string | Yes | Human-readable description |
| `parameters` | array | Yes | List of parameters |
| `return_type` | string | No | Return type (default: string) |

## Parameter Types

- `string` - Text values
- `number` - Numeric values (int or float)
- `boolean` - true/false
- `array` - List of values
- `object` - Nested key-value pairs

## See Also

- [Agentic Framework](../../docs/Architecture.md#agentic-framework)
- [Tool Registry API](../../include/rawrxd/agentic/ToolRegistry.hpp)

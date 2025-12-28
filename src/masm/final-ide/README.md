# Rawr1024 Dual Engine Custom Assembly

A pure assembly implementation of a dual-engine processing system with custom SDK-free components.

## Features

- **Pure Assembly**: No Windows SDK dependencies
- **Dual Engine**: Two independent processing engines
- **Custom Memory Management**: Custom malloc/free implementation
- **Crypto Functions**: AES encryption and SHA-256 hashing
- **Network Support**: Custom socket implementation
- **Direct System Calls**: No API wrapper dependencies

## Build Requirements

### Windows
- Microsoft Macro Assembler (MASM) - ml64.exe
- Microsoft Linker - link.exe
- Available through:
  - Visual Studio Build Tools
  - Windows SDK
  - Visual Studio Community

## Building

### Quick Build (Windows)
```batch
build.bat
```

### Using Make
```batch
make
```

### Manual Build
```batch
ml64 /c /Fo rawr1024_dual_engine_custom.obj rawr1024_dual_engine_custom.asm
link /SUBSYSTEM:CONSOLE /ENTRY:main rawr1024_dual_engine_custom.obj /OUT:rawr1024_engine.exe
```

## Running

### Execute the built program
```batch
rawr1024_engine.exe
```

### Run tests
```batch
test.bat
```

## Architecture

### Core Components
- **Engine Management**: Initialize, start, stop, and monitor dual engines
- **Memory Allocator**: Custom heap management with 16MB default size
- **Crypto Module**: AES encryption and SHA-256 hashing implementations
- **Network Stack**: Custom socket creation and management
- **System Interface**: Direct system calls without API wrappers

### Engine States
Each engine maintains:
- ID and status
- Progress counter
- Error codes
- Memory allocation
- Timing information

### Memory Layout
- Heap Size: 16MB (configurable)
- Stack Size: 1MB per engine
- Page Size: 4KB alignment

## API Functions

### Core Engine Functions
- `rawr1024_init()` - Initialize the dual engine system
- `rawr1024_start_engine(id)` - Start specific engine
- `rawr1024_process(id, data, size)` - Process data with engine
- `rawr1024_stop_engine(id)` - Stop specific engine
- `rawr1024_get_status(id, buffer)` - Get engine status
- `rawr1024_cleanup()` - Cleanup and shutdown

### Utility Functions
- `custom_malloc(size)` - Allocate memory
- `custom_free(ptr)` - Free memory
- `custom_aes_encrypt(data, key, output)` - AES encryption
- `custom_sha256(data, length, output)` - SHA-256 hash
- `custom_socket_create(type)` - Create network socket

## Configuration

### Constants (modifiable in source)
```assembly
RAWR1024_ENGINE_COUNT EQU 2        ; Number of engines
HEAP_SIZE             EQU 16777216 ; 16MB heap
STACK_SIZE            EQU 1048576  ; 1MB stack
PAGE_SIZE             EQU 4096     ; 4KB pages
```

## Troubleshooting

### Build Issues
1. **MASM not found**: Install Visual Studio Build Tools or Windows SDK
2. **Linker errors**: Ensure link.exe is in PATH
3. **Permission denied**: Run as administrator if needed

### Runtime Issues
1. **Memory allocation fails**: Increase heap size or check available memory
2. **Engine start fails**: Verify initialization completed successfully
3. **System call errors**: Check platform compatibility

## Performance Notes

- Direct system calls provide minimal overhead
- Custom memory allocator optimized for frequent allocations
- Dual engines can process data independently
- Assembly implementation maximizes performance

## Security Considerations

- Custom crypto implementations for educational purposes
- Production use requires thorough security review
- Direct memory access requires careful bounds checking
- System calls bypass normal security layers

## License

Custom implementation for educational and research purposes.
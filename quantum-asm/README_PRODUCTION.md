# Production Quantum Assembly & Tools Collection

A collection of high-performance, single-file Windows tools and advanced assembly code, all buildable with MinGW on Linux.

## 🚀 Single-File Tools

### 1. **Process Injector** (`process_injector.c`)
Advanced process manipulation tool with DLL and shellcode injection capabilities.

**Features:**
- Process enumeration by name
- Classic DLL injection
- Direct shellcode injection
- Multi-architecture support (x86/x64)

**Usage:**
```bash
# DLL Injection
process_injector32.exe notepad.exe C:\payload.dll

# Shellcode Injection
process_injector64.exe explorer.exe -shellcode
```

### 2. **AES-256 File Encryptor** (`file_encryptor.c`)
Military-grade file encryption using Windows CryptoAPI.

**Features:**
- AES-256-CBC encryption
- Secure key derivation
- Large file support (chunked processing)
- Secure file wiping (3-pass random overwrite)

**Usage:**
```bash
# Encrypt file
file_encryptor64.exe encrypt secret.doc secret.enc

# Decrypt file
file_encryptor64.exe decrypt secret.enc secret.doc

# Secure wipe
file_encryptor64.exe wipe sensitive.txt
```

### 3. **Network Scanner** (`network_scanner.c`)
Multi-threaded network reconnaissance tool.

**Features:**
- TCP/UDP port scanning
- Service detection & banner grabbing
- Network interface enumeration
- ARP cache inspection
- Configurable thread pool (up to 256 threads)

**Usage:**
```bash
# Port scan
network_scanner64.exe 192.168.1.1 1 65535 -t 200

# Network enumeration
network_scanner64.exe localhost -n

# ARP scan
network_scanner64.exe 192.168.1.0/24 -a
```

## 🔧 Advanced Assembly Code

### **Quantum Production Assembly** (`quantum_production.asm`)
System-level assembly routines for Windows x86/x64.

**Functions:**
- `allocate_exec_memory()` - Direct syscall memory allocation
- `generate_poly_decoder()` - Polymorphic code generation
- `is_debugger_present()` - Multi-technique anti-debugging
- `chacha20_quarter_round()` - ChaCha20 encryption primitive
- `inject_remote_process()` - Process injection via syscalls
- `install_hook()` - Inline function hooking

## 📦 Building Everything

### Prerequisites
```bash
sudo apt-get install -y mingw-w64 nasm
```

### Build All Tools
```bash
# Build all single-file tools
make -f Makefile.tools all

# Build only 64-bit versions
make -f Makefile.tools 64bit

# Build assembly code
nasm -f win32 quantum_production.asm -o quantum32.obj
nasm -f win64 -DWIN64 quantum_production.asm -o quantum64.obj
```

### Optimization Options
```bash
# Strip symbols for smaller size
make -f Makefile.tools strip

# Pack with UPX (if installed)
make -f Makefile.tools pack

# Show executable sizes
make -f Makefile.tools sizes
```

## 🎯 Production Features

- **No dependencies** - All tools are statically linked
- **Maximum optimization** - Compiled with `-O3` and size optimization
- **Cross-architecture** - Both 32-bit and 64-bit versions
- **Windows 7+ compatible** - Uses Windows API available since Windows 7
- **Anti-analysis** - Assembly code includes anti-debugging techniques
- **Direct syscalls** - Bypass user-mode hooks in assembly

## ⚡ Performance Tips

1. **Thread Count**: For network scanner, use threads = CPU cores × 2
2. **Chunk Size**: File encryptor uses 1MB chunks for optimal I/O
3. **Assembly Integration**: Link assembly objects with C code for maximum performance

## 🔒 Security Notes

These tools are powerful and should be used responsibly:
- Process injection requires appropriate privileges
- Network scanning may trigger security software
- Always comply with local laws and regulations
- Test only on systems you own or have permission to test

## 💻 Example Integration

Link assembly with C code:
```c
// main.c
extern int is_debugger_present(void);
extern void* allocate_exec_memory(size_t size);

int main() {
    if (is_debugger_present()) {
        return 1;
    }
    
    void* mem = allocate_exec_memory(4096);
    // Use allocated executable memory
    
    return 0;
}
```

Compile:
```bash
# 32-bit
nasm -f win32 quantum_production.asm -o quantum32.obj
i686-w64-mingw32-gcc main.c quantum32.obj -o program32.exe

# 64-bit
nasm -f win64 -DWIN64 quantum_production.asm -o quantum64.obj
x86_64-w64-mingw32-gcc main.c quantum64.obj -o program64.exe
```

## 📊 Tool Comparison

| Tool | 32-bit Size | 64-bit Size | Threads | Performance |
|------|-------------|-------------|---------|-------------|
| Process Injector | ~44KB | ~41KB | Single | Instant |
| File Encryptor | ~82KB | ~75KB | Single | ~100MB/s |
| Network Scanner | ~48KB | ~45KB | 256 max | ~10k ports/sec |

## 🚀 Advanced Usage

### Combining Tools
```bash
# Encrypt and inject
file_encryptor64.exe encrypt payload.dll payload.enc
process_injector64.exe target.exe payload.enc

# Scan and report
network_scanner64.exe 10.0.0.0/24 -a > network_map.txt
file_encryptor64.exe encrypt network_map.txt report.enc
```

### Custom Shellcode
```c
// Generate polymorphic decoder
unsigned char decoder[64];
generate_poly_decoder(decoder, 0xDEADBEEF);

// Inject with custom shellcode
unsigned char payload[] = { /* your shellcode */ };
inject_remote_process(pid, payload, sizeof(payload));
```

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.
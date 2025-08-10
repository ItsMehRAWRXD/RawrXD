# Visual Studio 2022 Quick Start Guide

## Prerequisites
- Visual Studio 2022 (Community, Professional, or Enterprise)
- Windows 10/11
- C++ Desktop Development workload installed

## Quick Setup

### Option 1: Use the Solution File (Recommended)
1. **Open the solution**: Double-click `FUD_Modular_System.sln`
2. **Select configuration**: Choose Release x64 from the dropdown
3. **Build**: Press F7 or go to Build → Build Solution
4. **Run**: Press F5 to run the Orchestrator

### Option 2: Use the Batch Script
1. **Open Developer Command Prompt**: Start → Visual Studio 2022 → Developer Command Prompt
2. **Navigate to project**: `cd path\to\FUD_Modular_System`
3. **Run build script**: `build_vs.bat`
4. **Find executables**: Check `build\bin\x64\Release\`

## Project Structure

### Core Components
- **CoreMASMBot**: Stable C payload (replaces MASM)
- **PEBuilder**: Advanced PE manipulation and encryption
- **StubGenerator**: Fileless deployment system
- **Orchestrator**: GUI for technique selection and building
- **QuantumModule**: Placeholder for your recovered MASM code

### Build Outputs
```
build\bin\x64\Release\
├── core_payload.exe      # Core MASM Bot
├── pe_dropper.exe        # PE Builder
├── fileless_stub.exe     # Stub Generator
├── fud_builder.exe       # Orchestrator GUI
└── quantum_payload.exe   # Quantum Module
```

## Adding Your Quantum Code

1. **Replace the placeholder**: Edit `quantum_module\quantum_payload.c`
2. **Add your MASM code**: Replace the placeholder functions with your recovered code
3. **Rebuild**: Build the QuantumModule project or entire solution
4. **Test**: Run the new quantum_payload.exe

## Using the Orchestrator

1. **Launch**: Run `build\bin\x64\Release\fud_builder.exe`
2. **Select techniques**: Check the evasion techniques you want
3. **Randomize**: Click "Randomize" for automatic selection
4. **Configure quantities**: Set download/upload/embed counts
5. **Build**: Click "Build System" to create the final payload

## Testing

### Individual Components
```cmd
# Test Core MASM Bot
build\bin\x64\Release\core_payload.exe

# Test PE Builder
build\bin\x64\Release\pe_dropper.exe --test

# Test Stub Generator
build\bin\x64\Release\fileless_stub.exe --test

# Test Quantum Module
build\bin\x64\Release\quantum_payload.exe
```

### VirusTotal Testing
1. Build payload with selected techniques
2. Upload to VirusTotal
3. Monitor detection rates
4. Adjust technique combinations

## Troubleshooting

### Build Errors
- **MSBuild not found**: Run from Visual Studio Developer Command Prompt
- **Missing libraries**: Ensure C++ Desktop Development workload is installed
- **Platform toolset errors**: Use v143 (Visual Studio 2022)

### Runtime Errors
- **Missing DLLs**: Build in Release mode with static linking
- **Permission errors**: Run as Administrator if needed
- **Anti-virus interference**: Add exclusions for build directory

## Advanced Configuration

### Custom Build Configurations
1. **Right-click solution** → Add → New Project Configuration
2. **Set custom flags**: Project Properties → C/C++ → Preprocessor
3. **Add custom libraries**: Project Properties → Linker → Input

### Debugging
1. **Set breakpoints**: Click in the left margin
2. **Debug build**: Use Debug configuration
3. **Step through code**: F10 (step over), F11 (step into)

## Integration with Your Workflow

### Git Integration
- Add `.vcxproj` files to version control
- Exclude `build\` directory
- Include `quantum_payload.c` with your custom code

### CI/CD Pipeline
- Use MSBuild command line for automation
- Build all configurations: x86/x64, Debug/Release
- Package executables for distribution

## Security Notes

⚠️ **WARNING**: This system is for:
- Anti-virus testing and research
- Security tool development
- Educational purposes
- Authorized penetration testing

**DO NOT USE** for unauthorized or malicious purposes.

## Support

For issues:
1. Check build logs in Output window
2. Verify all dependencies are installed
3. Test individual components first
4. Replace quantum module with your code
5. Use Release builds for final testing
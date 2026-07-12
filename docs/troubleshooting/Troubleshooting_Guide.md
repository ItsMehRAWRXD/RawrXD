# Sovereign IDE — Troubleshooting Guide
## Common Issues and Solutions

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## Table of Contents

1. [Installation Issues](#1-installation-issues)
2. [Startup Problems](#2-startup-problems)
3. [Performance Issues](#3-performance-issues)
4. [Extension Issues](#4-extension-issues)
5. [Build Issues](#5-build-issues)
6. [Debug Issues](#6-debug-issues)
7. [AI/ML Issues](#7-aiml-issues)
8. [SDK Integration Issues](#8-sdk-integration-issues)

---

## 1. Installation Issues

### 1.1 Installation Fails

**Symptom:** Installer fails with error code

**Solutions:**

1. **Check System Requirements**
   ```
   - OS: Windows 10/11, Linux, macOS 10.15+
   - RAM: 8GB minimum, 16GB recommended
   - Disk: 2GB free space
   - GPU: Optional, for AI features
   ```

2. **Run as Administrator** (Windows)
   ```powershell
   # Right-click installer → Run as Administrator
   ```

3. **Clear Previous Installation**
   ```bash
   # Windows
   %LOCALAPPDATA%\SovereignIDE\
   
   # Linux
   ~/.config/SovereignIDE/
   
   # macOS
   ~/Library/Application Support/SovereignIDE/
   ```

4. **Check Antivirus**
   - Add Sovereign IDE to exclusions
   - Temporarily disable antivirus
   - Retry installation

### 1.2 Portable Version Issues

**Symptom:** Portable version won't start

**Solutions:**

1. **Extract Completely**
   ```bash
   # Ensure all files extracted
   # Don't run from zip file
   ```

2. **Check Permissions**
   ```bash
   # Linux/macOS
   chmod +x sovereign
   ```

3. **Data Directory**
   ```bash
   # Create data directory
   mkdir -p data
   ```

---

## 2. Startup Problems

### 2.1 IDE Won't Start

**Symptom:** Double-click does nothing or shows error

**Solutions:**

1. **Check Logs**
   ```
   Windows: %APPDATA%\SovereignIDE\logs\main.log
   Linux: ~/.config/SovereignIDE/logs/main.log
   macOS: ~/Library/Logs/SovereignIDE/main.log
   ```

2. **Reset Settings**
   ```bash
   # Backup first
   mv ~/.config/SovereignIDE/settings.json ~/.config/SovereignIDE/settings.json.backup
   
   # IDE will recreate with defaults
   ```

3. **Disable Extensions**
   ```bash
   # Start with extensions disabled
   sovereign --disable-extensions
   ```

4. **Clear Cache**
   ```bash
   # Windows
   rmdir /s /q %LOCALAPPDATA%\SovereignIDE\Cache
   
   # Linux/macOS
   rm -rf ~/.config/SovereignIDE/Cache
   ```

### 2.2 Black Screen / White Screen

**Symptom:** IDE window opens but is blank

**Solutions:**

1. **Disable GPU Acceleration**
   ```bash
   sovereign --disable-gpu
   ```

2. **Software Rendering**
   ```bash
   sovereign --disable-gpu-compositing
   ```

3. **Update Graphics Drivers**
   ```bash
   # Windows: Device Manager → Display adapters
   # Linux: sudo apt update && sudo apt upgrade
   # macOS: System Preferences → Software Update
   ```

---

## 3. Performance Issues

### 3.1 High CPU Usage

**Symptom:** IDE uses excessive CPU

**Solutions:**

1. **Identify Culprit**
   ```bash
   # Open Process Explorer (Windows)
   # Or Activity Monitor (macOS)
   # Or top/htop (Linux)
   ```

2. **Disable Extensions**
   ```bash
   # Start with --disable-extensions
   # Re-enable one by one to find culprit
   ```

3. **Adjust Settings**
   ```json
   {
       "editor.minimap.enabled": false,
       "editor.renderWhitespace": "none",
       "editor.cursorBlinking": "solid",
       "files.watcherExclude": {
           "**/node_modules/**": true,
           "**/.git/objects/**": true
       }
   }
   ```

4. **Increase Memory**
   ```bash
   # Edit workbench.json
   "sovereign.maxMemory": 4096
   ```

### 3.2 Slow File Operations

**Symptom:** Opening/saving files is slow

**Solutions:**

1. **Exclude Large Folders**
   ```json
   {
       "files.exclude": {
           "**/build": true,
           "**/dist": true,
           "**/node_modules": true
       }
   }
   ```

2. **Disable Format On Save**
   ```json
   {
       "editor.formatOnSave": false
   }
   ```

3. **Check Disk Space**
   ```bash
   # Windows
   wmic logicaldisk get size,freespace,caption
   
   # Linux/macOS
   df -h
   ```

---

## 4. Extension Issues

### 4.1 Extension Won't Install

**Symptom:** Installation fails or hangs

**Solutions:**

1. **Check Compatibility**
   ```bash
   # Verify extension supports your IDE version
   # Check extension page for requirements
   ```

2. **Manual Installation**
   ```bash
   # Download .vsix file
   # Extensions → ... → Install from VSIX
   ```

3. **Clear Extension Cache**
   ```bash
   # Windows
   rmdir /s /q %USERPROFILE%\.sovereign\extensions
   
   # Linux/macOS
   rm -rf ~/.sovereign/extensions
   ```

### 4.2 Extension Crashes

**Symptom:** Extension causes IDE to crash

**Solutions:**

1. **Safe Mode**
   ```bash
   sovereign --disable-extensions
   ```

2. **Check Extension Logs**
   ```
   Help → Toggle Developer Tools → Console
   ```

3. **Report Issue**
   ```bash
   # Get extension ID
   # Report to extension developer
   # Include IDE version and logs
   ```

---

## 5. Build Issues

### 5.1 Build Task Fails

**Symptom:** Build task doesn't complete

**Solutions:**

1. **Check Task Configuration**
   ```json
   // Verify tasks.json
   {
       "version": "2.0.0",
       "tasks": [
           {
               "label": "Build",
               "type": "shell",
               "command": "make",
               "group": "build"
           }
       ]
   }
   ```

2. **Verify Build Tools**
   ```bash
   # Check compiler installed
   gcc --version
   cmake --version
   make --version
   ```

3. **Check Working Directory**
   ```json
   {
       "options": {
           "cwd": "${workspaceFolder}"
       }
   }
   ```

### 5.2 Intellisense Not Working

**Symptom:** Code completion doesn't appear

**Solutions:**

1. **Check Configuration**
   ```json
   {
       "C_Cpp.intelliSenseEngine": "Default",
       "C_Cpp.autocomplete": "Default"
   }
   ```

2. **Generate Compile Commands**
   ```bash
   cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
   ```

3. **Restart Language Server**
   ```bash
   # Command Palette → C/C++: Restart IntelliSense
   ```

---

## 6. Debug Issues

### 6.1 Debugger Won't Attach

**Symptom:** Debug session fails to start

**Solutions:**

1. **Check launch.json**
   ```json
   {
       "version": "0.2.0",
       "configurations": [
           {
               "name": "Debug",
               "type": "cppdbg",
               "request": "launch",
               "program": "${workspaceFolder}/build/app",
               "cwd": "${workspaceFolder}"
           }
       ]
   }
   ```

2. **Verify Program Path**
   ```bash
   # Check file exists
   ls -la build/app
   ```

3. **Check Debug Symbols**
   ```bash
   # Compile with -g flag
   gcc -g -o app main.c
   ```

### 6.2 Breakpoints Not Working

**Symptom:** Breakpoints ignored during debug

**Solutions:**

1. **Rebuild with Debug Info**
   ```bash
   # Ensure -g flag used
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   ```

2. **Check Source Mapping**
   ```bash
   # Verify source files match
   # Check path mappings in launch.json
   ```

3. **Disable Optimization**
   ```bash
   # Use -O0 for debugging
   gcc -O0 -g -o app main.c
   ```

---

## 7. AI/ML Issues

### 7.1 Model Won't Load

**Symptom:** AI model fails to load

**Solutions:**

1. **Check Model Path**
   ```json
   {
       "ai.model.path": "/absolute/path/to/model.gguf"
   }
   ```

2. **Verify Model Format**
   ```bash
   # Supported formats: GGUF, GGML, SafeTensors, ONNX
   # Check file extension
   ```

3. **Check GPU Memory**
   ```bash
   # Reduce gpuLayers if OOM
   {
       "ai.model.gpuLayers": 20
   }
   ```

### 7.2 Slow AI Completion

**Symptom:** AI suggestions take too long

**Solutions:**

1. **Adjust Timeout**
   ```json
   {
       "ai.completion.timeout": 5000
   }
   ```

2. **Reduce Context**
   ```json
   {
       "ai.model.contextLength": 2048
   }
   ```

3. **Use CPU Mode**
   ```json
   {
       "ai.model.device": "cpu"
   }
   ```

---

## 8. SDK Integration Issues

### 8.1 SDK Not Found

**Symptom:** SDK functions unavailable

**Solutions:**

1. **Verify SDK Installation**
   ```bash
   # Check SDK path
   ls $SOVEREIGN_SDK_PATH
   ```

2. **Set Environment Variable**
   ```bash
   # Windows
   set SOVEREIGN_SDK_PATH=C:\Sovereign\SDK
   
   # Linux/macOS
   export SOVEREIGN_SDK_PATH=/opt/sovereign/sdk
   ```

3. **Reinstall SDK**
   ```bash
   # Download latest SDK
   # Run installer
   ```

### 8.2 SDK Version Mismatch

**Symptom:** SDK functions fail with version error

**Solutions:**

1. **Check Versions**
   ```bash
   # IDE version
   sovereign --version
   
   # SDK version
   cat $SOVEREIGN_SDK_PATH/version.txt
   ```

2. **Update SDK**
   ```bash
   # Download matching SDK version
   # Reinstall SDK
   ```

---

## Quick Fixes

### Reset Everything

```bash
# Backup settings
cp -r ~/.config/SovereignIDE ~/.config/SovereignIDE.backup

# Reset to defaults
rm -rf ~/.config/SovereignIDE

# Restart IDE
```

### Get Help

1. **Check Documentation**
   - [Documentation](../README.md)
   - [API Reference](../api/API_Reference_Index.md)

2. **Community Support**
   - [GitHub Issues](https://github.com/ItsMehRAWRXD/RawrXD/issues)
   - [Discord](https://discord.gg/sovereign)
   - [Stack Overflow](https://stackoverflow.com/questions/tagged/sovereign-ide)

3. **Report Bug**
   ```
   Help → Report Issue
   # Include:
   # - IDE version
   # - OS version
   # - Steps to reproduce
   # - Error messages
   # - Log files
   ```

---

## Summary

This guide covers:

- ✅ Installation issues
- ✅ Startup problems
- ✅ Performance optimization
- ✅ Extension troubleshooting
- ✅ Build system issues
- ✅ Debug configuration
- ✅ AI/ML problems
- ✅ SDK integration

**Status:** Complete

---

*End of Troubleshooting Guide*

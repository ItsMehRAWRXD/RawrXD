# RawrXD GUI - Quick Start Guide

## 🚀 What You Get

A fully functional **local AI IDE** with:
- ✅ Chat interface with streaming responses
- ✅ File editor with dark theme
- ✅ GGUF model loading (100% local)
- ✅ No external dependencies
- ✅ Single 268KB executable

## 📥 Installation

No installation needed! Just download and run.

```batch
# Download location
cd d:\rawrxd-ci-bootstrap\bin

# Run the GUI
RawrXD_GUI_Minimal.exe
```

## 🎯 Usage

### 1. Load a Model
1. Click **"Browse..."** in the Model Panel (left)
2. Select a `.gguf` file
3. Click **"Load Selected Model"**
4. Status shows: "Loaded: <model_name>"

### 2. Chat with AI
1. Type your message in the input box (bottom right)
2. Click **"Send"** or press Enter
3. Watch the streaming response appear

### 3. Edit Files
1. Use **File → Open** to load a file
2. Edit in the center panel
3. Use **File → Save** to save changes

## 🖼️ Interface Layout

```
┌─────────────────────────────────────────────────────────────┐
│  File  Edit  Model  Help                                    │
├──────────┬────────────────────────┬───────────────────────────┤
│          │                        │                           │
│  MODEL   │       EDITOR           │         CHAT              │
│  PANEL   │       PANEL            │         PANEL             │
│          │                        │                           │
│  [List]  │  ┌────────────────┐  │  ┌─────────────────────┐  │
│  [Browse]│  │                │  │  │ Chat History        │  │
│  [Load]  │  │   Code Editor  │  │  │                     │  │
│          │  │   (Dark Theme) │  │  │ [You]: Hello        │  │
│  Status: │  │                │  │  │ [AI]: Hi there!     │  │
│  Ready   │  │                │  │  │                     │  │
│          │  └────────────────┘  │  ├─────────────────────┤  │
│          │                        │  │ Input box           │  │
│          │                        │  │ [Send]              │  │
│          │                        │  └─────────────────────┘  │
└──────────┴────────────────────────┴───────────────────────────┘
```

## 🔧 Building from Source

### Prerequisites
- Windows 10/11
- Visual Studio 2022 (or Build Tools)
- Windows SDK 10.0.22621.0

### Build Steps

```batch
# Clone/navigate to project
cd d:\rawrxd-ci-bootstrap

# Run build script
build_minimal_gui.bat

# Output: bin\RawrXD_GUI_Minimal.exe
```

### Manual Build

```batch
# Setup VS environment
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

# Compile
cd src\win32app
cl.exe /EHsc /O2 /std:c++17 /DUNICODE /D_UNICODE /FeRawrXD_GUI_Minimal.exe RawrXD_GUI_Minimal.cpp /link user32.lib gdi32.lib comctl32.lib shell32.lib ole32.lib comdlg32.lib
```

## 🧪 Testing

### Run Inference Routing Test

```batch
.\build\bin\RawrXD-InferenceRoutingTest.exe
```

Expected output:
```
========================================
TEST SUMMARY
========================================
LocalEngineReady: PASS
NoLocalEngine: PASS
ModelPathButNoEngine: PASS
EngineReadyNoModel: PASS

Total: 4 passed, 0 failed
```

## 📋 Features

### Chat Panel
- ✅ Rich text display with dark theme
- ✅ Streaming token-by-token responses
- ✅ Message history with context
- ✅ User (blue) and AI (green) colors
- ✅ Status bar showing model state

### Editor Panel
- ✅ Full-featured text editor
- ✅ Dark theme (RGB 25,25,25)
- ✅ Consolas font for code
- ✅ File open/save with UTF-8
- ✅ Windows (CRLF) and Unix (LF) line endings

### Model Panel
- ✅ GGUF file browser
- ✅ Auto-scan common directories
- ✅ Load/unload models
- ✅ Browse for models
- ✅ Model status display

### Menu System
- ✅ **File**: New, Open, Save, Exit
- ✅ **Edit**: Cut, Copy, Paste
- ✅ **Model**: Load, Unload, Clear Chat
- ✅ **Help**: About dialog

## 🔒 Local-Only Operation

**No Cloud Services**:
- ✅ No OpenAI API calls
- ✅ No internet required for local models
- ✅ No data leaves your machine
- ✅ Complete privacy

**Fallback Option**:
- Ollama integration available (optional)
- Only used when no local model loaded
- Configurable in integrated version

## 🛠️ Technical Details

### Architecture
- **Language**: C++17
- **Framework**: Pure Win32 API
- **GUI Toolkit**: Native Windows controls
- **Size**: 268KB single executable
- **Dependencies**: Windows SDK only

### GGUF Support
- ✅ GGUF format v1, v2, v3
- ✅ All quantization types (Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q2_K, Q3_K, Q4_K, Q5_K, Q6_K)
- ✅ Metadata extraction
- ✅ Tensor loading

### Performance
- ✅ Streaming responses
- ✅ Async inference (non-blocking UI)
- ✅ Memory-mapped file I/O
- ✅ Multi-threaded token generation

## 📚 Documentation

- `SESSION_COMPLETE.md` - Session summary
- `AUDIT_COMPLETE.md` - Full technical audit
- `GUI_COMPLETE_SESSION_SUMMARY.md` - Implementation details

## 🐛 Troubleshooting

### GUI Won't Start
- Ensure Windows 10/11
- Install Visual C++ Redistributable (if needed)
- Check Windows SDK is present

### Model Won't Load
- Verify file is valid GGUF format
- Check file path has no special characters
- Ensure file is not corrupted

### Build Fails
- Run `build_minimal_gui.bat` from VS Developer Prompt
- Check Visual Studio 2022 is installed
- Verify Windows SDK 10.0.22621.0

## 📄 License

RawrXD v14.7.3 - Local AI IDE

## 🙏 Credits

Built in a single session with:
- Pure Win32 API
- RawrXD native GGUF loader
- RawrXD CPU inference engine
- No external dependencies

---

**Ready to use!** Just run `RawrXD_GUI_Minimal.exe` and start chatting with your local AI.

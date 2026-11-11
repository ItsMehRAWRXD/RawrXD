# Voice Assistant Integration - Phase 34

## Overview

The Voice Assistant integration brings Siri and Alexa-style voice assistants to RawrXD IDE. This system provides:

- **Multiple Assistant Styles**: Siri (conversational), Alexa (task-oriented), and Hybrid (adaptive)
- **Natural Language Processing**: Intent parsing, entity extraction, and context-aware responses
- **IDE Integration**: Full Win32 panel with real-time interaction
- **Session Management**: Conversation history and context preservation
- **Micro-Model Chain Integration**: Connects to enhanced processing pipeline

## Architecture

### Components

1. **VoiceAssistantManager** (`voice_assistant_manager.hpp/cpp`)
   - Central coordinator for all voice assistants
   - Session management and routing
   - Micro-model chain integration

2. **SiriStyleAssistant**
   - Conversational, personal responses
   - Personality quirks and natural language
   - Intent parsing: weather, timer, reminder, calculation, search, code generation

3. **AlexaStyleAssistant**
   - Task-oriented, smart home control
   - Device state management
   - Skill-based organization

4. **HybridAssistant**
   - Adaptive switching between Siri and Alexa styles
   - Context-aware mode selection
   - Best of both worlds

5. **Win32IDE_VoiceAssistantPanel** (`Win32IDE_VoiceAssistantPanel.cpp`)
   - Win32 UI panel with controls
   - Real-time voice input processing
   - History management

## Usage

### Opening the Voice Assistant Panel

1. **Menu**: View → Voice Assistant → Voice Assistant Panel (Ctrl+Shift+V)
2. **Command Palette**: Type "Voice Assistant"

### Selecting Assistant Mode

From the View menu:
- **Siri-Style (Conversational)**: Personal, witty responses
- **Alexa-Style (Task-Oriented)**: Smart home, device control
- **Hybrid (Adaptive)**: Automatically selects best style

### Voice Commands

#### Siri-Style Commands
- "What's the weather like?"
- "Set a timer for 5 minutes"
- "Remind me to call mom"
- "Calculate 15% of 200"
- "Search for Python tutorials"
- "Create a function that..."
- "Analyze this code"

#### Alexa-Style Commands
- "Turn on the lights"
- "Set thermostat to 72"
- "Play music"
- "What time is it?"
- "Set a timer"

#### Hybrid Commands
- Any command - the system automatically selects the best assistant style

## Integration Points

### Resource IDs (resource.h)

```cpp
// Panel Controls
#define IDC_VOICE_ASSISTANT_PANEL   12000
#define IDC_ASSISTANT_COMBO         12001
#define IDC_VOICE_INPUT_EDIT        12002
#define IDC_RESPONSE_EDIT           12003
#define IDC_SEND_BUTTON             12004
#define IDC_CLEAR_BUTTON            12005
#define IDC_MIC_BUTTON              12006
#define IDC_HISTORY_LIST            12007
#define IDC_STATUS_TEXT             12008

// Menu Commands
#define IDM_VOICE_ASSISTANT_PANEL   12100
#define IDM_VOICE_SIRI_MODE         12101
#define IDM_VOICE_ALEXA_MODE        12102
#define IDM_VOICE_HYBRID_MODE       12103
#define IDM_VOICE_SETTINGS          12104
#define IDM_VOICE_HISTORY           12105
#define IDM_VOICE_CLEAR_HISTORY     12106
```

### Menu Integration (Win32IDE.cpp)

The Voice Assistant menu is added to the View menu:

```cpp
HMENU hVoiceAssistantMenu = CreatePopupMenu();
AppendMenuW(hVoiceAssistantMenu, MF_STRING, IDM_VOICE_ASSISTANT_PANEL, L"&Voice Assistant Panel\tCtrl+Shift+V");
AppendMenuW(hVoiceAssistantMenu, MF_SEPARATOR, 0, nullptr);
AppendMenuW(hVoiceAssistantMenu, MF_STRING, IDM_VOICE_SIRI_MODE, L"&Siri-Style (Conversational)");
AppendMenuW(hVoiceAssistantMenu, MF_STRING, IDM_VOICE_ALEXA_MODE, L"&Alexa-Style (Task-Oriented)");
AppendMenuW(hVoiceAssistantMenu, MF_STRING, IDM_VOICE_HYBRID_MODE, L"&Hybrid (Adaptive)");
AppendMenuW(hVoiceAssistantMenu, MF_SEPARATOR, 0, nullptr);
AppendMenuW(hVoiceAssistantMenu, MF_STRING, IDM_VOICE_SETTINGS, L"&Settings...");
AppendMenuW(hVoiceAssistantMenu, MF_STRING, IDM_VOICE_HISTORY, L"View &History");
AppendMenuW(hVoiceAssistantMenu, MF_STRING, IDM_VOICE_CLEAR_HISTORY, L"&Clear History");
AppendMenuW(hViewMenu, MF_POPUP, (UINT_PTR)hVoiceAssistantMenu, L"Voice &Assistant");
```

### Command Routing (Win32IDE_Commands.cpp)

Commands are routed through the unified command handler:

```cpp
else if (commandId >= 12000 && commandId < 12100)
{
    // Phase 34: Voice Assistant Panel commands
    handleVoiceAssistantCommand(commandId);
    return true;
}
```

### Header Declarations (Win32IDE.h)

```cpp
// Phase 34: Voice Assistant — Siri/Alexa-Style Integration
void initVoiceAssistantPanel();
void shutdownVoiceAssistantPanel();
HWND createVoiceAssistantPanel(HWND hwndParent);
void layoutVoiceAssistantPanel(int panelWidth, int panelHeight);
void handleVoiceAssistantCommand(int commandId);
void processVoiceInput(const std::string& input);
void displayVoiceResponse(const nlohmann::json& result);
void addToVoiceHistory(const std::string& input, const nlohmann::json& result);
void setVoiceAssistantMode(const std::string& mode);
void updateVoiceStatus(const std::string& status);
void showVoiceAssistantPanel();
void showVoiceAssistantSettings();
void showVoiceHistory();
void clearVoiceHistory();
LRESULT handleVoiceAssistantMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void handleSendButton();
void handleClearButton();
void handleMicButton();
void handleHistorySelection();
void handleVoiceAssistantTimer();
void connectVoiceToMicroModelChain();
void cleanupVoiceAssistant();
bool m_voiceAssistantInitialized = false;
```

## API Reference

### VoiceAssistantManager

```cpp
// Create manager
auto manager = std::make_unique<VoiceAssistantManager>();

// Process voice input
nlohmann::json result = manager->process_voice_input(
    "What's the weather?",
    "siri",           // or "alexa" or "hybrid"
    "session_id"       // optional
);

// Get assistant info
nlohmann::json info = manager->get_assistant_info();

// Session management
std::string session_id = manager->create_session();
manager->end_session(session_id);
nlohmann::json history = manager->get_session_history(session_id);

// Configuration
manager->set_wake_word("alexa", "computer");
manager->enable_voice_output(true);
manager->set_response_style("conversational");
```

### Response Format

```json
{
  "assistant": "Siri-Style",
  "response": "Let me check the weather for you...",
  "voice_output": "Let me check the weather for you...",
  "intent": "weather",
  "confidence": 0.85,
  "entities": {
    "location": "Seattle",
    "time": "today"
  },
  "suggested_actions": [
    "5-day forecast",
    "Weather alerts",
    "Radar map"
  ],
  "processing_time": 0.001,
  "session_id": "session_12345",
  "timestamp": 1234567890
}
```

## Testing

Run the test program:

```bash
cd d:\rawrxd\src\tests
g++ -std=c++17 -I../core voice_assistant_test.cpp -o voice_assistant_test.exe
./voice_assistant_test.exe
```

## Future Enhancements

1. **Voice Recognition**: Integrate Windows Speech API for actual voice input
2. **Text-to-Speech**: Add voice output for responses
3. **Smart Home Integration**: Connect to actual smart home devices
4. **Code Generation**: Enhanced code generation and analysis
5. **Multi-Language Support**: Support for multiple languages
6. **Custom Wake Words**: User-defined wake words
7. **Plugin System**: Third-party assistant extensions

## Troubleshooting

### Panel Not Showing
- Check that `IDM_VOICE_ASSISTANT_PANEL` is defined in resource.h
- Verify menu creation in Win32IDE.cpp
- Ensure command routing in Win32IDE_Commands.cpp

### Commands Not Working
- Check that `handleVoiceAssistantCommand` is implemented in Win32IDE_VoiceAssistantPanel.cpp
- Verify resource IDs match between resource.h and implementation
- Check that `initVoiceAssistantPanel()` is called during initialization

### Build Errors
- Ensure `voice_assistant_manager.hpp/cpp` are in the build
- Add `Win32IDE_VoiceAssistantPanel.cpp` to your build system
- Link against `nlohmann/json` library

## License

Part of RawrXD IDE - See main project license.
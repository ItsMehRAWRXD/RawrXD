# RawrXD Browser Integration Guide

This guide shows how to integrate the zero-dependency browser into the RawrXD CLI and GUI IDEs.

## Quick Integration

### 1. CLI Integration (cli_shell.cpp)

Add to the top of `d:\rawrxd\src\cli_shell.cpp`:

```cpp
#define RAWRXD_CLI_BUILD
#include "browser/BrowserIntegration.hpp"
```

Add to CLI initialization (in `main()` or init function):
```cpp
RAWRXD_BROWSER_CLI_INIT();
```

Add to CLI shutdown:
```cpp
RAWRXD_BROWSER_CLI_SHUTDOWN();
```

Add to command dispatcher (where you handle `!commands`):
```cpp
if (RAWRXD_BROWSER_CLI_HANDLE(command, args)) {
    return; // Command was handled by browser
}
```

### 2. GUI Integration (gui_main.cpp)

Add to the top of `d:\rawrxd\src\gui_main.cpp`:

```cpp
#define RAWRXD_GUI_BUILD
#include "browser/BrowserIntegration.hpp"
```

Add to GUI initialization (in `GUIMain::initialize`):
```cpp
RAWRXD_BROWSER_GUI_INIT();
```

Add to GUI shutdown (in `GUIMain::shutdown`):
```cpp
RAWRXD_BROWSER_GUI_SHUTDOWN();
```

Add to IDEEntry.cpp hotkey registration:
```cpp
HotkeySystem::Register("Ctrl+Shift+B", []() { RAWRXD_BROWSER_GUI_TOGGLE(); });
```

Add to IDEEntry.cpp panel registration:
```cpp
DockingLayout::Add(RawrXD::BrowserPanel::Id(), DockingLayout::Right);
```

## Build System Integration

### CMakeLists.txt

Add to your CMakeLists.txt:

```cmake
# Browser sources
set(BROWSER_SOURCES
    src/browser/RawrXD_Browser.cpp
    src/browser/RawrXD_BrowserWindow.cpp
    src/browser/BrowserPanel.cpp
    src/browser/BrowserCLI.cpp
)

# Add to CLI target
add_executable(RawrXD-CLI ${CLI_SOURCES} ${BROWSER_SOURCES})
target_link_libraries(RawrXD-CLI PRIVATE winhttp gdi32 user32)

# Add to GUI target
add_executable(RawrXD-GUI ${GUI_SOURCES} ${BROWSER_SOURCES})
target_link_libraries(RawrXD-GUI PRIVATE winhttp gdi32 user32)
```

### Makefile

Add to your Makefile:

```makefile
BROWSER_OBJS = \
    $(OBJ_DIR)/RawrXD_Browser.o \
    $(OBJ_DIR)/RawrXD_BrowserWindow.o \
    $(OBJ_DIR)/BrowserPanel.o \
    $(OBJ_DIR)/BrowserCLI.o

# Link flags
LDFLAGS += -lwinhttp -lgdi32 -luser32

# Add browser objects to targets
RawrXD-CLI: $(CLI_OBJS) $(BROWSER_OBJS)
RawrXD-GUI: $(GUI_OBJS) $(BROWSER_OBJS)
```

## Available Commands

### CLI Commands

| Command | Description |
|---------|-------------|
| `!browser <url>` | Navigate to URL |
| `!back` | Go back |
| `!forward` | Go forward |
| `!reload` | Reload page |
| `!stop` | Stop loading |
| `!docs` | Show documentation |
| `!github` | Open GitHub |
| `!search <query>` | Search web |
| `!fetch <url>` | HTTP GET |
| `!post <url> [data]` | HTTP POST |

### GUI Hotkeys

| Hotkey | Action |
|--------|--------|
| `Ctrl+Shift+B` | Toggle browser panel |
| `Ctrl+Shift+D` | Open documentation |
| `Ctrl+Shift+G` | Open GitHub |
| `F5` | Refresh page |
| `Escape` | Stop loading |

## Testing

### CLI Test
```bash
# Start CLI
RawrXD-CLI.exe

# In CLI shell:
!browser example.com
!docs
!search RawrXD IDE
!fetch https://api.github.com/users/github
```

### GUI Test
```bash
# Start GUI
RawrXD-GUI.exe

# Press Ctrl+Shift+B to open browser
# Type URL in address bar
# Navigate!
```

## Troubleshooting

### Build Errors

**Error: `winhttp.h` not found**
- Solution: Add `#include <windows.h>` before winhttp.h

**Error: Linker undefined references**
- Solution: Link against `winhttp.lib gdi32.lib user32.lib`

### Runtime Errors

**Browser doesn't open**
- Check that `BrowserPanel::Init()` was called
- Verify WinHTTP service is running

**Pages don't load**
- Check internet connection
- Verify URL format (add https:// if missing)
- Check Windows Firewall settings

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD IDE                                │
├────────────────────────┬──────────────────────────────────┤
│        CLI Mode          │           GUI Mode               │
├────────────────────────┼──────────────────────────────────┤
│  BrowserCLI.hpp/cpp    │    BrowserPanel.hpp/cpp            │
│  - Headless browser    │    - Windowed browser              │
│  - Text output         │    - Dockable panel                │
│  - Command interface   │    - GDI rendering                 │
├────────────────────────┴──────────────────────────────────┤
│              RawrXD_Browser.hpp/cpp                          │
│         (Shared core: Network, HTML, CSS, Layout)          │
├─────────────────────────────────────────────────────────────┤
│              Win32 APIs (WinHTTP, GDI)                     │
└─────────────────────────────────────────────────────────────┘
```

## License

Part of RawrXD project. See main LICENSE file.

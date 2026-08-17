# RawrXD Browser

A **zero-dependency built-in browser** for the RawrXD project. Written in pure C++ using only Win32 APIs - no Qt, no external libraries, no browser engines.

## Features

- ✅ **HTTP/HTTPS Support** - Via WinHTTP (built into Windows)
- ✅ **HTML Parsing** - Custom lightweight parser
- ✅ **Basic CSS** - Style support (in progress)
- ✅ **GDI Rendering** - Native Windows graphics
- ✅ **Navigation** - Back/forward, refresh, address bar
- ✅ **Links** - Clickable hyperlinks
- ✅ **Scrolling** - Mouse wheel support
- ✅ **Zero Dependencies** - Only uses Windows built-in APIs

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD Browser                            │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │   Network    │  │    HTML      │  │    CSS       │        │
│  │   Engine     │──│   Parser     │──│   Parser     │        │
│  │  (WinHTTP)   │  │  (Custom)    │  │  (Custom)    │        │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
│         │                   │                   │             │
│         ▼                   ▼                   ▼             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    DOM Tree                           │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                  │
│                           ▼                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │    Layout    │──│   Renderer   │──│   Window     │      │
│  │    Engine    │  │    (GDI)     │  │   (Win32)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Building

### Prerequisites
- Windows 10/11
- Visual Studio 2019 or later (with C++ desktop development)

### Build
```batch
build_browser.bat
```

Or manually:
```batch
cl.exe /nologo /W3 /O2 /MD /EHsc /std:c++17 /DUNICODE /D_UNICODE /c RawrXD_Browser.cpp
cl.exe /nologo /W3 /O2 /MD /EHsc /std:c++17 /DUNICODE /D_UNICODE /c RawrXD_BrowserWindow.cpp
cl.exe /nologo /W3 /O2 /MD /EHsc /std:c++17 /DUNICODE /D_UNICODE /c RawrXD_Browser_Main.cpp

link.exe /SUBSYSTEM:WINDOWS /MACHINE:X64 /OUT:RawrXD_Browser.exe ^
    RawrXD_Browser.obj RawrXD_BrowserWindow.obj RawrXD_Browser_Main.obj ^
    winhttp.lib gdi32.lib user32.lib shell32.lib ole32.lib
```

## Usage

```batch
# Start with default page (example.com)
RawrXD_Browser.exe

# Start with specific URL
RawrXD_Browser.exe example.com
RawrXD_Browser.exe https://raw.githubusercontent.com
```

## Controls

| Key/Action | Function |
|------------|----------|
| Mouse Wheel | Scroll page |
| Click | Follow links |
| F5 | Refresh page |
| Escape | Stop loading |
| Back Button | Navigate back |
| Forward Button | Navigate forward |
| Address Bar | Enter URL |

## Supported HTML Elements

- Document structure: `html`, `head`, `body`, `title`
- Text: `h1`-`h6`, `p`, `span`, `div`
- Lists: `ul`, `ol`, `li`
- Links: `a` (with `href`)
- Sections: `section`, `article`, `header`, `footer`
- Text content (inline)

## File Structure

```
browser/
├── RawrXD_Browser.h          # Main header with all classes
├── RawrXD_Browser.cpp        # Core implementation
├── RawrXD_BrowserWindow.cpp  # Window and UI implementation
├── RawrXD_Browser_Main.cpp   # Entry point
├── build_browser.bat         # Build script
└── README.md                 # This file
```

## Integration with RawrXD

The browser can be integrated into the RawrXD IDE for:
- **Documentation viewing** - Render help/docs inline
- **Web-based tools** - Access web-based development tools
- **Preview server** - View local development servers
- **API testing** - Built-in HTTP client for testing

## Future Enhancements

- [ ] JavaScript execution (minimal)
- [ ] Image rendering
- [ ] Form support (input, button, etc.)
- [ ] CSS box model improvements
- [ ] Tab support
- [ ] Bookmarks
- [ ] Download manager
- [ ] Cookie support
- [ ] HTTPS certificate validation options

## Technical Notes

### Why WinHTTP?
- Built into Windows (no extra dependencies)
- Supports HTTP/HTTPS
- Async capable
- Proxy support

### Why GDI?
- Built into Windows
- Fast for simple rendering
- No external graphics libraries
- Good enough for basic web content

### HTML Parsing Strategy
- Custom recursive descent parser
- Handles malformed HTML gracefully
- Minimal memory overhead
- Fast enough for small-medium pages

## License

Part of the RawrXD project. See main project license.

## Credits

Built for the RawrXD project - zero dependency philosophy.

# IDE Integration
## Sovereign IDE Integration Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Sovereign IDE integrates with popular IDEs and editors for seamless workflow.

### Supported IDEs

| IDE | Extension | Status |
|-----|-----------|--------|
| VS Code | sovereign-vscode | ✅ Available |
| Vim/Neovim | sovereign-vim | ✅ Available |
| Emacs | sovereign-emacs | ✅ Available |
| Sublime | sovereign-sublime | 🔄 Planned |

---

## VS Code Integration

### Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search "Sovereign"
4. Click Install

### Configuration

```json
{
    "sovereign.enabled": true,
    "sovereign.server.host": "localhost",
    "sovereign.server.port": 8080,
    "sovereign.analysis.onSave": true,
    "sovereign.analysis.onOpen": true
}
```

### Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| `Sovereign: Analyze File` | Ctrl+Shift+A | Analyze current file |
| `Sovereign: Show Results` | Ctrl+Shift+R | Show analysis results |
| `Sovereign: Go to Definition` | F12 | Navigate to definition |

---

## Vim Integration

### Installation

```vim
" Using vim-plug
Plug 'ItsMehRAWRXD/sovereign-vim'
```

### Configuration

```vim
" ~/.vimrc
let g:sovereign_enabled = 1
let g:sovereign_server = 'localhost:8080'

" Key mappings
nnoremap <leader>a :SovereignAnalyze<CR>
nnoremap <leader>r :SovereignResults<CR>
```

---

## Summary

IDE Integration provides:

- ✅ **VS Code extension**
- ✅ **Vim/Neovim plugin**
- ✅ **Emacs package**
- ✅ **Real-time analysis**
- ✅ **Navigation support**

**Status:** ✅ Complete

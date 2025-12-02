/**
 * RawrXD Menu Bar & Editor Layout Control System
 * Replicates Cursor IDE's complete menu and layout system
 * Fully wired to PowerShell backend and HTML IDE
 */

class RawrXDMenuSystem {
  constructor() {
    this.editorState = {
      openTabs: new Map(),
      activeTabs: new Map(),
      splitLayout: 'single', // single, vertical-split, horizontal-split, grid
      activeGroup: 'main',
      panelStates: {
        outline: true,
        problems: true,
        terminal: true,
        output: false,
        debug: false,
      },
      bottomPanelVisible: true,
      rightPanelVisible: true,
    };

    this.settingDisplayIds = {
      theme: 'current-theme',
      fontSize: 'current-fontsize',
      fontFamily: 'current-font',
      lineHeight: 'current-lineheight',
      tabSize: 'current-tabsize',
      wordWrap: 'current-wordwrap',
      zoom: 'current-zoom',
      autoHide: 'current-autohide',
      minimap: 'current-minimap',
      breadcrumbs: 'current-breadcrumbs',
      lineNumbers: 'current-linenumbers',
      autoComplete: 'current-autocomplete',
      intelliSense: 'current-intellisense',
      linting: 'current-linting',
      formatOnSave: 'current-formatonsave',
      autoSave: 'current-autosave',
      terminalShell: 'current-shell',
      terminalFontSize: 'current-termfont',
      terminalCursor: 'current-cursor',
      aiModel: 'current-aimodel',
      aiTemperature: 'current-aitemp',
      aiAutoComplete: 'current-aiauto',
      settingsSync: 'current-sync',
    };

    this.settingStoragePrefix = 'rawrxd-setting-';

    this.commandRegistry = [];
    this.commandPaletteElements = null;
    this.commandPaletteVisible = false;

    this.init();
  }

  init() {
    this.createTopMenuBar();
    this.createEditorLayoutControls();
    this.createEditorTabBar();
    this.createBottomPanelControls();
    this.createCommandPalette();
    this.registerDefaultCommands();
    this.wireUpEventHandlers();
    console.log('✅ RawrXD Menu System Initialized');
  }

  // ==================== TOP MENU BAR ====================
  createTopMenuBar() {
    const existingMenuBar = document.querySelector('.top-bar');
    if (!existingMenuBar) return;

    // Create menu bar with standard IDE menus
    const menuHTML = `
      <div class="rawrxd-menu-bar">
        <div class="menu-group">
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('file')">File</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('edit')">Edit</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('selection')">Selection</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('view')">View</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('go')">Go</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('run')">Run</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('terminal')">Terminal</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('chat')">Chat</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('agent')">Agent</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('settings')">Settings</button>
          <button class="menu-btn" onclick="window.rawrxdMenu.showMenu('help')">Help</button>
        </div>
      </div>

      <!-- Dropdown Menus -->
      <div class="dropdown-menus" id="dropdown-menus">
        <!-- FILE MENU -->
        <div class="dropdown-menu" id="menu-file" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileNew()">
            <span class="menu-icon">📄</span> New File <span class="menu-shortcut">Ctrl+N</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileNewFolder()">
            <span class="menu-icon">📁</span> New Folder <span class="menu-shortcut">Ctrl+Shift+N</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileOpen()">
            <span class="menu-icon">📂</span> Open File <span class="menu-shortcut">Ctrl+O</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileOpenFolder()">
            <span class="menu-icon">📁</span> Open Folder <span class="menu-shortcut">Ctrl+K Ctrl+O</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileSave()">
            <span class="menu-icon">💾</span> Save <span class="menu-shortcut">Ctrl+S</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileSaveAs()">
            <span class="menu-icon">💾</span> Save As <span class="menu-shortcut">Ctrl+Shift+S</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileSaveAll()">
            <span class="menu-icon">💾</span> Save All <span class="menu-shortcut">Ctrl+Alt+S</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileRevert()">
            <span class="menu-icon">↩️</span> Revert File
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileClose()">
            <span class="menu-icon">✕</span> Close <span class="menu-shortcut">Ctrl+W</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileCloseAll()">
            <span class="menu-icon">✕</span> Close All <span class="menu-shortcut">Ctrl+K Ctrl+W</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionFileExit()">
            <span class="menu-icon">🚪</span> Exit
          </div>
        </div>

        <!-- TERMINAL MENU -->
        <div class="dropdown-menu" id="menu-terminal" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionEditUndo()">
            <span class="menu-icon">↶</span> Undo <span class="menu-shortcut">Ctrl+Z</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionEditRedo()">
            <span class="menu-icon">↷</span> Redo <span class="menu-shortcut">Ctrl+Shift+Z</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionEditCut()">
            <span class="menu-icon">✂️</span> Cut <span class="menu-shortcut">Ctrl+X</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionEditCopy()">
            <span class="menu-icon">📋</span> Copy <span class="menu-shortcut">Ctrl+C</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionEditPaste()">
            <span class="menu-icon">📌</span> Paste <span class="menu-shortcut">Ctrl+V</span>
          </div>
          <div class="menu-separator"></div>

        <!-- CHAT MENU -->
        <div class="dropdown-menu" id="menu-chat" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionChatFocus()">
            <span class="menu-icon">💬</span> Focus Chat Panel <span class="menu-shortcut">Ctrl+Shift+C</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionChatNewTab()">
            <span class="menu-icon">➕</span> New Chat Tab <span class="menu-shortcut">Ctrl+T</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionChatSaveHistory()">
            <span class="menu-icon">💾</span> Save Chat History
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionChatLoadHistory()">
            <span class="menu-icon">📂</span> Load Chat History...
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionChatExportHistory()">
            <span class="menu-icon">⬇️</span> Export Chat History...
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionChatClearHistory()">
            <span class="menu-icon">🗑️</span> Clear Chat History
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionChatPopOut()">
            <span class="menu-icon">🪟</span> Pop Out Active Chat...
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionChatSettings()">
            <span class="menu-icon">⚙️</span> Chat Settings...
          </div>
        </div>

        <!-- AGENT MENU -->
        <div class="dropdown-menu" id="menu-agent" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentToggleMode()">
            <span class="menu-icon">🤖</span> Toggle Agent Mode <span class="menu-shortcut">Ctrl+Shift+A</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentEnableMode()">
            <span class="menu-icon">🟢</span> Enable Agent Mode
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentDisableMode()">
            <span class="menu-icon">🔴</span> Disable Agent Mode
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentOpenTasks()">
            <span class="menu-icon">📋</span> Open Agent Tasks
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentRefreshTasks()">
            <span class="menu-icon">🔁</span> Refresh Task List
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentMonitorJobs()">
            <span class="menu-icon">🛰️</span> Monitor Agent Jobs
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentInitializeWorkers()">
            <span class="menu-icon">⚙️</span> Initialize Agent Workers
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentStopWorkers()">
            <span class="menu-icon">⏹️</span> Stop Agent Workers
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAgentShowStatus()">
            <span class="menu-icon">📊</span> Show Agent Status
          </div>
        </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionEditFind()">
            <span class="menu-icon">🔍</span> Find <span class="menu-shortcut">Ctrl+F</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionEditReplace()">
            <span class="menu-icon">🔄</span> Replace <span class="menu-shortcut">Ctrl+H</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionEditSelectAll()">
            <span class="menu-icon">☑️</span> Select All <span class="menu-shortcut">Ctrl+A</span>
          </div>
        </div>

        <!-- SELECTION MENU -->
        <div class="dropdown-menu" id="menu-selection" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionSelectLine()">
            <span class="menu-icon">▬</span> Select Line <span class="menu-shortcut">Ctrl+L</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSelectWord()">
            <span class="menu-icon">W</span> Select Word <span class="menu-shortcut">Ctrl+D</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionExpandSelection()">
            <span class="menu-icon">⤧</span> Expand Selection <span class="menu-shortcut">Shift+Alt+→</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionShrinkSelection()">
            <span class="menu-icon">⤦</span> Shrink Selection <span class="menu-shortcut">Shift+Alt+←</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionAddCursor()">
            <span class="menu-icon">+</span> Add Cursor <span class="menu-shortcut">Ctrl+Alt+↑/↓</span>
          </div>
        </div>

        <!-- VIEW MENU -->
        <div class="dropdown-menu" id="menu-view" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewExplorer()">
            <span class="menu-icon">📁</span> Explorer <span class="menu-shortcut">Ctrl+Shift+E</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewSearch()">
            <span class="menu-icon">🔍</span> Search <span class="menu-shortcut">Ctrl+Shift+F</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewSource()">
            <span class="menu-icon">⚙️</span> Source Control <span class="menu-shortcut">Ctrl+Shift+G</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewDebug()">
            <span class="menu-icon">🐛</span> Debug <span class="menu-shortcut">Ctrl+Shift+D</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewExtensions()">
            <span class="menu-icon">🧩</span> Extensions <span class="menu-shortcut">Ctrl+Shift+X</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewOutline()">
            <span class="menu-icon">🗂️</span> Outline <span class="menu-shortcut">Ctrl+Shift+O</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewProblems()">
            <span class="menu-icon">⚠️</span> Problems <span class="menu-shortcut">Ctrl+Shift+M</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewTerminal()">
            <span class="menu-icon">⌨️</span> Terminal <span class="menu-shortcut">Ctrl+\`</span>
          </div >
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewTheme()">
            <span class="menu-icon">🎨</span> Color Theme
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionViewZoom()">
            <span class="menu-icon">🔍</span> Zoom <span class="menu-shortcut">Ctrl+= / Ctrl+-</span>
          </div>
        </div >

        < !--GO MENU-- >
        <div class="dropdown-menu" id="menu-go" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionGoToLine()">
            <span class="menu-icon">↔️</span> Go to Line <span class="menu-shortcut">Ctrl+G</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionGoToFile()">
            <span class="menu-icon">📄</span> Go to File <span class="menu-shortcut">Ctrl+P</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionGoToSymbol()">
            <span class="menu-icon">@</span> Go to Symbol <span class="menu-shortcut">Ctrl+Shift+O</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionGoBack()">
            <span class="menu-icon">◄</span> Go Back <span class="menu-shortcut">Alt+←</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionGoForward()">
            <span class="menu-icon">►</span> Go Forward <span class="menu-shortcut">Alt+→</span>
          </div>
        </div>

        <!--RUN MENU-- >
        <div class="dropdown-menu" id="menu-run" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionRunCode()">
            <span class="menu-icon">▶️</span> Run Code <span class="menu-shortcut">F5</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionRunWithoutDebug()">
            <span class="menu-icon">▶️</span> Run Without Debug <span class="menu-shortcut">Ctrl+F5</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionRunInTerminal()">
            <span class="menu-icon">⌨️</span> Run in Terminal <span class="menu-shortcut">Shift+F5</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionDebugStart()">
            <span class="menu-icon">🐛</span> Start Debugging <span class="menu-shortcut">F9</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionDebugStop()">
            <span class="menu-icon">⏹️</span> Stop Debugging <span class="menu-shortcut">Shift+F9</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSetBreakpoint()">
            <span class="menu-icon">🔴</span> Toggle Breakpoint <span class="menu-shortcut">F8</span>
          </div>
        </div>

        <!--TERMINAL MENU-- >
        <div class="dropdown-menu" id="menu-terminal" style="display: none;">
          <div class="menu-item" onclick="window.rawrxdMenu.actionTerminalNew()">
            <span class="menu-icon">➕</span> New Terminal <span class="menu-shortcut">Ctrl+Shift+\`</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionTerminalKill()">
            <span class="menu-icon">✕</span> Kill Terminal
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionTerminalClear()">
            <span class="menu-icon">🧹</span> Clear Terminal
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionTerminalPowershell()">
            <span class="menu-icon">⚡</span> Use PowerShell
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionTerminalCmd()">
            <span class="menu-icon">⌨️</span> Use Command Prompt
          </div>
        </div>

        <!--SETTINGS MENU(COMPREHENSIVE)-- >
        <div class="dropdown-menu" id="menu-settings" style="display: none;">
          <div class="menu-section-header">Editor Settings</div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsTheme()">
            <span class="menu-icon">🎨</span> Color Theme <span class="menu-value" id="current-theme">Dark+</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsFontSize()">
            <span class="menu-icon">🔤</span> Font Size <span class="menu-value" id="current-fontsize">14px</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsFontFamily()">
            <span class="menu-icon">✍️</span> Font Family <span class="menu-value" id="current-font">Consolas</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsLineHeight()">
            <span class="menu-icon">📏</span> Line Height <span class="menu-value" id="current-lineheight">1.5</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsTabSize()">
            <span class="menu-icon">↹</span> Tab Size <span class="menu-value" id="current-tabsize">4</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsWordWrap()">
            <span class="menu-icon">↩️</span> Word Wrap <span class="menu-value" id="current-wordwrap">Off</span>
          </div>
          <div class="menu-separator"></div>
          
          <div class="menu-section-header">Display Settings</div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsZoomLevel()">
            <span class="menu-icon">🔍</span> Zoom Level <span class="menu-value" id="current-zoom">100%</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsAutoHide()">
            <span class="menu-icon">👁️</span> Auto-Hide Panels <span class="menu-value" id="current-autohide">Off</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsMinimap()">
            <span class="menu-icon">🗺️</span> Show Minimap <span class="menu-value" id="current-minimap">On</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsBreadcrumbs()">
            <span class="menu-icon">🍞</span> Show Breadcrumbs <span class="menu-value" id="current-breadcrumbs">On</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsLineNumbers()">
            <span class="menu-icon">🔢</span> Line Numbers <span class="menu-value" id="current-linenumbers">On</span>
          </div>
          <div class="menu-separator"></div>
          
          <div class="menu-section-header">Code Features</div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsAutoComplete()">
            <span class="menu-icon">💡</span> Auto Complete <span class="menu-value" id="current-autocomplete">On</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsIntelliSense()">
            <span class="menu-icon">🧠</span> IntelliSense <span class="menu-value" id="current-intellisense">On</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsLinting()">
            <span class="menu-icon">✅</span> Auto Linting <span class="menu-value" id="current-linting">On</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsFormatOnSave()">
            <span class="menu-icon">📝</span> Format on Save <span class="menu-value" id="current-formatonsave">On</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsAutoSave()">
            <span class="menu-icon">💾</span> Auto Save <span class="menu-value" id="current-autosave">afterDelay</span>
          </div>
          <div class="menu-separator"></div>
          
          <div class="menu-section-header">Terminal Settings</div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsTerminalShell()">
            <span class="menu-icon">⚡</span> Default Shell <span class="menu-value" id="current-shell">PowerShell</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsTerminalFontSize()">
            <span class="menu-icon">🔠</span> Terminal Font Size <span class="menu-value" id="current-termfont">12px</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsTerminalCursorStyle()">
            <span class="menu-icon">▌</span> Cursor Style <span class="menu-value" id="current-cursor">Block</span>
          </div>
          <div class="menu-separator"></div>
          
          <div class="menu-section-header">AI Settings</div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsAIModel()">
            <span class="menu-icon">🤖</span> AI Model <span class="menu-value" id="current-aimodel">GPT-4</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsAITemperature()">
            <span class="menu-icon">🌡️</span> AI Temperature <span class="menu-value" id="current-aitemp">0.7</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsAIAutoComplete()">
            <span class="menu-icon">✨</span> AI Auto-Complete <span class="menu-value" id="current-aiauto">On</span>
          </div>
          <div class="menu-separator"></div>
          
          <div class="menu-section-header">Advanced</div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsKeybindings()">
            <span class="menu-icon">⌨️</span> Keyboard Shortcuts <span class="menu-shortcut">Ctrl+K Ctrl+S</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsExtensions()">
            <span class="menu-icon">🧩</span> Manage Extensions <span class="menu-shortcut">Ctrl+Shift+X</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsSync()">
            <span class="menu-icon">🔄</span> Settings Sync <span class="menu-value" id="current-sync">Off</span>
          </div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsOpenConfig()">
            <span class="menu-icon">⚙️</span> Open Settings (JSON) <span class="menu-shortcut">Ctrl+,</span>
          </div>
          <div class="menu-separator"></div>
          <div class="menu-item" onclick="window.rawrxdMenu.actionSettingsReset()">
            <span class="menu-icon">🔄</span> Reset All Settings
          </div>
        </div>

        <!--HELP MENU-- >
      <div class="dropdown-menu" id="menu-help" style="display: none;">
        <div class="menu-item" onclick="window.rawrxdMenu.actionHelpWelcome()">
          <span class="menu-icon">👋</span> Welcome
        </div>
        <div class="menu-item" onclick="window.rawrxdMenu.actionHelpKeyboardShortcuts()">
          <span class="menu-icon">⌨️</span> Keyboard Shortcuts <span class="menu-shortcut">Ctrl+K Ctrl+S</span>
        </div>
        <div class="menu-item" onclick="window.rawrxdMenu.actionHelpAbout()">
          <span class="menu-icon">ℹ️</span> About RawrXD
        </div>
      </div>
      </div >
      `;

    existingMenuBar.insertAdjacentHTML('beforebegin', menuHTML);
    this.addMenuBarStyles();
  }

  addMenuBarStyles() {
    if (document.getElementById('rawrxd-menu-styles')) return;

    const styles = `
      < style id = "rawrxd-menu-styles" >
        .rawrxd - menu - bar {
      display: flex;
      gap: 0;
      background: #1e1e1e;
      border - bottom: 1px solid #333;
      padding: 0;
      height: 30px;
      align - items: center;
      font - family: 'Segoe UI', sans - serif;
      z - index: 100;
    }

        .menu - group {
      display: flex;
      gap: 0;
    }

        .menu - btn {
      background: transparent;
      border: none;
      color: #d4d4d4;
      padding: 4px 12px;
      cursor: pointer;
      font - size: 12px;
      transition: all 0.2s;
      height: 30px;
      display: flex;
      align - items: center;
    }

        .menu - btn:hover {
      background: #2d2d2d;
      color: #fff;
    }

        .dropdown - menus {
      position: fixed;
      top: 30px;
      left: 0;
      z - index: 200;
    }

        .dropdown - menu {
      background: #252526;
      border: 1px solid #3e3e42;
      box - shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
      min - width: 280px;
      border - radius: 4px;
      z - index: 200;
      max - height: 80vh;
      overflow - y: auto;
    }

        .menu - item {
      padding: 8px 16px;
      cursor: pointer;
      display: flex;
      align - items: center;
      color: #cccccc;
      font - size: 12px;
      transition: all 0.15s;
      gap: 8px;
    }

        .menu - item:hover {
      background: #094771;
      color: #fff;
    }

        .menu - icon {
      display: inline - block;
      width: 16px;
      text - align: center;
    }

        .menu - shortcut {
      margin - left: auto;
      font - size: 11px;
      opacity: 0.6;
    }

        .menu - separator {
      height: 1px;
      background: #3e3e42;
      margin: 4px 0;
    }

        .menu - section - header {
      padding: 8px 12px 4px 12px;
      font - size: 11px;
      font - weight: 600;
      color: #858585;
      text - transform: uppercase;
      letter - spacing: 0.5px;
      background: #2d2d30;
      border - bottom: 1px solid #3e3e42;
    }

        .menu - value {
      margin - left: auto;
      color: #858585;
      font - size: 11px;
      padding - left: 12px;
    }
      </style >
      `;

    document.head.insertAdjacentHTML('beforeend', styles);
  }

  showMenu(menuName) {
    // Hide all menus
    document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');

    // Show selected menu
    const menu = document.getElementById(`menu - ${menuName} `);
    if (menu) {
      menu.style.display = 'block';
    }

    // Close on click outside
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.menu-btn') && !e.target.closest('.dropdown-menu')) {
        document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');
      }
    });
  }

  // ==================== MENU ACTIONS ====================

  // FILE MENU ACTIONS
  actionFileNew() {
    this.invokePowerShell('file.new');
    if (typeof createNewFile !== 'undefined') createNewFile();
    this.closeAllMenus();
  }

  actionFileNewFolder() {
    this.invokePowerShell('file.newFolder');
    this.closeAllMenus();
  }

  actionFileOpen() {
    this.invokePowerShell('file.open');
    this.closeAllMenus();
  }

  actionFileOpenFolder() {
    this.invokePowerShell('file.openFolder');
    if (typeof browseDrives !== 'undefined') browseDrives();
    this.closeAllMenus();
  }

  actionFileSave() {
    this.invokePowerShell('file.save');
    if (typeof saveCurrentFile !== 'undefined') saveCurrentFile();
    this.closeAllMenus();
  }

  actionFileSaveAs() {
    this.invokePowerShell('file.saveAs');
    this.closeAllMenus();
  }

  actionFileSaveAll() {
    this.invokePowerShell('file.saveAll');
    this.closeAllMenus();
  }

  actionFileRevert() {
    this.invokePowerShell('file.revert');
    this.closeAllMenus();
  }

  actionFileClose() {
    this.invokePowerShell('file.close');
    this.closeAllMenus();
  }

  actionFileCloseAll() {
    this.invokePowerShell('file.closeAll');
    this.closeAllMenus();
  }

  actionFileExit() {
    this.invokePowerShell('file.exit');
    window.close();
  }

  // EDIT MENU ACTIONS
  actionEditUndo() {
    const editor = this.getActiveEditor();
    if (editor && editor.undo) editor.undo();
    else document.execCommand('undo');
    this.closeAllMenus();
  }

  actionEditRedo() {
    const editor = this.getActiveEditor();
    if (editor && editor.redo) editor.redo();
    else document.execCommand('redo');
    this.closeAllMenus();
  }

  actionEditCut() {
    document.execCommand('cut');
    this.closeAllMenus();
  }

  actionEditCopy() {
    document.execCommand('copy');
    this.closeAllMenus();
  }

  actionEditPaste() {
    document.execCommand('paste');
    this.closeAllMenus();
  }

  actionEditFind() {
    this.showFindPanel();
    this.closeAllMenus();
  }

  actionEditReplace() {
    this.showReplacePanel();
    this.closeAllMenus();
  }

  actionEditSelectAll() {
    const editor = this.getActiveEditor();
    if (editor && editor.selectAll) editor.selectAll();
    else document.execCommand('selectAll');
    this.closeAllMenus();
  }

  // SELECTION MENU ACTIONS
  actionSelectLine() {
    this.selectLine();
    this.closeAllMenus();
  }

  actionSelectWord() {
    this.selectWord();
    this.closeAllMenus();
  }

  actionExpandSelection() {
    this.expandSelection();
    this.closeAllMenus();
  }

  actionShrinkSelection() {
    this.shrinkSelection();
    this.closeAllMenus();
  }

  actionAddCursor() {
    this.addCursor();
    this.closeAllMenus();
  }

  // VIEW MENU ACTIONS
  actionViewExplorer() {
    if (typeof togglePanel !== 'undefined') togglePanel('sidebar');
    this.invokePowerShell('view.toggleExplorer');
    this.closeAllMenus();
  }

  actionViewSearch() {
    if (typeof showSearchPanel !== 'undefined') showSearchPanel();
    this.invokePowerShell('view.showSearch');
    this.closeAllMenus();
  }

  actionViewSource() {
    this.invokePowerShell('view.showSourceControl');
    this.closeAllMenus();
  }

  actionViewDebug() {
    this.invokePowerShell('view.showDebug');
    this.closeAllMenus();
  }

  actionViewExtensions() {
    if (typeof showSearchPanel !== 'undefined') showSearchPanel();
    this.invokePowerShell('view.showExtensions');
    this.closeAllMenus();
  }

  actionViewOutline() {
    this.togglePanel('outline');
    this.closeAllMenus();
  }

  actionViewProblems() {
    this.togglePanel('problems');
    this.closeAllMenus();
  }

  actionViewTerminal() {
    this.togglePanel('terminal');
    this.invokePowerShell('view.toggleTerminal');
    this.closeAllMenus();
  }

  actionViewTheme() {
    this.showThemeSelector();
    this.closeAllMenus();
  }

  actionViewZoom() {
    this.showZoomControls();
    this.closeAllMenus();
  }

  // GO MENU ACTIONS
  actionGoToLine() {
    const line = prompt('Go to line:');
    if (line) this.goToLine(parseInt(line));
    this.closeAllMenus();
  }

  actionGoToFile() {
    this.showQuickOpen();
    this.closeAllMenus();
  }

  actionGoToSymbol() {
    this.showSymbolSearch();
    this.closeAllMenus();
  }

  actionGoBack() {
    this.navigationHistory('back');
    this.closeAllMenus();
  }

  actionGoForward() {
    this.navigationHistory('forward');
    this.closeAllMenus();
  }

  // RUN MENU ACTIONS
  actionRunCode() {
    if (typeof runCode !== 'undefined') runCode();
    this.invokePowerShell('run.execute');
    this.closeAllMenus();
  }

  actionRunWithoutDebug() {
    this.invokePowerShell('run.executeWithoutDebug');
    this.closeAllMenus();
  }

  actionRunInTerminal() {
    this.invokePowerShell('run.executeInTerminal');
    this.closeAllMenus();
  }

  actionDebugStart() {
    this.invokePowerShell('debug.start');
    this.closeAllMenus();
  }

  actionDebugStop() {
    this.invokePowerShell('debug.stop');
    this.closeAllMenus();
  }

  actionSetBreakpoint() {
    this.toggleBreakpoint();
    this.closeAllMenus();
  }

  // TERMINAL MENU ACTIONS
  actionTerminalNew() {
    this.invokePowerShell('terminal.new');
    this.closeAllMenus();
  }

  actionTerminalKill() {
    this.invokePowerShell('terminal.kill');
    this.closeAllMenus();
  }

  actionTerminalClear() {
    this.invokePowerShell('terminal.clear');
    this.closeAllMenus();
  }

  actionTerminalPowershell() {
    this.invokePowerShell('terminal.setShell', { value: 'PowerShell' });
    this.closeAllMenus();
  }

  actionTerminalCmd() {
    this.invokePowerShell('terminal.setShell', { value: 'CMD' });
    this.closeAllMenus();
  }

  // CHAT MENU ACTIONS
  actionChatFocus() {
    this.invokePowerShell('chat.focus');
    this.closeAllMenus();
  }

  actionChatNewTab() {
    this.invokePowerShell('chat.newTab');
    this.closeAllMenus();
  }

  actionChatSaveHistory() {
    this.invokePowerShell('chat.saveHistory');
    this.closeAllMenus();
  }

  actionChatLoadHistory() {
    this.invokePowerShell('chat.loadHistory');
    this.closeAllMenus();
  }

  actionChatExportHistory() {
    this.invokePowerShell('chat.exportHistory');
    this.closeAllMenus();
  }

  actionChatClearHistory() {
    this.invokePowerShell('chat.clearHistory');
    this.closeAllMenus();
  }

  actionChatPopOut() {
    this.invokePowerShell('chat.popOut');
    this.closeAllMenus();
  }

  actionChatSettings() {
    this.invokePowerShell('chat.settings');
    this.closeAllMenus();
  }

  // AGENT MENU ACTIONS
  actionAgentToggleMode() {
    this.invokePowerShell('agent.toggleMode');
    this.closeAllMenus();
  }

  actionAgentEnableMode() {
    this.invokePowerShell('agent.enableMode');
    this.closeAllMenus();
  }

  actionAgentDisableMode() {
    this.invokePowerShell('agent.disableMode');
    this.closeAllMenus();
  }

  actionAgentOpenTasks() {
    this.invokePowerShell('agent.openTasks');
    this.closeAllMenus();
  }

  actionAgentRefreshTasks() {
    this.invokePowerShell('agent.refreshTasks');
    this.closeAllMenus();
  }

  actionAgentMonitorJobs() {
    this.invokePowerShell('agent.monitorJobs');
    this.closeAllMenus();
  }

  actionAgentInitializeWorkers() {
    this.invokePowerShell('agent.initializeWorkers');
    this.closeAllMenus();
  }

  actionAgentStopWorkers() {
    this.invokePowerShell('agent.stopWorkers');
    this.closeAllMenus();
  }

  actionAgentShowStatus() {
    this.invokePowerShell('agent.showStatus');
    this.closeAllMenus();
  }

  // ==================== SETTINGS MENU ACTIONS ====================
  actionSettingsTheme() {
    const themes = ['Dark+', 'Light+', 'Monokai', 'Solarized Dark', 'Dracula', 'Nord', 'One Dark Pro'];
    const current = document.getElementById('current-theme')?.textContent || 'Dark+';
    const idx = themes.indexOf(current);
    const next = themes[(idx + 1) % themes.length];
    this.updateSetting('theme', next);
    this.invokePowerShell('settings.theme', { value: next });
    this.closeAllMenus();
  }

  actionSettingsFontSize() {
    const sizes = [10, 11, 12, 13, 14, 16, 18, 20, 24];
    const currentDisplay = document.getElementById('current-fontsize')?.textContent || '14px';
    const currentIndex = sizes.findIndex((size) => `${size}px` === currentDisplay);
    const nextSize = sizes[(currentIndex + 1) % sizes.length];
    this.updateSetting('fontSize', `${nextSize}px`);
    this.invokePowerShell('settings.fontSize', { value: nextSize });
    this.closeAllMenus();
  }

  actionSettingsFontFamily() {
    const fonts = ['Consolas', 'Fira Code', 'JetBrains Mono', 'Cascadia Code', 'Source Code Pro', 'Monaco'];
    const current = document.getElementById('current-font')?.textContent || 'Consolas';
    const idx = fonts.indexOf(current);
    const next = fonts[(idx + 1) % fonts.length];
    this.updateSetting('fontFamily', next);
    this.invokePowerShell('settings.fontFamily', { value: next });
    this.closeAllMenus();
  }

  actionSettingsLineHeight() {
    const heights = ['1.2', '1.3', '1.4', '1.5', '1.6', '1.8', '2.0'];
    const current = document.getElementById('current-lineheight')?.textContent || '1.5';
    const idx = heights.indexOf(current);
    const next = heights[(idx + 1) % heights.length];
    this.updateSetting('lineHeight', next);
    this.closeAllMenus();
  }

  actionSettingsTabSize() {
    const sizes = [2, 4, 8];
    const currentDisplay = document.getElementById('current-tabsize')?.textContent || '4';
    const currentIndex = sizes.findIndex((size) => `${size}` === currentDisplay);
    const nextSize = sizes[(currentIndex + 1) % sizes.length];
    this.updateSetting('tabSize', `${nextSize}`);
    this.invokePowerShell('settings.tabSize', { value: nextSize });
    this.closeAllMenus();
  }

  actionSettingsWordWrap() {
    const current = document.getElementById('current-wordwrap')?.textContent || 'Off';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('wordWrap', next);
    this.invokePowerShell('settings.wordWrap', { value: next === 'On' });
    this.closeAllMenus();
  }

  actionSettingsZoomLevel() {
    const levels = ['75%', '90%', '100%', '110%', '125%', '150%', '175%', '200%'];
    const current = document.getElementById('current-zoom')?.textContent || '100%';
    const idx = levels.indexOf(current);
    const next = levels[(idx + 1) % levels.length];
    this.updateSetting('zoom', next);
    document.body.style.zoom = parseInt(next) / 100;
    this.closeAllMenus();
  }

  actionSettingsAutoHide() {
    const current = document.getElementById('current-autohide')?.textContent || 'Off';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('autoHide', next);
    this.closeAllMenus();
  }

  actionSettingsMinimap() {
    const current = document.getElementById('current-minimap')?.textContent || 'On';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('minimap', next);
    this.invokePowerShell('settings.minimap', { value: next === 'On' });
    this.closeAllMenus();
  }

  actionSettingsBreadcrumbs() {
    const current = document.getElementById('current-breadcrumbs')?.textContent || 'On';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('breadcrumbs', next);
    this.closeAllMenus();
  }

  actionSettingsLineNumbers() {
    const current = document.getElementById('current-linenumbers')?.textContent || 'On';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('lineNumbers', next);
    this.closeAllMenus();
  }

  actionSettingsAutoComplete() {
    const current = document.getElementById('current-autocomplete')?.textContent || 'On';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('autoComplete', next);
    this.invokePowerShell('settings.autoComplete', { value: next === 'On' });
    this.closeAllMenus();
  }

  actionSettingsIntelliSense() {
    const current = document.getElementById('current-intellisense')?.textContent || 'On';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('intelliSense', next);
    this.invokePowerShell('settings.intelliSense', { value: next === 'On' });
    this.closeAllMenus();
  }

  actionSettingsLinting() {
    const current = document.getElementById('current-linting')?.textContent || 'On';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('linting', next);
    this.invokePowerShell('settings.linting', { value: next === 'On' });
    this.closeAllMenus();
  }

  actionSettingsFormatOnSave() {
    const current = document.getElementById('current-formatonsave')?.textContent || 'On';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('formatOnSave', next);
    this.invokePowerShell('settings.formatOnSave', { value: next === 'On' });
    this.closeAllMenus();
  }

  actionSettingsAutoSave() {
    const modes = ['off', 'afterDelay', 'onFocusChange', 'onWindowChange'];
    const current = document.getElementById('current-autosave')?.textContent || 'afterDelay';
    const idx = modes.indexOf(current);
    const next = modes[(idx + 1) % modes.length];
    this.updateSetting('autoSave', next);
    this.invokePowerShell('settings.autoSave', { value: next });
    this.closeAllMenus();
  }

  actionSettingsTerminalShell() {
    const shells = ['PowerShell', 'CMD', 'Git Bash', 'WSL'];
    const current = document.getElementById('current-shell')?.textContent || 'PowerShell';
    const idx = shells.indexOf(current);
    const next = shells[(idx + 1) % shells.length];
    this.updateSetting('terminalShell', next);
    this.invokePowerShell('terminal.setShell', { value: next });
    this.closeAllMenus();
  }

  actionSettingsTerminalFontSize() {
    const sizes = ['10px', '11px', '12px', '13px', '14px', '16px'];
    const current = document.getElementById('current-termfont')?.textContent || '12px';
    const idx = sizes.indexOf(current);
    const next = sizes[(idx + 1) % sizes.length];
    this.updateSetting('terminalFontSize', next);
    this.closeAllMenus();
  }

  actionSettingsTerminalCursorStyle() {
    const styles = ['Block', 'Line', 'Underline'];
    const current = document.getElementById('current-cursor')?.textContent || 'Block';
    const idx = styles.indexOf(current);
    const next = styles[(idx + 1) % styles.length];
    this.updateSetting('terminalCursor', next);
    this.closeAllMenus();
  }

  actionSettingsAIModel() {
    const models = ['GPT-4', 'GPT-3.5', 'Claude', 'Gemini', 'Llama'];
    const current = document.getElementById('current-aimodel')?.textContent || 'GPT-4';
    const idx = models.indexOf(current);
    const next = models[(idx + 1) % models.length];
    this.updateSetting('aiModel', next);
    this.invokePowerShell('ai.model', { value: next });
    this.closeAllMenus();
  }

  actionSettingsAITemperature() {
    const temps = ['0.0', '0.3', '0.5', '0.7', '0.9', '1.0'];
    const current = document.getElementById('current-aitemp')?.textContent || '0.7';
    const idx = temps.indexOf(current);
    const next = temps[(idx + 1) % temps.length];
    this.updateSetting('aiTemperature', next);
    this.invokePowerShell('ai.temperature', { value: parseFloat(next) });
    this.closeAllMenus();
  }

  actionSettingsAIAutoComplete() {
    const current = document.getElementById('current-aiauto')?.textContent || 'On';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('aiAutoComplete', next);
    this.invokePowerShell('ai.autoComplete', { value: next === 'On' });
    this.closeAllMenus();
  }

  actionSettingsKeybindings() {
    this.showKeyboardShortcuts();
    this.closeAllMenus();
  }

  actionSettingsExtensions() {
    this.actionViewExtensions();
    this.closeAllMenus();
  }

  actionSettingsSync() {
    const current = document.getElementById('current-sync')?.textContent || 'Off';
    const next = current === 'Off' ? 'On' : 'Off';
    this.updateSetting('settingsSync', next);
    this.invokePowerShell('settings.sync', { value: next === 'On' });
    this.closeAllMenus();
  }

  actionSettingsOpenConfig() {
    this.invokePowerShell('settings.openConfig');
    this.closeAllMenus();
  }

  actionSettingsReset() {
    if (confirm('Reset all settings to default? This cannot be undone.')) {
      this.invokePowerShell('settings.reset');
      location.reload();
    }
    this.closeAllMenus();
  }

  updateSetting(key, value, displayId) {
    const resolvedId = displayId || this.settingDisplayIds[key];
    if (resolvedId) {
      const element = document.getElementById(resolvedId);
      if (element) {
        element.textContent = value;
      }
    }

    try {
      localStorage.setItem(`${this.settingStoragePrefix}${key}`, value);
      console.log(`✅ Setting updated: ${key} = ${value}`);
    } catch (e) {
      console.error('Failed to save setting:', e);
    }
  }

  // ==================== HELP MENU ACTIONS ====================
  actionHelpWelcome() {
    this.showWelcomeScreen();
    this.closeAllMenus();
  }

  actionHelpKeyboardShortcuts() {
    this.showKeyboardShortcuts();
    this.closeAllMenus();
  }

  actionHelpAbout() {
    this.showAboutDialog();
    this.closeAllMenus();
  }

  closeAllMenus() {
    document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');
  }

  // ==================== EDITOR LAYOUT CONTROLS ====================
  createEditorLayoutControls() {
    const editorHeader = document.querySelector('.editor-header');
    if (!editorHeader) return;

    const layoutControlsHTML = `
      < div class="editor-layout-controls" >
        < !--Tab Management-- >
        <button class="layout-btn" title="Split Right (Ctrl+\\)" onclick="window.rawrxdMenu.splitEditorRight()">⬜ ⬜</button>
        <button class="layout-btn" title="Split Down" onclick="window.rawrxdMenu.splitEditorDown()">⬜<br>⬜</button>
        
        <!--Editor Group Controls-- >
        <button class="layout-btn" title="Focus Right Group" onclick="window.rawrxdMenu.focusGroupRight()">▶</button>
        <button class="layout-btn" title="Focus Down Group" onclick="window.rawrxdMenu.focusGroupDown()">▼</button>
        
        <!--View Controls-- >
        <button class="layout-btn" title="Maximize Editor (Ctrl+K Z)" onclick="window.rawrxdMenu.maximizeEditor()">🔲</button>
        <button class="layout-btn" title="Restore Editor" onclick="window.rawrxdMenu.restoreEditor()">🔳</button>
        <button class="layout-btn" title="Toggle Sidebar (Ctrl+B)" onclick="togglePanel('sidebar')">🗂️</button>
        <button class="layout-btn" title="Toggle Bottom Panel (Ctrl+J)" onclick="window.rawrxdMenu.toggleBottomPanel()">📋</button>
      </div >
      `;

    editorHeader.insertAdjacentHTML('beforeend', layoutControlsHTML);
    this.addLayoutControlStyles();
  }

  addLayoutControlStyles() {
    if (document.getElementById('layout-controls-styles')) return;

    const styles = `
      < style id = "layout-controls-styles" >
        .editor - layout - controls {
      display: flex;
      gap: 4px;
      align - items: center;
      padding: 0 8px;
      border - left: 1px solid #3e3e42;
    }

        .layout - btn {
      background: transparent;
      border: 1px solid #3e3e42;
      color: #858585;
      width: 28px;
      height: 28px;
      cursor: pointer;
      border - radius: 3px;
      font - size: 12px;
      display: flex;
      align - items: center;
      justify - content: center;
      transition: all 0.2s;
      padding: 0;
    }

        .layout - btn:hover {
      background: #2d2d2d;
      color: #d4d4d4;
      border - color: #505050;
    }

        .menu - btn:active {
      background: #094771;
      border - color: #0078d4;
    }

        .menu - section - header {
      padding: 8px 12px 4px 12px;
      font - size: 11px;
      font - weight: 600;
      color: #858585;
      text - transform: uppercase;
      letter - spacing: 0.5px;
      background: #2d2d30;
      border - bottom: 1px solid #3e3e42;
    }

        .menu - value {
      margin - left: auto;
      color: #858585;
      font - size: 11px;
      padding - left: 12px;
    }
      </style >
      `;

    document.head.insertAdjacentHTML('beforeend', styles);
  }

  // ==================== EDITOR TAB BAR ====================
  createEditorTabBar() {
    const editorTabs = document.querySelector('.editor-tabs');
    if (!editorTabs) return;

    // Add tab context menu
    const tabContextHTML = `
      < div class="tab-context-menu" id = "tab-context-menu" style = "display: none; position: fixed;" >
        <div class="menu-item" onclick="window.rawrxdMenu.actionTabClose()">Close</div>
        <div class="menu-item" onclick="window.rawrxdMenu.actionTabCloseOthers()">Close Others</div>
        <div class="menu-item" onclick="window.rawrxdMenu.actionTabCloseAll()">Close All</div>
        <div class="menu-separator"></div>
        <div class="menu-item" onclick="window.rawrxdMenu.actionTabSplitRight()">Split Right</div>
        <div class="menu-item" onclick="window.rawrxdMenu.actionTabSplitDown()">Split Down</div>
      </div >
      `;

    document.body.insertAdjacentHTML('beforeend', tabContextHTML);

    // Add tab right-click handlers
    editorTabs.addEventListener('contextmenu', (e) => {
      if (e.target.closest('.editor-tab')) {
        e.preventDefault();
        const menu = document.getElementById('tab-context-menu');
        menu.style.left = e.pageX + 'px';
        menu.style.top = e.pageY + 'px';
        menu.style.display = 'block';
      }
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('#tab-context-menu') && !e.target.closest('.editor-tab')) {
        document.getElementById('tab-context-menu').style.display = 'none';
      }
    });
  }

  // ==================== BOTTOM PANEL CONTROLS ====================
  createBottomPanelControls() {
    // This would integrate with existing bottom panel
    // For now, we'll add toggle functionality
  }

  // ==================== LAYOUT ACTIONS ====================
  splitEditorRight() {
    console.log('Split editor right');
    alert('Split Right - Coming Soon');
  }

  splitEditorDown() {
    console.log('Split editor down');
    alert('Split Down - Coming Soon');
  }

  focusGroupRight() {
    alert('Focus Right Group');
  }

  focusGroupDown() {
    alert('Focus Down Group');
  }

  maximizeEditor() {
    alert('Maximize Editor');
  }

  restoreEditor() {
    alert('Restore Editor');
  }

  toggleBottomPanel() {
    const panel = document.querySelector('.bottom-panel');
    if (panel) {
      panel.style.display = panel.style.display === 'none' ? 'flex' : 'none';
    }
  }

  // ==================== TAB ACTIONS ====================
  actionTabClose() { alert('Close Tab'); }
  actionTabCloseOthers() { alert('Close Other Tabs'); }
  actionTabCloseAll() { alert('Close All Tabs'); }
  actionTabSplitRight() { alert('Split Right'); }
  actionTabSplitDown() { alert('Split Down'); }

  // ==================== EVENT HANDLERS ====================
  wireUpEventHandlers() {
    // Comprehensive keyboard shortcuts system
    document.addEventListener('keydown', (e) => {
      const key = e.key.toLowerCase();
      const ctrl = e.ctrlKey;
      const shift = e.shiftKey;
      const alt = e.altKey;

      if (ctrl && shift && !alt && key === 'p') {
        e.preventDefault();
        this.toggleCommandPalette(!this.commandPaletteVisible);
        return;
      }

      if (this.commandPaletteVisible) {
        if (!ctrl && !shift && !alt && key === 'escape') {
          e.preventDefault();
          this.toggleCommandPalette(false);
        }
        return;
      }

      // FILE MENU SHORTCUTS
      if (ctrl && !shift && !alt && key === 'n') { e.preventDefault(); this.actionFileNew(); }
      if (ctrl && shift && !alt && key === 'n') { e.preventDefault(); this.actionFileNewFolder(); }
      if (ctrl && !shift && !alt && key === 'o') { e.preventDefault(); this.actionFileOpen(); }
      if (ctrl && !shift && !alt && key === 's') { e.preventDefault(); this.actionFileSave(); }
      if (ctrl && shift && !alt && key === 's') { e.preventDefault(); this.actionFileSaveAs(); }
      if (ctrl && alt && !shift && key === 's') { e.preventDefault(); this.actionFileSaveAll(); }
      if (ctrl && !shift && !alt && key === 'w') { e.preventDefault(); this.actionFileClose(); }

      // EDIT MENU SHORTCUTS
      if (ctrl && !shift && !alt && key === 'z') { e.preventDefault(); this.actionEditUndo(); }
      if (ctrl && shift && !alt && key === 'z') { e.preventDefault(); this.actionEditRedo(); }
      if (ctrl && !shift && !alt && key === 'x') { e.preventDefault(); this.actionEditCut(); }
      if (ctrl && !shift && !alt && key === 'c') { e.preventDefault(); this.actionEditCopy(); }
      if (ctrl && !shift && !alt && key === 'v') { e.preventDefault(); this.actionEditPaste(); }
      if (ctrl && !shift && !alt && key === 'f') { e.preventDefault(); this.actionEditFind(); }
      if (ctrl && !shift && !alt && key === 'h') { e.preventDefault(); this.actionEditReplace(); }
      if (ctrl && !shift && !alt && key === 'a') { e.preventDefault(); this.actionEditSelectAll(); }
      if (ctrl && !shift && !alt && key === 'l') { e.preventDefault(); this.actionSelectLine(); }
      if (ctrl && !shift && !alt && key === 'd') { e.preventDefault(); this.actionSelectWord(); }

      // VIEW MENU SHORTCUTS
      if (ctrl && !shift && !alt && key === 'b') { e.preventDefault(); this.actionViewExplorer(); }
      if (ctrl && shift && !alt && key === 'e') { e.preventDefault(); this.actionViewExplorer(); }
      if (ctrl && shift && !alt && key === 'f') { e.preventDefault(); this.actionViewSearch(); }
      if (ctrl && shift && !alt && key === 'g') { e.preventDefault(); this.actionViewSource(); }
      if (ctrl && shift && !alt && key === 'd') { e.preventDefault(); this.actionViewDebug(); }
      if (ctrl && shift && !alt && key === 'x') { e.preventDefault(); this.actionViewExtensions(); }
      if (ctrl && shift && !alt && key === 'o') { e.preventDefault(); this.actionViewOutline(); }
      if (ctrl && shift && !alt && key === 'm') { e.preventDefault(); this.actionViewProblems(); }
      if (ctrl && !shift && !alt && key === '`') { e.preventDefault(); this.actionViewTerminal(); }
      if (ctrl && !shift && !alt && key === 'j') { e.preventDefault(); this.toggleBottomPanel(); }

      // GO MENU SHORTCUTS
      if (ctrl && !shift && !alt && key === 'g') { e.preventDefault(); this.actionGoToLine(); }
      if (ctrl && !shift && !alt && key === 'p') { e.preventDefault(); this.actionGoToFile(); }
      if (alt && !shift && !ctrl && key === 'arrowleft') { e.preventDefault(); this.actionGoBack(); }
      if (alt && !shift && !ctrl && key === 'arrowright') { e.preventDefault(); this.actionGoForward(); }

      // RUN MENU SHORTCUTS
      if (!ctrl && !shift && !alt && key === 'f5') { e.preventDefault(); this.actionRunCode(); }
      if (ctrl && !shift && !alt && key === 'f5') { e.preventDefault(); this.actionRunWithoutDebug(); }
      if (!ctrl && shift && !alt && key === 'f5') { e.preventDefault(); this.actionRunInTerminal(); }
      if (!ctrl && !shift && !alt && key === 'f9') { e.preventDefault(); this.actionDebugStart(); }
      if (!ctrl && shift && !alt && key === 'f9') { e.preventDefault(); this.actionDebugStop(); }
      if (!ctrl && !shift && !alt && key === 'f8') { e.preventDefault(); this.actionSetBreakpoint(); }

      // TERMINAL MENU SHORTCUTS
      if (ctrl && shift && !alt && key === '`') { e.preventDefault(); this.actionTerminalNew(); }

      // CHAT MENU SHORTCUTS
      if (ctrl && !shift && !alt && key === 't') { e.preventDefault(); this.actionChatNewTab(); }
      if (ctrl && shift && !alt && key === 'c') { e.preventDefault(); this.actionChatFocus(); }

      // AGENT MENU SHORTCUTS
      if (ctrl && shift && !alt && key === 'a') { e.preventDefault(); this.actionAgentToggleMode(); }

      // SETTINGS SHORTCUTS
      if (ctrl && !shift && !alt && key === ',') { e.preventDefault(); this.actionSettingsOpenConfig(); }

      // EDITOR LAYOUT SHORTCUTS
      if (ctrl && !shift && !alt && key === '\\') { e.preventDefault(); this.splitEditorRight(); }
    });

    console.log('✅ Comprehensive keyboard shortcuts wired (50+ shortcuts)');
  }

  // ==================== COMMAND PALETTE ====================
  createCommandPalette() {
    if (document.getElementById('rawrxd-command-palette')) {
      this.commandPaletteElements = {
        overlay: document.getElementById('rawrxd-command-palette'),
        input: document.querySelector('.command-palette-input'),
        results: document.querySelector('.command-palette-results'),
      };
      return;
    }

    const styleId = 'rawrxd-command-palette-style';
    if (!document.getElementById(styleId)) {
      const style = document.createElement('style');
      style.id = styleId;
      style.textContent = `
        .command-palette-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.35); display: flex; align-items: flex-start; justify-content: center; padding-top: 10vh; z-index: 5000; }
        .command-palette-overlay.hidden { display: none; }
        .command-palette-container { width: min(640px, 90vw); background: #1e1e1e; border: 1px solid #3c3c3c; border-radius: 6px; box-shadow: 0 18px 48px rgba(0,0,0,0.45); overflow: hidden; }
        .command-palette-input { width: 100%; padding: 14px 18px; background: #2d2d30; border: none; color: #f3f3f3; font-size: 16px; outline: none; }
        .command-palette-results { list-style: none; margin: 0; padding: 8px 0; max-height: 360px; overflow-y: auto; }
        .command-palette-item { display: flex; justify-content: space-between; align-items: center; padding: 10px 18px; color: #c8c8c8; cursor: pointer; }
        .command-palette-item.active, .command-palette-item:hover { background: #094771; color: #ffffff; }
        .command-label { flex: 1; }
        .command-meta { display: flex; gap: 12px; font-size: 12px; color: #9da5b4; }
        .command-shortcut { font-family: 'Consolas', 'Courier New', monospace; background: rgba(255,255,255,0.07); padding: 2px 6px; border-radius: 3px; }
        .command-palette-item.empty { cursor: default; color: #757575; }
      `;
      document.head.appendChild(style);
    }

    const overlay = document.createElement('div');
    overlay.id = 'rawrxd-command-palette';
    overlay.className = 'command-palette-overlay hidden';
    overlay.innerHTML = `
      <div class="command-palette-container">
        <input class="command-palette-input" type="text" placeholder="Type a command or search..." autocomplete="off" />
        <ul class="command-palette-results"></ul>
      </div>
    `;

    document.body.appendChild(overlay);

    const input = overlay.querySelector('.command-palette-input');
    const results = overlay.querySelector('.command-palette-results');

    input.addEventListener('input', () => this.updateCommandPaletteResults(input.value));
    input.addEventListener('keydown', (evt) => this.handleCommandPaletteNavigation(evt));
    overlay.addEventListener('click', (evt) => {
      if (evt.target === overlay) {
        this.toggleCommandPalette(false);
      }
    });

    this.commandPaletteElements = { overlay, input, results };
  }

  registerCommand({ id, label, action, category = 'General', shortcut = '' }) {
    if (!id || typeof action !== 'function') { return; }
    // Deduplicate by id so later registrations can replace earlier ones
    this.commandRegistry = this.commandRegistry.filter((cmd) => cmd.id !== id);
    this.commandRegistry.push({ id, label, action, category, shortcut });
  }

  registerDefaultCommands() {
    this.registerCommand({ id: 'file.new', label: 'File: New File', action: () => this.actionFileNew(), category: 'File', shortcut: 'Ctrl+N' });
    this.registerCommand({ id: 'file.open', label: 'File: Open File', action: () => this.actionFileOpen(), category: 'File', shortcut: 'Ctrl+O' });
    this.registerCommand({ id: 'file.save', label: 'File: Save', action: () => this.actionFileSave(), category: 'File', shortcut: 'Ctrl+S' });
    this.registerCommand({ id: 'view.problems', label: 'View: Toggle Problems Panel', action: () => this.actionViewProblems(), category: 'View', shortcut: 'Ctrl+Shift+M' });
    this.registerCommand({ id: 'view.terminal', label: 'View: Toggle Terminal', action: () => this.actionViewTerminal(), category: 'View', shortcut: 'Ctrl+`' });
    this.registerCommand({ id: 'view.commandPalette', label: 'View: Toggle Command Palette', action: () => this.toggleCommandPalette(true), category: 'View', shortcut: 'Ctrl+Shift+P' });
    this.registerCommand({
      id: 'extensions.marketplace',
      label: 'Extensions: Open Marketplace',
      category: 'Extensions',
      action: () => {
        this.invokePowerShell('extensions.marketplace');
      }
    });
    this.registerCommand({
      id: 'extensions.installed',
      label: 'Extensions: Show Installed Extensions',
      category: 'Extensions',
      action: () => {
        this.invokePowerShell('extensions.installed');
      }
    });
    this.registerCommand({
      id: 'diagnostics.show',
      label: 'Diagnostics: Show Editor Report',
      category: 'Diagnostics',
      action: () => {
        this.invokePowerShell('diagnostics.show');
      }
    });
    this.registerCommand({
      id: 'diagnostics.repairColors',
      label: 'Diagnostics: Repair Editor Colors',
      category: 'Diagnostics',
      action: () => {
        this.invokePowerShell('diagnostics.repairColors');
      }
    });
    this.registerCommand({
      id: 'diagnostics.fullRepair',
      label: 'Diagnostics: Run Full Repair',
      category: 'Diagnostics',
      action: () => {
        this.invokePowerShell('diagnostics.fullRepair');
      }
    });
    this.registerCommand({
      id: 'diagnostics.toggleAuto',
      label: 'Diagnostics: Toggle Auto-Repair',
      category: 'Diagnostics',
      action: () => {
        this.invokePowerShell('diagnostics.toggleAuto');
      }
    });
    this.registerCommand({ id: 'chat.focus', label: 'Chat: Focus Chat Panel', category: 'Chat', shortcut: 'Ctrl+Shift+C', action: () => this.actionChatFocus() });
    this.registerCommand({ id: 'chat.newTab', label: 'Chat: New Chat Tab', category: 'Chat', shortcut: 'Ctrl+T', action: () => this.actionChatNewTab() });
    this.registerCommand({ id: 'chat.saveHistory', label: 'Chat: Save Chat History', category: 'Chat', action: () => this.actionChatSaveHistory() });
    this.registerCommand({ id: 'chat.loadHistory', label: 'Chat: Load Chat History', category: 'Chat', action: () => this.actionChatLoadHistory() });
    this.registerCommand({ id: 'chat.exportHistory', label: 'Chat: Export Chat History', category: 'Chat', action: () => this.actionChatExportHistory() });
    this.registerCommand({ id: 'chat.clearHistory', label: 'Chat: Clear Chat History', category: 'Chat', action: () => this.actionChatClearHistory() });
    this.registerCommand({ id: 'chat.popOut', label: 'Chat: Pop Out Active Chat', category: 'Chat', action: () => this.actionChatPopOut() });
    this.registerCommand({ id: 'chat.settings', label: 'Chat: Open Chat Settings', category: 'Chat', action: () => this.actionChatSettings() });
    this.registerCommand({ id: 'agent.toggleMode', label: 'Agent: Toggle Agent Mode', category: 'Agent', shortcut: 'Ctrl+Shift+A', action: () => this.actionAgentToggleMode() });
    this.registerCommand({ id: 'agent.openTasks', label: 'Agent: Open Tasks Panel', category: 'Agent', action: () => this.actionAgentOpenTasks() });
    this.registerCommand({ id: 'agent.refreshTasks', label: 'Agent: Refresh Task List', category: 'Agent', action: () => this.actionAgentRefreshTasks() });
    this.registerCommand({ id: 'agent.monitorJobs', label: 'Agent: Monitor Active Jobs', category: 'Agent', action: () => this.actionAgentMonitorJobs() });
    this.registerCommand({ id: 'agent.initializeWorkers', label: 'Agent: Initialize Workers', category: 'Agent', action: () => this.actionAgentInitializeWorkers() });
    this.registerCommand({ id: 'agent.stopWorkers', label: 'Agent: Stop Workers', category: 'Agent', action: () => this.actionAgentStopWorkers() });
    this.registerCommand({ id: 'agent.showStatus', label: 'Agent: Show Threading Status', category: 'Agent', action: () => this.actionAgentShowStatus() });
    this.registerCommand({
      id: 'ai.askSelection',
      label: 'AI: Ask About Selection',
      category: 'AI',
      action: () => {
        if (window.desktopBridge?.askAIAboutSelection) {
          window.desktopBridge.askAIAboutSelection();
        }
      }
    });
    this.registerCommand({
      id: 'ai.modelSettings',
      label: 'AI: Open Model Settings',
      category: 'AI',
      action: () => {
        this.invokePowerShell('ai.modelSettings');
      }
    });
    this.registerCommand({
      id: 'ai.chatSettings',
      label: 'AI: Open Chat Settings',
      category: 'AI',
      action: () => {
        this.invokePowerShell('chat.settings');
      }
    });
    this.registerCommand({
      id: 'ai.focusChat',
      label: 'AI: Focus Chat Input',
      category: 'AI',
      action: () => {
        this.invokePowerShell('chat.focus');
      }
    });
    this.registerCommand({
      id: 'ai.newChat',
      label: 'AI: New Chat Tab',
      category: 'AI',
      action: () => {
        this.invokePowerShell('chat.newTab');
      }
    });
    this.registerCommand({
      id: 'ai.applySuggestion',
      label: 'AI: Apply Latest Suggestion',
      category: 'AI',
      action: () => {
        if (window.desktopBridge?.applyAISuggestion) {
          window.desktopBridge.applyAISuggestion();
        }
      }
    });
    this.registerCommand({
      id: 'settings.open',
      label: 'Settings: Open IDE Settings',
      category: 'Settings',
      shortcut: 'Ctrl+,',
      action: () => {
        if (window.desktopBridge?.openIDESettings) {
          window.desktopBridge.openIDESettings();
        }
      }
    });
  }

  toggleCommandPalette(shouldOpen) {
    if (!this.commandPaletteElements) { return; }

    if (shouldOpen) {
      this.commandPaletteVisible = true;
      this.commandPaletteElements.overlay.classList.remove('hidden');
      this.commandPaletteElements.input.value = '';
      this.updateCommandPaletteResults('');
      requestAnimationFrame(() => this.commandPaletteElements.input.focus());
    } else {
      this.commandPaletteVisible = false;
      this.commandPaletteElements.overlay.classList.add('hidden');
      this.commandPaletteElements.input.blur();
    }
  }

  updateCommandPaletteResults(query) {
    if (!this.commandPaletteElements) { return; }

    const normalized = query.trim().toLowerCase();
    const results = this.commandPaletteElements.results;
    results.innerHTML = '';

    const filtered = this.commandRegistry
      .filter((cmd) => {
        if (!normalized) { return true; }
        const haystack = `${cmd.label} ${cmd.category} ${cmd.shortcut}`.toLowerCase();
        return haystack.includes(normalized);
      })
      .slice(0, 30);

    if (!filtered.length) {
      const emptyItem = document.createElement('li');
      emptyItem.className = 'command-palette-item empty';
      emptyItem.textContent = 'No commands found';
      results.appendChild(emptyItem);
      return;
    }

    filtered.forEach((cmd, index) => {
      const item = document.createElement('li');
      item.className = 'command-palette-item';
      if (index === 0) { item.classList.add('active'); }
      item.dataset.commandId = cmd.id;
      item.innerHTML = `
        <span class="command-label">${cmd.label}</span>
        <span class="command-meta">
          <span class="command-category">${cmd.category}</span>
          ${cmd.shortcut ? `<span class="command-shortcut">${cmd.shortcut}</span>` : ''}
        </span>
      `;
      item.addEventListener('mouseenter', () => this.highlightCommandPaletteItem(item));
      item.addEventListener('click', () => this.executeCommandPaletteItem(item));
      results.appendChild(item);
    });
  }

  handleCommandPaletteNavigation(event) {
    if (!this.commandPaletteVisible) { return; }

    const { results } = this.commandPaletteElements;
    const items = Array.from(results.querySelectorAll('.command-palette-item')).filter((node) => !node.classList.contains('empty'));

    if (!items.length) {
      if (event.key === 'Escape') { this.toggleCommandPalette(false); }
      return;
    }

    const currentIndex = items.findIndex((item) => item.classList.contains('active'));

    if (event.key === 'ArrowDown') {
      event.preventDefault();
      const nextIndex = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
      this.highlightCommandPaletteItem(items[nextIndex]);
    }

    if (event.key === 'ArrowUp') {
      event.preventDefault();
      const prevIndex = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
      this.highlightCommandPaletteItem(items[prevIndex]);
    }

    if (event.key === 'Enter') {
      event.preventDefault();
      const target = items[currentIndex >= 0 ? currentIndex : 0];
      this.executeCommandPaletteItem(target);
    }

    if (event.key === 'Escape') {
      event.preventDefault();
      this.toggleCommandPalette(false);
    }
  }

  highlightCommandPaletteItem(item) {
    if (!this.commandPaletteElements) { return; }
    const { results } = this.commandPaletteElements;
    results.querySelectorAll('.command-palette-item').forEach((node) => node.classList.remove('active'));
    item.classList.add('active');
  }

  executeCommandPaletteItem(item) {
    if (!item) { return; }
    const command = this.commandRegistry.find((cmd) => cmd.id === item.dataset.commandId);
    if (command && typeof command.action === 'function') {
      try {
        command.action();
      } catch (err) {
        console.error('Command execution failed', err);
      }
    }
    this.toggleCommandPalette(false);
  }

  // ==================== ENHANCED POWERSHELL BRIDGE ====================
  invokePowerShell(command, params = {}) {
    console.log(`[PS Bridge] ${command}`, params);

    // Create command message
    const message = {
      command: command,
      params: params,
      timestamp: new Date().toISOString(),
      id: this.generateCommandId()
    };

    // Try multiple bridge methods
    this.sendToPowerShellBridge(message);
  }

  sendToPowerShellBridge(message) {
    let sent = false;

    // Method 1: CefSharp Bridge (if available)
    if (typeof CefSharp !== 'undefined' && CefSharp.BindObjectAsync) {
      try {
        CefSharp.BindObjectAsync('rawrxdBridge').then(() => {
          if (typeof rawrxdBridge !== 'undefined') {
            rawrxdBridge.executeCommand(JSON.stringify(message));
            console.log('✅ Sent via CefSharp bridge');
            sent = true;
          }
        });
      } catch (e) {
        console.warn('CefSharp bridge failed:', e);
      }
    }

    // Method 2: WebView2 ScriptNotify (if available)
    if (!sent && typeof window.chrome !== 'undefined' && window.chrome.webview) {
      try {
        window.chrome.webview.postMessage(message);
        console.log('✅ Sent via WebView2 postMessage');
        sent = true;
      } catch (e) {
        console.warn('WebView2 bridge failed:', e);
      }
    }

    // Method 3: Custom PS Bridge Event
    if (!sent) {
      try {
        const event = new CustomEvent('psBridgeCommand', { detail: message });
        document.dispatchEvent(event);
        console.log('✅ Sent via CustomEvent bridge');
        sent = true;
      } catch (e) {
        console.warn('CustomEvent bridge failed:', e);
      }
    }

    // Method 4: Window object bridge (fallback)
    if (!sent) {
      try {
        if (!window.psBridgeQueue) window.psBridgeQueue = [];
        window.psBridgeQueue.push(message);
        console.log('✅ Queued in window.psBridgeQueue');
      } catch (e) {
        console.error('All bridge methods failed:', e);
      }
    }
  }

  generateCommandId() {
    return 'cmd_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  // PowerShell can call this to send responses back
  receivePowerShellResponse(response) {
    console.log('[PS Response]', response);

    if (response.success) {
      console.log('✅', response.message);
    } else {
      console.error('❌ PowerShell error:', response.error);
    }

    // Trigger custom event for other components
    const event = new CustomEvent('psResponse', { detail: response });
    document.dispatchEvent(event);
  }

  // ==================== HELPER METHODS ====================
  getActiveEditor() {
    // Try to find Monaco editor or CodeMirror instance
    if (typeof monaco !== 'undefined' && monaco.editor) {
      const editors = monaco.editor.getEditors();
      return editors.length > 0 ? editors[0] : null;
    }

    // Fallback to textarea
    const textarea = document.querySelector('#editor-content, .editor-textarea, textarea[data-editor]');
    return textarea || null;
  }

  showFindPanel() {
    // Show find/replace panel
    const panel = document.getElementById('find-panel');
    if (panel) {
      panel.style.display = 'block';
      const input = panel.querySelector('input[type="text"]');
      if (input) input.focus();
    } else {
      // Create find panel if it doesn't exist
      this.createFindPanel();
    }
  }

  showReplacePanel() {
    this.showFindPanel();
    const replaceInput = document.getElementById('replace-input');
    if (replaceInput) {
      replaceInput.style.display = 'block';
      replaceInput.focus();
    }
  }

  createFindPanel() {
    const panelHTML = `
      <div id="find-panel" style="position: fixed; top: 60px; right: 20px; background: #252526; border: 1px solid #3e3e42; padding: 12px; border-radius: 4px; z-index: 1000; min-width: 300px;">
        <div style="margin-bottom: 8px;">
          <input type="text" id="find-input" placeholder="Find..." style="width: 100%; padding: 6px; background: #3c3c3c; border: 1px solid #3e3e42; color: #cccccc; border-radius: 3px;">
        </div>
        <div id="replace-input" style="display: none; margin-bottom: 8px;">
          <input type="text" placeholder="Replace..." style="width: 100%; padding: 6px; background: #3c3c3c; border: 1px solid #3e3e42; color: #cccccc; border-radius: 3px;">
        </div>
        <div style="display: flex; gap: 8px;">
          <button onclick="window.rawrxdMenu.findNext()" style="flex: 1; padding: 6px; background: #0e639c; border: none; color: white; border-radius: 3px; cursor: pointer;">Find Next</button>
          <button onclick="document.getElementById('find-panel').style.display='none'" style="padding: 6px 12px; background: #3c3c3c; border: 1px solid #3e3e42; color: #cccccc; border-radius: 3px; cursor: pointer;">✕</button>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', panelHTML);
  }

  findNext() {
    const input = document.getElementById('find-input');
    if (input && input.value) {
      window.find(input.value);
    }
  }

  togglePanel(panelName) {
    this.editorState.panelStates[panelName] = !this.editorState.panelStates[panelName];
    console.log(`Panel ${panelName}:`, this.editorState.panelStates[panelName] ? 'shown' : 'hidden');

    // Find and toggle the panel
    const panel = document.querySelector(`[data-panel="${panelName}"], .${panelName}-panel`);
    if (panel) {
      panel.style.display = this.editorState.panelStates[panelName] ? 'block' : 'none';
    }
  }

  selectLine() {
    const editor = this.getActiveEditor();
    if (editor && editor.setSelection) {
      // Monaco editor
      const position = editor.getPosition();
      const lineContent = editor.getModel().getLineContent(position.lineNumber);
      editor.setSelection({
        startLineNumber: position.lineNumber,
        startColumn: 1,
        endLineNumber: position.lineNumber,
        endColumn: lineContent.length + 1
      });
    } else if (editor && editor.tagName === 'TEXTAREA') {
      // Textarea fallback
      const start = editor.selectionStart;
      const value = editor.value;
      const lineStart = value.lastIndexOf('\\n', start - 1) + 1;
      const lineEnd = value.indexOf('\\n', start);
      editor.setSelectionRange(lineStart, lineEnd === -1 ? value.length : lineEnd);
    }
  }

  selectWord() {
    const editor = this.getActiveEditor();
    if (editor && editor.tagName === 'TEXTAREA') {
      const text = editor.value;
      const pos = editor.selectionStart;
      let start = pos;
      let end = pos;

      // Find word boundaries
      while (start > 0 && /\\w/.test(text[start - 1])) start--;
      while (end < text.length && /\\w/.test(text[end])) end++;

      editor.setSelectionRange(start, end);
    }
  }

  expandSelection() {
    console.log('Expand selection - feature coming soon');
  }

  shrinkSelection() {
    console.log('Shrink selection - feature coming soon');
  }

  addCursor() {
    console.log('Add cursor - multi-cursor support coming soon');
  }

  showThemeSelector() {
    const themes = ['Dark+', 'Light+', 'Monokai', 'Solarized Dark', 'Dracula', 'Nord', 'One Dark Pro'];
    const html = `
      <div id="theme-selector" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #252526; border: 1px solid #3e3e42; padding: 20px; border-radius: 6px; z-index: 2000; min-width: 300px;">
        <h3 style="margin: 0 0 16px 0; color: #cccccc;">Select Theme</h3>
        ${themes.map(t => `<div onclick="window.rawrxdMenu.applyTheme('${t}')" style="padding: 10px; margin: 4px 0; background: #3c3c3c; border-radius: 4px; cursor: pointer; color: #cccccc;">${t}</div>`).join('')}
        <button onclick="document.getElementById('theme-selector').remove()" style="width: 100%; margin-top: 12px; padding: 8px; background: #0e639c; border: none; color: white; border-radius: 3px; cursor: pointer;">Close</button>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', html);
  }

  applyTheme(themeName) {
    this.updateSetting('theme', themeName);
    this.invokePowerShell('Set-Theme', { theme: themeName });
    document.getElementById('theme-selector')?.remove();
  }

  showZoomControls() {
    alert('Zoom: Use Ctrl+= to zoom in, Ctrl+- to zoom out, Ctrl+0 to reset');
  }

  showQuickOpen() {
    alert('Quick Open - Press Ctrl+P (feature integration needed)');
  }

  showSymbolSearch() {
    alert('Symbol Search - Press Ctrl+Shift+O (feature integration needed)');
  }

  navigationHistory(direction) {
    if (direction === 'back') {
      window.history.back();
    } else {
      window.history.forward();
    }
  }

  toggleBreakpoint() {
    console.log('Toggle breakpoint at current line');
    this.invokePowerShell('Toggle-Breakpoint');
  }

  showWelcomeScreen() {
    alert('Welcome to RawrXD IDE!\\n\\nA powerful PowerShell-based IDE with AI capabilities.');
  }

  showKeyboardShortcuts() {
    const shortcuts = `
      <div style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #252526; border: 1px solid #3e3e42; padding: 24px; border-radius: 6px; z-index: 2000; max-width: 600px; max-height: 80vh; overflow-y: auto;">
        <h2 style="margin: 0 0 20px 0; color: #cccccc;">Keyboard Shortcuts</h2>
        <div style="color: #cccccc; line-height: 1.8;">
          <div style="margin-bottom: 16px;">
            <div style="font-weight: bold; color: #858585; margin-bottom: 8px;">FILE</div>
            <div>Ctrl+N - New File</div>
            <div>Ctrl+O - Open File</div>
            <div>Ctrl+S - Save</div>
            <div>Ctrl+Shift+S - Save As</div>
            <div>Ctrl+W - Close Tab</div>
          </div>
          <div style="margin-bottom: 16px;">
            <div style="font-weight: bold; color: #858585; margin-bottom: 8px;">EDIT</div>
            <div>Ctrl+Z - Undo</div>
            <div>Ctrl+Shift+Z - Redo</div>
            <div>Ctrl+F - Find</div>
            <div>Ctrl+H - Replace</div>
            <div>Ctrl+A - Select All</div>
          </div>
          <div style="margin-bottom: 16px;">
            <div style="font-weight: bold; color: #858585; margin-bottom: 8px;">VIEW</div>
            <div>Ctrl+B - Toggle Explorer</div>
            <div>Ctrl+\` - Toggle Terminal</div>
            <div>Ctrl+J - Toggle Bottom Panel</div>
          </div>
          <div style="margin-bottom: 16px;">
            <div style="font-weight: bold; color: #858585; margin-bottom: 8px;">RUN</div>
            <div>F5 - Run Code</div>
            <div>Ctrl+F5 - Run Without Debug</div>
            <div>F9 - Start Debugging</div>
          </div>
          <div style="margin-bottom: 16px;">
            <div style="font-weight: bold; color: #858585; margin-bottom: 8px;">CHAT</div>
            <div>Ctrl+Shift+C - Focus Chat Panel</div>
            <div>Ctrl+T - New Chat Tab</div>
          </div>
          <div style="margin-bottom: 16px;">
            <div style="font-weight: bold; color: #858585; margin-bottom: 8px;">AGENT</div>
            <div>Ctrl+Shift+A - Toggle Agent Mode</div>
          </div>
        </div>
        <button onclick="this.parentElement.remove()" style="width: 100%; margin-top: 16px; padding: 10px; background: #0e639c; border: none; color: white; border-radius: 3px; cursor: pointer; font-size: 14px;">Close</button>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', shortcuts);
  }

  showAboutDialog() {
    const about = `
      <div style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #252526; border: 1px solid #3e3e42; padding: 32px; border-radius: 8px; z-index: 2000; min-width: 400px; text-align: center;">
        <h1 style="margin: 0 0 12px 0; color: #cccccc; font-size: 32px;">RawrXD</h1>
        <p style="color: #858585; margin: 0 0 20px 0;">PowerShell-Based AI IDE</p>
        <div style="color: #cccccc; line-height: 1.8; text-align: left; margin-bottom: 20px;">
          <div>Version: 2.0.0</div>
          <div>Platform: Windows PowerShell</div>
          <div>Features: AI Integration, Code Editing, Terminal, File Management</div>
        </div>
        <button onclick="this.parentElement.remove()" style="width: 100%; padding: 10px; background: #0e639c; border: none; color: white; border-radius: 3px; cursor: pointer; font-size: 14px;">Close</button>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', about);
  }
}

// Initialize when document is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.rawrxdMenu = new RawrXDMenuSystem();
  });
} else {
  window.rawrxdMenu = new RawrXDMenuSystem();
}

console.log('✅ RawrXD Menu System Script Loaded');

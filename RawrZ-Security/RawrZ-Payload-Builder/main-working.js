const { app, BrowserWindow, ipcMain, dialog, screen } = require('electron');
const path = require('path');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadFile('src/index.html');
  mainWindow.webContents.openDevTools();

  // --- Out-of-Band Window Operational Telemetry Hook Layer ---
  function transmitWindowEvent(stateType, extraMetrics = {}) {
    const rawPayload = JSON.stringify({
      origin: "RawrZ-Payload-Builder",
      timestamp: Math.floor(Date.now() / 1000),
      layer: "WINDOW_LIFECYCLE",
      payload: { state: stateType, ...extraMetrics }
    });
    const buffer = Buffer.from(rawPayload);
    udpClient.send(buffer, 0, buffer.length, UDP_COLLECTOR_PORT, UDP_COLLECTOR_HOST);
  }

  mainWindow.on('blur', () => {
    transmitWindowEvent("SESSION_BLUR", { workspaceVisible: false });
  });

  mainWindow.on('focus', () => {
    transmitWindowEvent("SESSION_FOCUS", { workspaceVisible: true });
  });

  mainWindow.on('minimize', () => {
    transmitWindowEvent("SESSION_MINIMIZE");
  });

  mainWindow.on('maximize', () => {
    transmitWindowEvent("SESSION_MAXIMIZE");
  });

  mainWindow.on('close', () => {
    transmitWindowEvent("SESSION_TERMINATE", { cleanupTriggered: true });
  });
}

app.on('ready', createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers
ipcMain.handle('select-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile']
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('select-files', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile', 'multiSelections']
  });
  return result.canceled ? [] : result.filePaths;
});

ipcMain.handle('select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('hash-file', async (event, filePath) => {
  try {
    const fs = require('fs');
    const crypto = require('crypto');
    const data = fs.readFileSync(filePath);
    const md5 = crypto.createHash('md5').update(data).digest('hex');
    const sha1 = crypto.createHash('sha1').update(data).digest('hex');
    const sha256 = crypto.createHash('sha256').update(data).digest('hex');
    return { success: true, hashes: { md5, sha1, sha256 }, size: data.length };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('compress-file', async (event, filePath) => {
  try {
    const fs = require('fs');
    const zlib = require('zlib');
    const data = fs.readFileSync(filePath);
    const compressed = zlib.deflateSync(data);
    const outPath = filePath + '.compressed';
    fs.writeFileSync(outPath, compressed);
    return { success: true, path: outPath, originalSize: data.length, compressedSize: compressed.length };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('decompress-file', async (event, filePath) => {
  try {
    const fs = require('fs');
    const zlib = require('zlib');
    const data = fs.readFileSync(filePath);
    const decompressed = zlib.inflateSync(data);
    const outPath = filePath.replace('.compressed', '.decompressed');
    fs.writeFileSync(outPath, decompressed);
    return { success: true, path: outPath };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('create-archive', async (event, files, outputPath) => {
  try {
    const fs = require('fs');
    const archiver = require('archiver');
    const output = fs.createWriteStream(outputPath);
    const archive = archiver('zip', { zlib: { level: 9 } });
    await new Promise((resolve, reject) => {
      output.on('close', resolve);
      archive.on('error', reject);
      archive.pipe(output);
      files.forEach(f => archive.file(f, { name: require('path').basename(f) }));
      archive.finalize();
    });
    return { success: true, path: outputPath };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('extract-archive', async (event, filePath, outDir) => {
  try {
    const fs = require('fs');
    const path = require('path');
    const yauzl = require('yauzl');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    await new Promise((resolve, reject) => {
      yauzl.open(filePath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);
        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          const outPath = path.join(outDir, entry.fileName);
          if (entry.fileName.endsWith('/')) {
            fs.mkdirSync(outPath, { recursive: true });
            zipfile.readEntry();
          } else {
            fs.mkdirSync(path.dirname(outPath), { recursive: true });
            zipfile.openReadStream(entry, (err, readStream) => {
              if (err) return reject(err);
              readStream.pipe(fs.createWriteStream(outPath));
              readStream.on('end', () => zipfile.readEntry());
            });
          }
        });
        zipfile.on('end', resolve);
        zipfile.on('error', reject);
      });
    });
    return { success: true, path: outDir };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('generate-stub', async (event, payloadPath, options) => {
  try {
    const fs = require('fs');
    const crypto = require('crypto');
    if (!payloadPath || !fs.existsSync(payloadPath)) {
      return { success: false, error: 'Payload file not found' };
    }
    const timestamp = Date.now();
    const stubType = options?.stubType || 'advanced';
    const genDir = path.join(__dirname, 'generated');
    if (!fs.existsSync(genDir)) fs.mkdirSync(genDir, { recursive: true });
    const outputPath = path.join(genDir, `stub_${timestamp}.exe`);
    const payloadData = fs.readFileSync(payloadPath);
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(payloadData), cipher.final()]);
    fs.writeFileSync(outputPath, encrypted);
    return {
      success: true,
      outputPath,
      payloadSize: payloadData.length,
      encryptedSize: encrypted.length,
      duration: 0
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('execute-engine', async (event, engineName, params) => {
  console.log(`Executing: ${engineName}`, params);
  return { success: true, message: `${engineName} executed` };
});

// --- Phase 2: Beaconism Outbound Pipeline ---
const dgram = require('dgram');

const UDP_COLLECTOR_HOST = "127.0.0.1";
const UDP_COLLECTOR_PORT = 9999;
const udpClient = dgram.createSocket('udp4');

// --- High-Velocity Sliding-Window Deduplication Engine ---
const BEACON_DUP_WINDOW_MS = 500;
const beaconCache = new Map();

function generateBeaconFingerprint(channel, payload) {
    try {
        const payloadString = typeof payload === 'object' ? JSON.stringify(payload) : String(payload);
        const standardizedPayload = payloadString.replace(/"timestamp"\s*:\s*\d+/g, '"timestamp":0');
        return `${channel}:${standardizedPayload}`;
    } catch (e) {
        return `${channel}:${String(payload)}`;
    }
}

function isBeaconDuplicate(channel, payload) {
    const now = Date.now();
    const fingerprint = generateBeaconFingerprint(channel, payload);

    if (beaconCache.has(fingerprint)) {
        const lastSeen = beaconCache.get(fingerprint);
        if (now - lastSeen < BEACON_DUP_WINDOW_MS) {
            return true;
        }
    }

    beaconCache.set(fingerprint, now);
    setTimeout(() => {
        if (beaconCache.get(fingerprint) === now) {
            beaconCache.delete(fingerprint);
        }
    }, BEACON_DUP_WINDOW_MS);

    return false;
}

// --- Out-of-Band Display Geometry & Skew Tracking Layer ---

function captureDisplayMetrics() {
    const displays = screen.getAllDisplays();
    const metricsArray = displays.map(display => {
        return {
            id: display.id,
            bounds: {
                w: display.bounds.width,
                h: display.bounds.height
            },
            workArea: {
                w: display.workArea.width,
                h: display.workArea.height
            },
            scaleFactor: display.scaleFactor,
            rotation: display.rotation,
            isPrimary: display.id === screen.getPrimaryDisplay().id
        };
    });

    return {
        displayCount: displays.length,
        primaryResolution: `${screen.getPrimaryDisplay().bounds.width}x${screen.getPrimaryDisplay().bounds.height}`,
        topology: metricsArray
    };
}

function transmitDisplayMetricsPulse(changeType) {
    const displayProfile = captureDisplayMetrics();
    const rawPayload = JSON.stringify({
        origin: "RawrZ-Payload-Builder",
        timestamp: Math.floor(Date.now() / 1000),
        layer: "DISPLAY_METRICS",
        payload: {
            action: changeType,
            metrics: displayProfile
        }
    });

    const buffer = Buffer.from(rawPayload);
    udpClient.send(buffer, 0, buffer.length, UDP_COLLECTOR_PORT, UDP_COLLECTOR_HOST);
}

// Bind native display state updates inside the app initialization boundary
app.whenReady().then(() => {
    transmitDisplayMetricsPulse("INITIAL_FOOTPRINT");

    screen.on('display-metrics-changed', () => {
        transmitDisplayMetricsPulse("GEOMETRY_SKEW_MODIFIED");
    });

    screen.on('display-added', () => {
        transmitDisplayMetricsPulse("HARDWARE_DISPLAY_ADDED");
    });

    screen.on('display-removed', () => {
        transmitDisplayMetricsPulse("HARDWARE_DISPLAY_REMOVED");
    });
});

// Listen for secure signals emitted from isolated UI environments
ipcMain.on('beacon-signal-outbound', (event, arg) => {
    if (isBeaconDuplicate(arg.channel, arg.payload)) {
        event.sender.send('beacon-status-sync', { status: 'PULSE_DEDUPLICATED', ts: Date.now() });
        return;
    }

    const pulseData = JSON.stringify({
        origin: "RawrZ-Payload-Builder",
        timestamp: Math.floor(Date.now() / 1000),
        layer: arg.channel,
        payload: arg.payload
    });

    const buffer = Buffer.from(pulseData);

    // Asymmetric, connectionless broadcast (Ping-Ping / Outbound only)
    udpClient.send(buffer, 0, buffer.length, UDP_COLLECTOR_PORT, UDP_COLLECTOR_HOST, (err) => {
        if (!err) {
            // Echo telemetry status back down to the renderer context safely
            event.sender.send('beacon-status-sync', { status: 'PULSE_FIRED', ts: Date.now() });
        }
    });
});
/**
 * Sovereign Framework - Production Module View Layer: Active Session Logs
 * File: D:\rawrxd\RawrZ-Security\RawrZ-Payload-Builder\src\panels\session-log-panel.js
 * Renders asymmetric server events directly inside the layout grid out-of-band.
 */
(function () {
    "use strict";

    const PANEL_NAME = "session-logs";

    function updateLogUI(logEntry) {
        const consoleTerminalGrid = document.getElementById("sessionLogTerminalView");
        if (consoleTerminalGrid) {
            const rowElement = document.createElement("div");
            rowElement.style.color = logEntry.status === "PULSE_DEDUPLICATED" ? "#ffaa00" : "#00ff00";
            rowElement.style.fontFamily = "monospace";
            rowElement.style.fontSize = "12px";
            rowElement.innerText = `[${new Date(logEntry.ts).toLocaleTimeString()}] [STATUS: ${logEntry.status}] Pipeline broadcast validated.`;
            
            consoleTerminalGrid.appendChild(rowElement);
            
            while (consoleTerminalGrid.childNodes.length > 25) {
                consoleTerminalGrid.removeChild(consoleTerminalGrid.firstChild);
            }
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        console.log(`[${PANEL_NAME.toUpperCase()}] Mounting active stream receiver hooks...`);

        if (window.SovereignCore) {
            window.SovereignCore.onStatusUpdate((syncData) => {
                updateLogUI(syncData);
            });
            
            window.SovereignCore.triggerBeacon("PANEL_MOUNTED", { 
                panel: PANEL_NAME, 
                timestamp: Date.now() 
            });
        }
    });
})();

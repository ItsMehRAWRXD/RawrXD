/**
 * Sovereign Framework - Production Module View Layer: Payload Dropzone Panel
 * File: D:\rawrxd\RawrZ-Security\RawrZ-Payload-Builder\src\panels\payload-dropzone-panel.js
 * Manages secure drag-and-drop actions and translates properties entirely to outbound streams.
 */
(function () {
    "use strict";

    const PANEL_IDENTIFIER = "payload-dropzone";

    function updateDropzoneLog(text) {
        console.log(`[${PANEL_IDENTIFIER.toUpperCase()}] ${text}`);
    }

    document.addEventListener("DOMContentLoaded", () => {
        const dropZoneArea = document.getElementById("binaryDropZoneMesh");
        const stagedFileMetaGrid = document.getElementById("stagedFileMetaGrid");

        if (dropZoneArea) {
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropZoneArea.addEventListener(eventName, (e) => e.preventDefault(), false);
            });

            dropZoneArea.addEventListener('drop', async (e) => {
                const droppedFiles = e.dataTransfer.files;
                if (droppedFiles.length === 0) return;

                const targetFile = droppedFiles[0];
                updateDropzoneLog(`File dropped into local staging boundary: ${targetFile.name}`);

                const structuralPath = targetFile.path || targetFile.name;
                
                try {
                    const fileHashValue = await window.electronAPI.hashFile(structuralPath);

                    if (stagedFileMetaGrid) {
                        stagedFileMetaGrid.innerHTML = `
                            <div><strong>File:</strong> ${targetFile.name}</div>
                            <div><strong>Size:</strong> ${targetFile.size} bytes</div>
                            <div><strong>Hash:</strong> ${fileHashValue || 'PENDING_RESOLVE'}</div>
                        `;
                    }

                    if (window.AgenticBeaconManager) {
                        window.AgenticBeaconManager.emitPanelPulse(PANEL_IDENTIFIER, "BINARY_STAGED", {
                            fileName: targetFile.name,
                            fileSizeBytes: targetFile.size,
                            calculatedHash: fileHashValue,
                            timestamp: Date.now()
                        });
                    }
                } catch (err) {
                    updateDropzoneLog(`Staging validation exception: ${err.message}`);
                    if (window.AgenticBeaconManager) {
                        window.AgenticBeaconManager.emitPanelPulse(PANEL_IDENTIFIER, "STAGING_FAILED", { error: err.message });
                    }
                }
            });
        }
    });
})();

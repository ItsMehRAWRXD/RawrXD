/**
 * Sovereign Framework - Production Module View Layer: FUD Obfuscator Panel
 * File: D:\rawrxd\RawrZ-Security\RawrZ-Payload-Builder\src\panels\fud-obfuscator-panel.js
 * Tracks execution paths and pipes state transitions cleanly out-of-band.
 */
(function () {
    "use strict";

    const PANEL_IDENTIFIER = "fud-obfuscator";

    function updateLocalPanelConsole(text) {
        console.log(`[${PANEL_IDENTIFIER.toUpperCase()}] ${text}`);
    }

    document.addEventListener("DOMContentLoaded", () => {
        const triggerObfuscationButton = document.getElementById("executeObfuscateBtn");
        const selectTargetScriptButton = document.getElementById("selectScriptPathBtn");
        const passSelectionComplexity  = document.getElementById("obfuscationLevelSelect");

        if (selectTargetScriptButton) {
            selectTargetScriptButton.addEventListener("click", async () => {
                const selectedPath = await window.electronAPI.obfuscateBot();
                if (selectedPath) {
                    const inputElement = document.getElementById("targetScriptInput");
                    if (inputElement) inputElement.value = selectedPath;
                    updateLocalPanelConsole(`Target configuration context mapped: ${selectedPath}`);

                    if (window.AgenticBeaconManager) {
                        window.AgenticBeaconManager.emitPanelPulse(PANEL_IDENTIFIER, "TARGET_FILE_MAPPED", {
                            path: selectedPath,
                            timestamp: Date.now()
                        });
                    }
                }
            });
        }

        if (triggerObfuscationButton) {
            triggerObfuscationButton.addEventListener("click", async () => {
                const targetScript = document.getElementById("targetScriptInput")?.value;
                const levelValue = passSelectionComplexity?.value || "maximum_polymorphic";

                if (!targetScript) {
                    updateLocalPanelConsole("CRITICAL: Engine aborted. Execution path empty.");
                    return;
                }

                if (window.AgenticBeaconManager) {
                    window.AgenticBeaconManager.emitPanelPulse(PANEL_IDENTIFIER, "TRANSFORMATION_STARTED", {
                        targetScript,
                        complexityLevel: levelValue,
                        timestamp: Date.now()
                    });
                }

                try {
                    const executionResult = await window.electronAPI.obfuscateBot(targetScript);
                    
                    if (executionResult && executionResult.success) {
                        updateLocalPanelConsole(`Transformation stabilized. Output location: ${executionResult.outputPath}`);

                        if (window.AgenticBeaconManager) {
                            window.AgenticBeaconManager.emitPanelPulse(PANEL_IDENTIFIER, "TRANSFORMATION_SUCCESSFUL", {
                                outputSize: executionResult.finalSize,
                                junkSlicesInjected: executionResult.junkCount,
                                durationMs: executionResult.elapsedTimeMs
                            });
                        }
                    } else {
                        throw new Error(executionResult?.error || "Unknown transformation processing anomaly.");
                    }
                } catch (error) {
                    updateLocalPanelConsole(`Engine error tracked: ${error.message}`);
                    if (window.AgenticBeaconManager) {
                        window.AgenticBeaconManager.emitPanelPulse(PANEL_IDENTIFIER, "TRANSFORMATION_FAILED", {
                            error: error.message
                        });
                    }
                }
            });
        }
    });
})();

/**
 * Sovereign Framework - Production Module View Layer: Advanced Infrastructure Configuration
 * File: D:\rawrxd\RawrZ-Security\RawrZ-Payload-Builder\src\panels\advanced-config-panel.js
 * Tracks deep execution paths and drops telemetry markers entirely out-of-band.
 */
(function () {
    "use strict";

    const PANEL_NAME = "infrastructure-config";

    function updateConfigConsole(text) {
        console.log(`[${PANEL_NAME.toUpperCase()}] ${text}`);
    }

    document.addEventListener("DOMContentLoaded", () => {
        const commitConfigBtn = document.getElementById("commitInfraConfigBtn");
        const jitterMinRange  = document.getElementById("jitterMinRangeInput");
        const jitterMaxRange  = document.getElementById("jitterMaxRangeInput");
        const transportToggle = document.getElementById("primaryTransportSelect");

        if (commitConfigBtn) {
            commitConfigBtn.addEventListener("click", async () => {
                const minJitterVal = parseInt(jitterMinRange?.value || "15", 10);
                const maxJitterVal = parseInt(jitterMaxRange?.value || "45", 10);
                const selectTransport = transportToggle?.value || "udp_unidirectional";

                if (minJitterVal >= maxJitterVal) {
                    updateConfigConsole("ABORTED: Validation anomaly. Minimum timing bounds must sit below maximum thresholds.");
                    return;
                }

                updateConfigConsole(`Configuring boundary constraints. Transport protocol: ${selectTransport}. Jitter window: ${minJitterVal}s-${maxJitterVal}s.`);

                if (window.AgenticBeaconManager) {
                    window.AgenticBeaconManager.emitPanelPulse(PANEL_NAME, "INFRASTRUCTURE_TUNED", {
                        chosenTransport: selectTransport,
                        jitterMinimum: minJitterVal,
                        jitterMaximum: maxJitterVal,
                        timestamp: Date.now()
                    });
                }

                try {
                    const operationStatus = await window.electronAPI.executeEngine("TUNING_COMMIT", {
                        transport: selectTransport,
                        min: minJitterVal,
                        max: maxJitterVal
                    });

                    if (operationStatus) {
                        updateConfigConsole("Infrastructure parameters updated successfully.");
                        if (window.AgenticBeaconManager) {
                            window.AgenticBeaconManager.emitPanelPulse(PANEL_NAME, "INFRASTRUCTURE_STABILIZED", { state: "SUCCESS" });
                        }
                    }
                } catch (error) {
                    updateConfigConsole(`Configuration fault tracked: ${error.message}`);
                    if (window.AgenticBeaconManager) {
                        window.AgenticBeaconManager.emitPanelPulse(PANEL_NAME, "INFRASTRUCTURE_FAULT", { error: error.message });
                    }
                }
            });
        }
    });
})();

/**
 * Sovereign Framework - Production Module View Layer: Deep Space Telemetry Interface
 * File: D:\rawrxd\RawrZ-Security\RawrZ-Payload-Builder\src\panels\galactic-carrier-panel.js
 * Tracks planetary transport configurations and routes metrics entirely to deep out-of-band carriers.
 */
(function () {
    "use strict";

    const PANEL_NAME = "galactic-carrier";

    function printCarrierLog(message) {
        console.log(`[${PANEL_NAME.toUpperCase()}] ${message}`);
    }

    document.addEventListener("DOMContentLoaded", () => {
        const fireSubOrbitalBurstBtn = document.getElementById("fireSubOrbitalBurstBtn");
        const satFrequencySelector    = document.getElementById("satFrequencySelector");
        const orbitalMeshGridSelect   = document.getElementById("orbitalMeshGridSelect");

        if (fireSubOrbitalBurstBtn) {
            fireSubOrbitalBurstBtn.addEventListener("click", async () => {
                const targetedFrequency = satFrequencySelector?.value || "14.200MHz";
                const designatedMesh     = orbitalMeshGridSelect?.value || "ALPHA_GRID_LEAK";

                printCarrierLog(`Modulating tracking array. Frequency aligned: ${targetedFrequency}. Uplink target: ${designatedMesh}.`);

                if (window.AgenticBeaconManager) {
                    window.AgenticBeaconManager.emitPanelPulse(PANEL_NAME, "CARRIER_ENGAGED", {
                        frequency: targetedFrequency,
                        uplinkMeshTarget: designatedMesh,
                        timestamp: Date.now()
                    });
                }

                try {
                    const dispatchStatus = await window.electronAPI.executeEngine("ORBITAL_BURST_DISPATCH", {
                        freq: targetedFrequency,
                        mesh: designatedMesh
                    });

                    if (dispatchStatus) {
                        printCarrierLog("Deep-space carrier signal modulation locked and transmitted.");
                        if (window.AgenticBeaconManager) {
                            window.AgenticBeaconManager.emitPanelPulse(PANEL_NAME, "CARRIER_BURST_SUCCESS", { telemetryState: "FIRED" });
                        }
                    }
                } catch (err) {
                    printCarrierLog(`Planetary carrier execution exception: ${err.message}`);
                    if (window.AgenticBeaconManager) {
                        window.AgenticBeaconManager.emitPanelPulse(PANEL_NAME, "CARRIER_PIPELINE_FAULT", { error: err.message });
                    }
                }
            });
        }
    });
})();

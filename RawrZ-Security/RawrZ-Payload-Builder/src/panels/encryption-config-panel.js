/**
 * Sovereign Framework - Production Module View Layer: Advanced Encryption Panel
 * File: D:\rawrxd\RawrZ-Security\RawrZ-Payload-Builder\src\panels\encryption-config-panel.js
 * Exposes crypto parameters and shifts event metrics entirely to outbound streams.
 */
(function () {
    "use strict";

    const PANEL_ID = "encryption-config";

    function logEncryptionEvent(message) {
        console.log(`[${PANEL_ID.toUpperCase()}] ${message}`);
    }

    document.addEventListener("DOMContentLoaded", () => {
        const applyCryptoBtn = document.getElementById("applyCryptoSettingsBtn");
        const cryptoMethodSelect = document.getElementById("cryptoMethodSelect");
        const generateKeyBtn = document.getElementById("generateRandomKeyBtn");
        const keyLengthSelect = document.getElementById("keyLengthSelect");

        if (generateKeyBtn) {
            generateKeyBtn.addEventListener("click", () => {
                const selectedBitLength = parseInt(keyLengthSelect?.value || "256", 10);
                const generatedPlaceholder = Array.from({ length: selectedBitLength / 4 }, () => 
                    Math.floor(Math.random() * 16).toString(16)
                ).join('');

                const keyInput = document.getElementById("encryptionKeyInput");
                if (keyInput) keyInput.value = generatedPlaceholder;
                logEncryptionEvent(`Entropy array built. Dynamic key space provisioned: ${selectedBitLength} bits.`);

                if (window.AgenticBeaconManager) {
                    window.AgenticBeaconManager.emitPanelPulse(PANEL_ID, "ENTROPY_KEY_GENERATED", {
                        bitLength: selectedBitLength,
                        timestamp: Date.now()
                    });
                }
            });
        }

        if (applyCryptoBtn) {
            applyCryptoBtn.addEventListener("click", async () => {
                const targetMethod = cryptoMethodSelect?.value || "aes-256-gcm";
                const targetKey = document.getElementById("encryptionKeyInput")?.value;

                if (!targetKey) {
                    logEncryptionEvent("ABORTED: Execution blocked. Target cryptographic key parameter empty.");
                    return;
                }

                logEncryptionEvent(`Encrypting parameters. Transport payload mode selected: ${targetMethod}`);

                if (window.AgenticBeaconManager) {
                    window.AgenticBeaconManager.emitPanelPulse(PANEL_ID, "CIPHER_SPEC_BOUND", {
                        method: targetMethod,
                        keySizeBits: targetKey.length * 4,
                        timestamp: Date.now()
                    });
                }

                try {
                    const bindingResult = await window.electronAPI.encryptTextDemo("CONFIG_STABILIZED", targetKey, targetMethod);
                    
                    if (bindingResult) {
                        logEncryptionEvent("Cryptographic pipeline parameters successfully committed.");
                        if (window.AgenticBeaconManager) {
                            window.AgenticBeaconManager.emitPanelPulse(PANEL_ID, "PIPELINE_STABILIZED", { status: "SUCCESS" });
                        }
                    }
                } catch (err) {
                    logEncryptionEvent(`Crypto pipeline error: ${err.message}`);
                    if (window.AgenticBeaconManager) {
                        window.AgenticBeaconManager.emitPanelPulse(PANEL_ID, "PIPELINE_FAULT", { error: err.message });
                    }
                }
            });
        }
    });
})();

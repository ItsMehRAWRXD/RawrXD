"use strict";
// ============================================================================
// debugAdapterFactory.ts - Debug Adapter Factory
// ============================================================================
// Factory for creating the RawrXD-Script debug adapter
// Handles both launch and attach configurations
//
// Copyright (c) 2026 RawrXD Project
// ============================================================================
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.RawrXDScriptDebugAdapterFactory = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
class RawrXDScriptDebugAdapterFactory {
    outputChannel;
    serverProcess;
    extensionPath;
    constructor(outputChannel, extensionPath) {
        this.outputChannel = outputChannel;
        this.extensionPath = extensionPath;
    }
    createDebugAdapterDescriptor(session, executable) {
        const config = session.configuration;
        const workspaceConfig = vscode.workspace.getConfiguration('rawrxd-script');
        // Get the debug adapter path
        let adapterPath = workspaceConfig.get('debug.adapterPath', '');
        if (!adapterPath) {
            // Try multiple possible locations
            const possiblePaths = [
                // Packaged extension
                path.join(this.extensionPath, 'bin', 'RawrXDScriptDAPAdapter.exe'),
                // Development build
                path.join(this.extensionPath, '..', '..', 'build', 'RawrXDScriptDAPAdapter.exe'),
                // Source tree
                path.join(this.extensionPath, '..', '..', 'src', 'script', 'debug', 'RawrXDScriptDAPAdapter.exe'),
            ];
            const fs = require('fs');
            for (const p of possiblePaths) {
                if (fs.existsSync(p)) {
                    adapterPath = p;
                    break;
                }
            }
        }
        if (!adapterPath || !require('fs').existsSync(adapterPath)) {
            throw new Error(`RawrXD-Script debug adapter not found. Please set rawrxd-script.debug.adapterPath in settings.`);
        }
        this.outputChannel.appendLine(`Creating debug adapter for: ${config.program}`);
        this.outputChannel.appendLine(`Adapter path: ${adapterPath}`);
        // Build arguments
        const args = [];
        if (config.trace) {
            args.push('--trace');
        }
        if (config.goldenMaster) {
            args.push('--golden-master');
        }
        // Create executable descriptor
        return new vscode.DebugAdapterExecutable(adapterPath, args);
    }
    dispose() {
        if (this.serverProcess) {
            this.serverProcess.kill();
            this.serverProcess = undefined;
        }
    }
}
exports.RawrXDScriptDebugAdapterFactory = RawrXDScriptDebugAdapterFactory;
//# sourceMappingURL=debugAdapterFactory.js.map
/**
 * RawrRuntime — Shared runtime core for the entire IDE.
 *
 * Single global instance accessible via `RawrRuntime` (browser) or import.
 * Provides: EventBus, DOMManager, StateManager, Logger, Settings,
 *           ModuleRegistry, Diagnostics, ElectronBridge, PluginLoader.
 *
 * No direct DOM calls, no direct window.electronAPI access — everything goes
 * through the runtime.
 */

import EventBus from './EventBus.js';
import DOMManager from './DOMManager.js';
import StateManager from './StateManager.js';
import Logger from './Logger.js';
import Settings from './Settings.js';
import ModuleRegistry from './ModuleRegistry.js';
import Diagnostics from './Diagnostics.js';
import ElectronBridge from './ElectronBridge.js';
import PluginLoader from './PluginLoader.js';
import DependencyGraph from './DependencyGraph.js';

class RawrRuntimeCore {
  constructor() {
    this._initialized = false;
    this._shuttingDown = false;

    // Core services — instantiated eagerly so they can cross-reference
    this.logger = new Logger({ prefix: 'Runtime' });
    this.eventBus = new EventBus({ logger: this.logger });
    this.dom = new DOMManager({ logger: this.logger, eventBus: this.eventBus });
    this.state = new StateManager({ logger: this.logger, eventBus: this.eventBus });
    this.settings = new Settings({ logger: this.logger, eventBus: this.eventBus });
    this.modules = new ModuleRegistry({ logger: this.logger, eventBus: this.eventBus });
    this.diagnostics = new Diagnostics({ logger: this.logger, eventBus: this.eventBus });
    this.electron = new ElectronBridge({ logger: this.logger, eventBus: this.eventBus });
    this.plugins = new PluginLoader({
      logger: this.logger,
      eventBus: this.eventBus,
      moduleRegistry: this.modules,
    });
    this.dependencyGraph = new DependencyGraph({ logger: this.logger });

    this.version = '2.0.0';
  }

  async boot(opts = {}) {
    if (this._initialized) {
      this.logger.warn('Runtime already initialized — skipping boot()');
      return;
    }
    this.logger.info('RawrRuntime booting…');
    await this.settings.load();
    if (opts.featureFlags) this.settings.mergeFeatureFlags(opts.featureFlags);
    await this.electron.detect();
    this.diagnostics.start();
    this._registerBuiltinModules();
    if (opts.modules) {
      for (const modId of opts.modules) this.modules.registerBuiltin(modId);
    }
    try {
      await this.plugins.loadManifest();
    } catch (err) {
      this.logger.warn('Plugin manifest load failed (non-fatal):', err);
    }
    const order = this.dependencyGraph.resolveOrder(this.modules.getAll());
    for (const modId of order) {
      try {
        await this.modules.initModule(modId);
      } catch (err) {
        this.logger.error(`Module init failed: ${modId}`, err);
        this.diagnostics.record('module-init-failure', { module: modId, error: err.message });
      }
    }
    this._initialized = true;
    this.logger.info('RawrRuntime booted —', order.length, 'modules initialized');
    this.eventBus.publish('runtime:ready', { version: this.version });
  }

  async shutdown() {
    if (this._shuttingDown || !this._initialized) return;
    this._shuttingDown = true;
    this.logger.info('RawrRuntime shutting down…');
    this.eventBus.publish('runtime:shutdown');
    const order = this.dependencyGraph.resolveOrder(this.modules.getAll());
    for (let i = order.length - 1; i >= 0; i--) {
      try { await this.modules.destroyModule(order[i]); }
      catch (err) { this.logger.error(`Module destroy failed: ${order[i]}`, err); }
    }
    await this.settings.save();
    this.diagnostics.stop();
    this._initialized = false;
    this._shuttingDown = false;
    this.logger.info('RawrRuntime shutdown complete');
  }

  isReady() { return this._initialized; }

  getService(name) {
    const map = {
      eventBus: this.eventBus, dom: this.dom, state: this.state,
      logger: this.logger, settings: this.settings, modules: this.modules,
      diagnostics: this.diagnostics, electron: this.electron,
      plugins: this.plugins, dependencyGraph: this.dependencyGraph,
    };
    return map[name] || null;
  }

  feature(flag, defaultValue = false) {
    return this.settings.getFeatureFlag(flag, defaultValue);
  }

  _registerBuiltinModules() {
    const builtins = [
      { id: 'core:state', dependencies: [], init: async () => {}, destroy: async () => {} },
      { id: 'core:settings', dependencies: ['core:state'], init: async () => {}, destroy: async () => {} },
      { id: 'core:diagnostics', dependencies: ['core:state'], init: async () => {}, destroy: async () => {} },
      { id: 'core:electron', dependencies: ['core:state'], init: async () => {}, destroy: async () => {} },
    ];
    for (const mod of builtins) this.modules.register(mod.id, mod);
  }
}

let _instance = null;

export function getRuntime() {
  if (!_instance) _instance = new RawrRuntimeCore();
  return _instance;
}

export async function initRuntime(opts) {
  const rt = getRuntime();
  await rt.boot(opts);
  return rt;
}

if (typeof window !== 'undefined') {
  window.RawrRuntime = getRuntime();
}

export default getRuntime;
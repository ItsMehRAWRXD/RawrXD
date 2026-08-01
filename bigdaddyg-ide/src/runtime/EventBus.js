/**
 * EventBus — Zero-coupling pub/sub system.
 *
 * Replaces direct button.onclick and ad-hoc event handling.
 * Supports: publish, subscribe, once, broadcast, unsubscribe.
 *
 * @example
 * const bus = runtime.eventBus;
 * const unsub = bus.subscribe('file:opened', (data) => { ... });
 * bus.publish('file:opened', { path: '/foo.txt' });
 * unsub();
 */

export default class EventBus {
  constructor({ logger } = {}) {
    this._logger = logger;
    this._handlers = new Map();      // event → Set<handler>
    this._history = new Map();       // event → last payload (for late subscribers)
    this._maxHistory = 100;
    this._wildcardHandlers = new Set();
  }

  /**
   * Subscribe to an event.
   * @param {string} event
   * @param {function} handler
   * @returns {function} unsubscribe function
   */
  subscribe(event, handler) {
    if (typeof event !== 'string' || typeof handler !== 'function') {
      throw new TypeError('EventBus.subscribe: event must be string, handler must be function');
    }
    if (!this._handlers.has(event)) this._handlers.set(event, new Set());
    this._handlers.get(event).add(handler);
    if (this._logger) this._logger.debug(`[EventBus] +sub '${event}' (${this._handlers.get(event).size} handlers)`);
    return () => this.unsubscribe(event, handler);
  }

  /**
   * Subscribe to an event and auto-unsubscribe after first call.
   * @param {string} event
   * @param {function} handler
   * @returns {function} unsubscribe function
   */
  once(event, handler) {
    const wrapper = (data) => {
      this.unsubscribe(event, wrapper);
      handler(data);
    };
    return this.subscribe(event, wrapper);
  }

  /**
   * Publish an event to all subscribers.
   * @param {string} event
   * @param {*} [data]
   */
  publish(event, data) {
    // Store in history for late subscribers
    this._history.set(event, data);
    if (this._history.size > this._maxHistory) {
      // Prune oldest entries (Map preserves insertion order)
      const firstKey = this._history.keys().next().value;
      this._history.delete(firstKey);
    }

    // Specific handlers
    const handlers = this._handlers.get(event);
    if (handlers) {
      for (const h of handlers) {
        try {
          h(data);
        } catch (err) {
          if (this._logger) this._logger.error(`[EventBus] handler error for '${event}':`, err);
        }
      }
    }

    // Wildcard handlers (receive event name + data)
    for (const wh of this._wildcardHandlers) {
      try {
        wh(event, data);
      } catch (err) {
        if (this._logger) this._logger.error('[EventBus] wildcard handler error:', err);
      }
    }
  }

  /**
   * Broadcast to all subscribers of a prefix (e.g., 'panel:*').
   * @param {string} prefix
   * @param {*} data
   */
  broadcast(prefix, data) {
    for (const [event] of this._handlers) {
      if (event.startsWith(prefix)) this.publish(event, data);
    }
  }

  /**
   * Unsubscribe a handler from an event.
   * @param {string} event
   * @param {function} handler
   */
  unsubscribe(event, handler) {
    const handlers = this._handlers.get(event);
    if (handlers) {
      handlers.delete(handler);
      if (handlers.size === 0) this._handlers.delete(event);
    }
  }

  /**
   * Subscribe to all events (wildcard).
   * @param {function} handler — receives (eventName, data)
   * @returns {function} unsubscribe
   */
  subscribeAll(handler) {
    this._wildcardHandlers.add(handler);
    return () => this._wildcardHandlers.delete(handler);
  }

  /**
   * Get the last published payload for an event (for late subscribers).
   * @param {string} event
   * @returns {*|undefined}
   */
  lastPayload(event) {
    return this._history.get(event);
  }

  /**
   * Clear all handlers for an event (or all events if no arg).
   * @param {string} [event]
   */
  clear(event) {
    if (event) {
      this._handlers.delete(event);
      this._history.delete(event);
    } else {
      this._handlers.clear();
      this._history.clear();
      this._wildcardHandlers.clear();
    }
  }

  /**
   * Get diagnostic info: number of events and total handlers.
   * @returns {object}
   */
  stats() {
    let total = 0;
    for (const [, set] of this._handlers) total += set.size;
    return { events: this._handlers.size, totalHandlers: total, wildcards: this._wildcardHandlers.size };
  }
}
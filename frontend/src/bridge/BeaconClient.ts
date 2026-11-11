// ================================================================
// BeaconClient.ts
// Sovereign Beaconism Protocol v1.1
// TypeScript frontend client for zero-dependency MASM orchestrator
// ================================================================

/** Native bridge interface — inject this from your host layer */
export interface NativeBridge {
  /** Returns base pointer to mapped 64KB shared memory */
  mapSharedMemory(sessionName: string): bigint;
  /** Trigger the command event (pulse SOVEREIGN_CMD_EVENT) */
  pulseCommandEvent(sessionName: string): void;
  /** Wait for response event with timeout ms */
  waitResponseEvent(sessionName: string, timeoutMs: number): boolean;
  /** Read U32 from absolute offset in shared memory */
  readU32(addr: bigint, offset: number): number;
  /** Write U32 to absolute offset */
  writeU32(addr: bigint, offset: number, value: number): void;
  /** Read U64 from absolute offset */
  readU64(addr: bigint, offset: number): bigint;
  /** Write U64 to absolute offset */
  writeU64(addr: bigint, offset: number, value: bigint): void;
  /** Copy bytes from shared memory into JS buffer */
  readBytes(addr: bigint, offset: number, length: number): Uint8Array;
  /** Copy bytes from JS buffer into shared memory */
  writeBytes(addr: bigint, offset: number, data: Uint8Array): void;
}

// ----------------------------------------------------------------
// Binary Layout Contract (must match SovereignOrchestrator_Hardened.asm)
// ----------------------------------------------------------------
const SHMEM_SIZE = 65536;
const OFF_STATE = 0x00;
const OFF_CMD_ID = 0x04;
const OFF_CMD_TYPE = 0x08;
const OFF_PAYLOAD_LEN = 0x0C;
const OFF_RESP_STATUS = 0x10;
const OFF_RESP_LEN = 0x14;
const OFF_CMD_PAYLOAD = 0x18;
const OFF_RESP_PAYLOAD = 0x1018;
const OFF_MAGIC_COOKIE = 0xFFF0;
const OFF_HEARTBEAT = 0xFFF8;

const PAYLOAD_CMD_SIZE = 4096;
const PAYLOAD_RESP_SIZE = 61416;

const MAGIC_COOKIE = 0xCAFEBABEDEADBEEFn;

// Beacon States
const BEACON_READY = 0x01;
const BEACON_PROCESSING = 0x02;
const BEACON_COMPLETE = 0x04;
const BEACON_SHUTDOWN = 0xFF;

// Commands
export const CMD_LOAD_MODEL = 0x10;
export const CMD_INFERENCE = 0x20;
export const CMD_STATUS = 0x30;
export const CMD_HOTPATCH = 0x40;
export const CMD_TELEMETRY = 0x50;

// Error Codes
export const ERR_OK = 0;
export const ERR_INVALID_STATE = 0xE0000001;
export const ERR_CORRUPT_SHMEM = 0xE0000002;
export const ERR_UNKNOWN_CMD = 0xE0000003;
export const ERR_TIMEOUT = 0xE0000004;

// ----------------------------------------------------------------
// Response Structure
// ----------------------------------------------------------------
export interface SovereignResponse {
  status: number;
  length: number;
  payload: Uint8Array;
  commandId: number;
}

// ----------------------------------------------------------------
// BeaconClient
// ----------------------------------------------------------------
export class BeaconClient {
  private shmemAddr: bigint = 0n;
  private sessionId: number = 0;
  private commandCounter: number = 0;
  private running: boolean = false;

  constructor(
    private bridge: NativeBridge,
    private sessionIdOverride?: number
  ) {}

  /** Connect to the orchestrator's shared memory region */
  connect(): boolean {
    this.sessionId = this.sessionIdOverride ?? this.detectSession();
    const name = this.qualifyName("SOVEREIGN_BEACON_V1");

    try {
      this.shmemAddr = this.bridge.mapSharedMemory(name);
      if (this.shmemAddr === 0n) return false;

      // Validate magic cookie before accepting
      const cookie = this.bridge.readU64(this.shmemAddr, OFF_MAGIC_COOKIE);
      if (cookie !== MAGIC_COOKIE) {
        console.error("[BEACON] Magic cookie mismatch. Expected", MAGIC_COOKIE, "got", cookie);
        return false;
      }

      this.running = true;
      console.log(`[BEACON] Connected to session ${this.sessionId}. SHMEM @ ${this.shmemAddr}`);
      return true;
    } catch (e) {
      console.error("[BEACON] Connection failed:", e);
      return false;
    }
  }

  /** Disconnect and optionally send shutdown */
  disconnect(sendShutdown = false): void {
    if (!this.running) return;

    if (sendShutdown) {
      try {
        this.sendRaw(BEACON_SHUTDOWN, new Uint8Array(0), 1000);
      } catch {
        /* best effort */
      }
    }

    this.running = false;
    this.shmemAddr = 0n;
    console.log("[BEACON] Disconnected.");
  }

  /** Send a command and await response */
  sendCommand(cmdType: number, payload: Uint8Array, timeoutMs = 5000): Promise<SovereignResponse> {
    return new Promise((resolve, reject) => {
      if (!this.running) {
        reject(new Error("[BEACON] Not connected"));
        return;
      }

      if (payload.length > PAYLOAD_CMD_SIZE) {
        reject(new Error(`[BEACON] Payload exceeds ${PAYLOAD_CMD_SIZE} bytes`));
        return;
      }

      try {
        // Atomically write command header + payload
        this.commandCounter++;
        const cmdId = this.commandCounter;

        this.bridge.writeU32(this.shmemAddr, OFF_CMD_ID, cmdId);
        this.bridge.writeU32(this.shmemAddr, OFF_CMD_TYPE, cmdType);
        this.bridge.writeU32(this.shmemAddr, OFF_PAYLOAD_LEN, payload.length);
        this.bridge.writeBytes(this.shmemAddr, OFF_CMD_PAYLOAD, payload);

        // Transition state to READY
        this.bridge.writeU32(this.shmemAddr, OFF_STATE, BEACON_READY);

        // Pulse command event (wake orchestrator)
        this.bridge.pulseCommandEvent(this.qualifyName("SOVEREIGN_CMD_EVENT"));

        // Wait for response event
        const signaled = this.bridge.waitResponseEvent(
          this.qualifyName("SOVEREIGN_RESP_EVENT"),
          timeoutMs
        );

        if (!signaled) {
          reject(new Error(`[BEACON] Timeout after ${timeoutMs}ms`));
          return;
        }

        // Validate completion
        const state = this.bridge.readU32(this.shmemAddr, OFF_STATE);
        if (state !== BEACON_COMPLETE) {
          reject(new Error(`[BEACON] Invalid final state: 0x${state.toString(16)}`));
          return;
        }

        // Validate cookie again (detect mid-flight corruption)
        const cookie = this.bridge.readU64(this.shmemAddr, OFF_MAGIC_COOKIE);
        if (cookie !== MAGIC_COOKIE) {
          reject(new Error("[BEACON] Corruption detected during command execution"));
          return;
        }

        const respStatus = this.bridge.readU32(this.shmemAddr, OFF_RESP_STATUS);
        const respLen = this.bridge.readU32(this.shmemAddr, OFF_RESP_LEN);
        const respPayload = this.bridge.readBytes(
          this.shmemAddr,
          OFF_RESP_PAYLOAD,
          Math.min(respLen, PAYLOAD_RESP_SIZE)
        );

        resolve({
          status: respStatus,
          length: respLen,
          payload: respPayload,
          commandId: cmdId,
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  /** Convenience: Load model by path */
  async loadModel(modelPath: string): Promise<SovereignResponse> {
    const encoder = new TextEncoder();
    const payload = encoder.encode(modelPath + "\0");
    return this.sendCommand(CMD_LOAD_MODEL, payload, 30000); // 30s for model load
  }

  /** Convenience: Run inference with prompt */
  async inference(prompt: string): Promise<SovereignResponse> {
    const encoder = new TextEncoder();
    const payload = encoder.encode(prompt);
    return this.sendCommand(CMD_INFERENCE, payload, 60000); // 60s for generation
  }

  /** Convenience: Get system status */
  async status(): Promise<SovereignResponse> {
    return this.sendCommand(CMD_STATUS, new Uint8Array(0), 5000);
  }

  /** Convenience: Apply hotpatch */
  async hotpatch(targetAddr: bigint, patchBytes: Uint8Array): Promise<SovereignResponse> {
    const payload = new Uint8Array(8 + 4 + patchBytes.length);
    const view = new DataView(payload.buffer);
    view.setBigUint64(0, targetAddr, true);
    view.setUint32(8, patchBytes.length, true);
    payload.set(patchBytes, 12);
    return this.sendCommand(CMD_HOTPATCH, payload, 10000);
  }

  /** Convenience: Pull telemetry snapshot */
  async telemetry(): Promise<SovereignResponse> {
    return this.sendCommand(CMD_TELEMETRY, new Uint8Array(0), 5000);
  }

  /** Read heartbeat counter (orchestrator liveness) */
  getHeartbeat(): bigint {
    if (!this.running) return 0n;
    return this.bridge.readU64(this.shmemAddr, OFF_HEARTBEAT);
  }

  /** Verify shared memory integrity on-demand */
  validateIntegrity(): boolean {
    if (!this.running) return false;
    try {
      const cookie = this.bridge.readU64(this.shmemAddr, OFF_MAGIC_COOKIE);
      return cookie === MAGIC_COOKIE;
    } catch {
      return false;
    }
  }

  // ----------------------------------------------------------------
  // Private
  // ----------------------------------------------------------------
  private detectSession(): number {
    // In Electron/Node: require('process').pid -> session lookup via native addon
    // In WebView2: host exposes session ID via postMessage
    // Fallback: return 0 (assumes console session)
    return 0;
  }

  private qualifyName(base: string): string {
    return `${base}_S${this.sessionId}`;
  }

  private sendRaw(state: number, payload: Uint8Array, timeout: number): void {
    this.bridge.writeU32(this.shmemAddr, OFF_STATE, state);
    this.bridge.writeBytes(this.shmemAddr, OFF_CMD_PAYLOAD, payload);
    this.bridge.pulseCommandEvent(this.qualifyName("SOVEREIGN_CMD_EVENT"));
    this.bridge.waitResponseEvent(this.qualifyName("SOVEREIGN_RESP_EVENT"), timeout);
  }
}

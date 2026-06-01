import { engineService } from '../engine/EngineService';
import { binaryThreatScanner } from '../telemetry/BinaryThreatScanner';
import type { ToolExecutionResult } from './ToolRegistry';

/**
 * PEWriterAdapter — Bridge to the MASM PE32+ emitter (RawrXD_PE_Writer.asm).
 *
 * This is a HIGH-risk tool: it writes raw binary PE executables.
 * Every invocation computes a SHA-256 hash of the code buffer and
 * forwards it to the backend, where the audit trail captures the hash
 * before any bytes hit disk.
 *
 * Day 21: Pre-flight structural analysis via BinaryThreatScanner.
 * Even if HITL approves, the scanner can veto based on W^X violations
 * or suspicious opcode patterns.
 */

function asString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

function asBase64(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  // Accept either raw base64 or a data-URI prefix.
  const clean = value.replace(/^data:[^;]+;base64,/, '');
  return clean.length > 0 ? clean : fallback;
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

/**
 * Compute SHA-256 hash of a base64 string in the browser.
 * Returns a hex-encoded digest.
 */
async function sha256Base64(base64String: string): Promise<string> {
  const binary = atob(base64String);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export interface PeWriterParams {
  outputPath: string;
  codeBufferBase64: string;
  entryPointRva?: number;
  subsystem?: number; // e.g. 3 = CUI, 2 = GUI
}

export interface PeWriterResult {
  outputPath: string;
  bytesWritten: number;
  peHash: string; // SHA-256 of the final PE file
  codeHash: string; // SHA-256 of the code buffer (pre-write)
}

export class PeWriterAdapter {
  public static async emitBinary(params: Record<string, unknown>): Promise<ToolExecutionResult> {
    const outputPath = asString(params.outputPath, 'build/emit.exe');
    const codeBufferBase64 = asBase64(params.codeBuffer, '');
    const entryPointRva = asNumber(params.entryPointRva, 0x1000);
    const subsystem = asNumber(params.subsystem, 3);

    if (!codeBufferBase64) {
      return {
        status: 'FAILED',
        message: 'pe_writer requires a non-empty codeBuffer (base64).',
      };
    }

    // Compute pre-write hash of the code buffer for the audit trail.
    let codeHash: string;
    try {
      codeHash = await sha256Base64(codeBufferBase64);
    } catch {
      return {
        status: 'FAILED',
        message: 'Failed to compute SHA-256 hash of code buffer.',
      };
    }

    // Day 21: Pre-flight structural threat scan.
    // Even if HITL approves, the scanner can veto based on W^X violations
    // or suspicious opcode patterns.
    const scanResult = binaryThreatScanner.scan(codeBufferBase64);
    if (scanResult.blocked) {
      return {
        status: 'DENIED',
        message: `BinaryThreatScanner blocked emission: threatScore=${scanResult.threatScore}. Flags: ${scanResult.threatFlags.join(', ')}. Details: ${scanResult.details.join('; ')}`,
        output: {
          threatScore: scanResult.threatScore,
          threatFlags: scanResult.threatFlags,
          threatDetails: scanResult.details,
          codeHash,
        },
      };
    }

    try {
      const output = await engineService.toolPeWriter(
        outputPath,
        codeBufferBase64,
        entryPointRva,
        subsystem
      );

      return {
        status: 'EXECUTED',
        message: `pe_writer emitted ${output.bytesWritten} bytes to ${outputPath} (codeHash=${codeHash})`,
        output: {
          ...output,
          codeHash,
          threatScore: scanResult.threatScore,
          threatFlags: scanResult.threatFlags,
        } as PeWriterResult,
      };
    } catch (error) {
      return {
        status: 'FAILED',
        message: error instanceof Error ? error.message : 'pe_writer failed',
      };
    }
  }
}

/**
 * BinaryThreatScanner.ts
 * Day 21: Structural Binary Analysis — W^X Validation + Opcode Heuristics
 *
 * Scans PE32+ binaries before write to detect:
 * 1. W^X violations (writable + executable sections)
 * 2. Suspicious opcode patterns (NOP sleds, syscalls, indirect calls)
 *
 * Returns a threat score (0–100) and flag list for audit trail.
 */

export type ThreatFlag =
  | 'W_X_VIOLATION'
  | 'NOP_SLED_DETECTED'
  | 'SYSCALL_INSTRUCTION'
  | 'INDIRECT_CALL_DETECTED'
  | 'UNCONDITIONAL_JUMP_OBFUSCATION'
  | 'SUSPICIOUS_ENTRY_POINT'
  | 'SECTION_ALIGNMENT_ANOMALY';

export interface ThreatScanResult {
  threatScore: number; // 0–100
  threatFlags: ThreatFlag[];
  details: string[];
  blocked: boolean; // true if score >= criticalThreshold
}

// PE32+ constants
const IMAGE_DOS_SIGNATURE = 0x5A4D; // 'MZ'
const IMAGE_NT_SIGNATURE = 0x00004550; // 'PE\0\0'
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;

// Section characteristics
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;

// Threat scoring weights
const WEIGHT_WX_VIOLATION = 60;
const WEIGHT_SYSCALL = 25;
const WEIGHT_NOP_SLED = 20;
const WEIGHT_INDIRECT_CALL = 15;
const WEIGHT_UNCONDITIONAL_JUMP = 10;
const WEIGHT_ALIGNMENT_ANOMALY = 10;

const CRITICAL_THRESHOLD = 50;

/**
 * Parse a little-endian DWORD (4 bytes) from buffer at offset.
 */
function readUInt32(buffer: Uint8Array, offset: number): number {
  return (
    buffer[offset] |
    (buffer[offset + 1] << 8) |
    (buffer[offset + 2] << 16) |
    (buffer[offset + 3] << 24)
  ) >>> 0;
}

/**
 * Parse a little-endian WORD (2 bytes) from buffer at offset.
 */
function readUInt16(buffer: Uint8Array, offset: number): number {
  return (buffer[offset] | (buffer[offset + 1] << 8)) >>> 0;
}

/**
 * Decode base64 string to Uint8Array.
 */
function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export class BinaryThreatScanner {
  private criticalThreshold: number;

  constructor(criticalThreshold = CRITICAL_THRESHOLD) {
    this.criticalThreshold = criticalThreshold;
  }

  /**
   * Scan a PE32+ binary (base64-encoded) for structural threats.
   */
  public scan(base64Pe: string): ThreatScanResult {
    const flags: ThreatFlag[] = [];
    const details: string[] = [];
    let score = 0;

    try {
      const buffer = base64ToBytes(base64Pe);

      if (buffer.length < 0x40) {
        return this.buildResult(score, flags, details, 'Buffer too small for PE header');
      }

      // Validate DOS signature
      const dosSignature = readUInt16(buffer, 0);
      if (dosSignature !== IMAGE_DOS_SIGNATURE) {
        details.push(`Invalid DOS signature: 0x${dosSignature.toString(16)}`);
        return this.buildResult(score, flags, details);
      }

      // Get PE header offset
      const peOffset = readUInt32(buffer, 0x3C);
      if (peOffset + 24 > buffer.length) {
        details.push('PE header offset out of bounds');
        return this.buildResult(score, flags, details);
      }

      // Validate PE signature
      const peSignature = readUInt32(buffer, peOffset);
      if (peSignature !== IMAGE_NT_SIGNATURE) {
        details.push(`Invalid PE signature: 0x${peSignature.toString(16)}`);
        return this.buildResult(score, flags, details);
      }

      // File header
      const machine = readUInt16(buffer, peOffset + 4);
      if (machine !== IMAGE_FILE_MACHINE_AMD64) {
        details.push(`Non-AMD64 machine type: 0x${machine.toString(16)}`);
      }

      const numSections = readUInt16(buffer, peOffset + 6);
      const optionalHeaderSize = readUInt16(buffer, peOffset + 20);

      // Optional header magic
      const optionalHeaderOffset = peOffset + 24;
      const magic = readUInt16(buffer, optionalHeaderOffset);
      if (magic !== IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        details.push(`Non-PE32+ magic: 0x${magic.toString(16)}`);
      }

      // Entry point
      const entryPoint = readUInt32(buffer, optionalHeaderOffset + 16);
      if (entryPoint === 0) {
        score += WEIGHT_SYSCALL;
        flags.push('SUSPICIOUS_ENTRY_POINT');
        details.push('Entry point is zero (possible hollowed binary)');
      }

      // Section headers start after optional header
      const sectionTableOffset = optionalHeaderOffset + optionalHeaderSize;
      const sectionHeaderSize = 40; // IMAGE_SECTION_HEADER

      let textSection: { virtualAddress: number; virtualSize: number; rawOffset: number; rawSize: number } | null = null;

      for (let i = 0; i < numSections; i++) {
        const secOffset = sectionTableOffset + i * sectionHeaderSize;
        if (secOffset + sectionHeaderSize > buffer.length) {
          details.push(`Section ${i} header out of bounds`);
          break;
        }

        const nameBytes = buffer.slice(secOffset, secOffset + 8);
        const name = new TextDecoder().decode(nameBytes).replace(/\x00/g, '');

        const virtualSize = readUInt32(buffer, secOffset + 8);
        const virtualAddress = readUInt32(buffer, secOffset + 12);
        const rawSize = readUInt32(buffer, secOffset + 16);
        const rawOffset = readUInt32(buffer, secOffset + 20);
        const characteristics = readUInt32(buffer, secOffset + 36);

        const isExecutable = (characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0;
        const isWritable = (characteristics & IMAGE_SCN_MEM_WRITE) !== 0;

        // W^X Violation: writable + executable
        if (isExecutable && isWritable) {
          score += WEIGHT_WX_VIOLATION;
          if (!flags.includes('W_X_VIOLATION')) {
            flags.push('W_X_VIOLATION');
          }
          details.push(`Section "${name}" has W^X violation (EXECUTE|WRITE)`);
        }

        // Alignment anomaly: raw size doesn't align to file alignment
        if (rawSize > 0 && (rawOffset % 0x200) !== 0) {
          score += WEIGHT_ALIGNMENT_ANOMALY;
          if (!flags.includes('SECTION_ALIGNMENT_ANOMALY')) {
            flags.push('SECTION_ALIGNMENT_ANOMALY');
          }
          details.push(`Section "${name}" has misaligned raw offset: 0x${rawOffset.toString(16)}`);
        }

        // Track .text section for opcode scanning
        if (name === '.text' && isExecutable) {
          textSection = { virtualAddress, virtualSize, rawOffset, rawSize };
        }
      }

      // Opcode heuristic scanning on .text section
      if (textSection && textSection.rawOffset + textSection.rawSize <= buffer.length) {
        const textBytes = buffer.slice(textSection.rawOffset, textSection.rawOffset + textSection.rawSize);
        const opcodeResult = this.scanOpcodes(textBytes);
        score += opcodeResult.score;
        flags.push(...opcodeResult.flags);
        details.push(...opcodeResult.details);
      } else if (textSection) {
        details.push('.text section bounds exceed buffer — skipping opcode scan');
      }
    } catch (err) {
      details.push(`Scan error: ${err instanceof Error ? err.message : String(err)}`);
    }

    return this.buildResult(score, flags, details);
  }

  /**
   * Scan raw opcode bytes for suspicious patterns.
   */
  private scanOpcodes(textBytes: Uint8Array): { score: number; flags: ThreatFlag[]; details: string[] } {
    let score = 0;
    const flags: ThreatFlag[] = [];
    const details: string[] = [];

    let nopCount = 0;
    let maxNopRun = 0;

    for (let i = 0; i < textBytes.length; i++) {
      const byte = textBytes[i];

      // NOP sled detection (0x90)
      if (byte === 0x90) {
        nopCount++;
        maxNopRun = Math.max(maxNopRun, nopCount);
      } else {
        nopCount = 0;
      }

      // Syscall: 0x0F 0x05 (syscall) or 0x0F 0x34 (sysenter)
      if (byte === 0x0F && i + 1 < textBytes.length) {
        const next = textBytes[i + 1];
        if (next === 0x05 || next === 0x34) {
          score += WEIGHT_SYSCALL;
          if (!flags.includes('SYSCALL_INSTRUCTION')) {
            flags.push('SYSCALL_INSTRUCTION');
            details.push(`Syscall instruction detected at offset 0x${i.toString(16)}`);
          }
        }
      }

      // Indirect call: 0xFF /2 (call r/m32) or 0xFF /3 (callf)
      // Simplified: 0xFF followed by modrm with reg field = 010 (2) or 011 (3)
      if (byte === 0xFF && i + 1 < textBytes.length) {
        const modrm = textBytes[i + 1];
        const reg = (modrm >> 3) & 0x07;
        if (reg === 2 || reg === 3) {
          score += WEIGHT_INDIRECT_CALL;
          if (!flags.includes('INDIRECT_CALL_DETECTED')) {
            flags.push('INDIRECT_CALL_DETECTED');
            details.push(`Indirect call detected at offset 0x${i.toString(16)}`);
          }
        }
      }

      // Unconditional jump: 0xEB (short) or 0xE9 (near)
      if (byte === 0xEB || byte === 0xE9) {
        score += WEIGHT_UNCONDITIONAL_JUMP;
        if (!flags.includes('UNCONDITIONAL_JUMP_OBFUSCATION')) {
          flags.push('UNCONDITIONAL_JUMP_OBFUSCATION');
          details.push(`Unconditional jump detected at offset 0x${i.toString(16)}`);
        }
      }
    }

    // NOP sled threshold: > 16 consecutive NOPs
    if (maxNopRun > 16) {
      score += WEIGHT_NOP_SLED;
      flags.push('NOP_SLED_DETECTED');
      details.push(`NOP sled detected: ${maxNopRun} consecutive NOPs`);
    }

    return { score, flags, details };
  }

  private buildResult(
    score: number,
    flags: ThreatFlag[],
    details: string[],
    extraDetail?: string
  ): ThreatScanResult {
    if (extraDetail) {
      details.push(extraDetail);
    }

    const clampedScore = Math.max(0, Math.min(100, score));
    const blocked = clampedScore >= this.criticalThreshold;

    return {
      threatScore: clampedScore,
      threatFlags: flags,
      details,
      blocked,
    };
  }
}

export const binaryThreatScanner = new BinaryThreatScanner();

// Sovereign IPC Protocol — hardened length-prefixed JSON-RPC framing.
// Every frame is: [4-byte LE uint32 length] + [UTF-8 payload]
// This removes stream-injection ambiguity and prevents state-machine confusion.

export interface SovereignFrame {
  length: number;
  payload: string; // JSON-RPC 2.0 object
}

function readExact(reader: NodeJS.ReadableStream, bytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let received = 0;

    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      received += chunk.length;
      if (received >= bytes) {
        cleanup();
        const combined = Buffer.concat(chunks);
        resolve(combined.subarray(0, bytes));
      }
    };

    const onEnd = () => {
      cleanup();
      reject(new Error('SovereignPipe: stream ended before frame complete'));
    };

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    const cleanup = () => {
      reader.off('data', onData);
      reader.off('end', onEnd);
      reader.off('error', onError);
    };

    reader.on('data', onData);
    reader.on('end', onEnd);
    reader.on('error', onError);
  });
}

export async function readFrame(reader: NodeJS.ReadableStream): Promise<string> {
  const lenBuf = await readExact(reader, 4);
  const length = lenBuf.readUInt32LE(0);
  if (length > 16 * 1024 * 1024) {
    throw new Error(`SovereignPipe: frame length ${length} exceeds 16 MiB maximum`);
  }
  const payload = await readExact(reader, length);
  return payload.toString('utf8');
}

export function writeFrame(writer: NodeJS.WritableStream, payload: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const buf = Buffer.from(payload, 'utf8');
    const lenBuf = Buffer.allocUnsafe(4);
    lenBuf.writeUInt32LE(buf.length, 0);

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    const cleanup = () => {
      writer.off('error', onError);
    };

    writer.on('error', onError);
    writer.write(lenBuf, (err1?: Error | null) => {
      if (err1) {
        cleanup();
        reject(err1);
        return;
      }
      writer.write(buf, (err2?: Error | null) => {
        cleanup();
        if (err2) {
          reject(err2);
        } else {
          resolve();
        }
      });
    });
  });
}

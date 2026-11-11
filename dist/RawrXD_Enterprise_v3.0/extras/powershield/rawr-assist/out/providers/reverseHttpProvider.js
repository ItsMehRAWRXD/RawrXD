"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ReverseHttpProvider = void 0;
const streamParsing_1 = require("../streamParsing");
class ReverseHttpProvider {
    constructor(options) {
        this.name = 'reverse-http';
        this.opts = {
            endpoint: options.endpoint,
            getAuth: options.getAuth,
            streamMode: options.streamMode ?? 'sse',
            extraHeaders: options.extraHeaders,
            buildPayload: options.buildPayload,
            allowRawFallback: options.allowRawFallback ?? true,
            timeoutMs: options.timeoutMs ?? 120000,
        };
    }
    async isAvailable() {
        const token = await this.opts.getAuth();
        return token !== null && token.length > 0;
    }
    async *generate(req, signal) {
        const auth = await this.opts.getAuth();
        if (!auth)
            throw new Error('ReverseHttpProvider: missing auth token');
        const controller = new AbortController();
        const abortOnSignal = () => controller.abort();
        signal.addEventListener('abort', abortOnSignal);
        const timeout = setTimeout(() => controller.abort(), this.opts.timeoutMs);
        try {
            const payload = this.opts.buildPayload
                ? this.opts.buildPayload(req)
                : this.defaultPayload(req);
            const headers = {
                'Authorization': `Bearer ${auth}`,
                'Content-Type': 'application/json',
                'Accept': 'text/event-stream, application/x-ndjson, application/json',
                ...(this.opts.extraHeaders ?? {}),
            };
            const response = await fetch(this.opts.endpoint, {
                method: 'POST',
                headers,
                body: JSON.stringify(payload),
                signal: controller.signal,
            });
            if (!response.ok) {
                const text = await response.text().catch(() => '');
                throw new Error(`ReverseHttpProvider: HTTP ${response.status} - ${text.slice(0, 200)}`);
            }
            if (!response.body)
                throw new Error('ReverseHttpProvider: no response body');
            const reader = response.body.getReader();
            const tokenizer = new streamParsing_1.StreamTokenizer(this.opts.streamMode);
            let rawBuffer = '';
            let lastYieldTime = Date.now();
            while (true) {
                if (signal.aborted)
                    break;
                const { done, value } = await reader.read();
                if (done)
                    break;
                const chunks = tokenizer.push(value);
                if (chunks.length > 0) {
                    for (const c of chunks) {
                        yield c;
                        if (c.isFinal)
                            return;
                    }
                    lastYieldTime = Date.now();
                    rawBuffer = '';
                }
                else if (this.opts.allowRawFallback) {
                    // Accumulate raw data in case structured parsing keeps failing
                    rawBuffer += new TextDecoder().decode(value);
                    // If no structured tokens for 500ms and we have raw data, emit fallback
                    if (Date.now() - lastYieldTime > 500 && rawBuffer.length > 20) {
                        const fb = (0, streamParsing_1.extractRawTextFallback)(rawBuffer);
                        for (const c of fb.items)
                            yield c;
                        rawBuffer = fb.remaining;
                        lastYieldTime = Date.now();
                    }
                }
            }
            // Flush remaining
            const finalChunks = tokenizer.flushFinal();
            for (const c of finalChunks)
                yield c;
            // If still have raw buffer leftover, emit
            if (this.opts.allowRawFallback && rawBuffer.length > 0) {
                const fb = (0, streamParsing_1.extractRawTextFallback)(rawBuffer);
                for (const c of fb.items)
                    yield c;
            }
        }
        finally {
            clearTimeout(timeout);
            signal.removeEventListener('abort', abortOnSignal);
        }
    }
    defaultPayload(req) {
        const payload = {
            model: req.model,
            prompt: req.prompt,
            stream: true,
        };
        if (req.systemPrompt)
            payload.system = req.systemPrompt;
        if (req.temperature !== undefined)
            payload.temperature = req.temperature;
        if (req.maxTokens !== undefined) {
            payload.max_tokens = req.maxTokens;
            payload.max_new_tokens = req.maxTokens; // some APIs use this variant
        }
        if (req.stop)
            payload.stop = req.stop;
        return payload;
    }
}
exports.ReverseHttpProvider = ReverseHttpProvider;
/**
 * Example instantiation for a hypothetical reverse-engineered endpoint:
 *
 * ```ts
 * import * as vscode from 'vscode';
 * const provider = new ReverseHttpProvider({
 *   endpoint: 'https://some-service.example/internal/chat',
 *   getAuth: async () => {
 *     return await vscode.workspace.getConfiguration('rawrAssist').get<string>('reverseApiToken') ?? null;
 *   },
 *   streamMode: 'sse',
 *   extraHeaders: { 'x-client-version': '1.0.0' },
 *   allowRawFallback: true,
 * });
 *
 * for await (const chunk of provider.generate({ model: 'gpt-4', prompt: 'Hello' }, abortController.signal)) {
 *   console.log(chunk.token);
 *   if (chunk.isFinal) break;
 * }
 * ```
 */
//# sourceMappingURL=reverseHttpProvider.js.map
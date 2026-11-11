// RawrXD Node.js Client SDK
//
// A simple, efficient client for interacting with RawrXD LLM inference servers.
// Compatible with OpenAI API format.
//
// Example usage:
//     const client = new RawrXDClient('http://localhost:8080');
//     const response = await client.complete('Hello, world!');
//     console.log(response.text);

const axios = require('axios');

/**
 * RawrXD API client
 */
class RawrXDClient {
    /**
     * Create a new RawrXD client
     * @param {string} baseUrl - Server URL
     * @param {string} [apiKey] - API key for authentication
     * @param {number} [timeout=60000] - Request timeout in milliseconds
     */
    constructor(baseUrl, apiKey = null, timeout = 60000) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.apiKey = apiKey;
        this.timeout = timeout;
        
        this.client = axios.create({
            baseURL: this.baseUrl,
            timeout: this.timeout,
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (this.apiKey) {
            this.client.defaults.headers.common['Authorization'] = `Bearer ${this.apiKey}`;
        }
    }

    /**
     * Generate text completion
     * @param {Object} params - Completion parameters
     * @param {string} params.prompt - Input prompt
     * @param {string} [params.model] - Model identifier
     * @param {number} [params.max_tokens=256] - Maximum tokens to generate
     * @param {number} [params.temperature=0.7] - Sampling temperature
     * @param {number} [params.top_p=0.9] - Nucleus sampling threshold
     * @param {number} [params.top_k=40] - Top-k sampling limit
     * @param {number} [params.repetition_penalty=1.0] - Repetition penalty
     * @param {boolean} [params.stream=false] - Stream response
     * @param {string[]} [params.stop] - Stop sequences
     * @param {number} [params.seed] - Random seed
     * @returns {Promise<CompletionResponse>} Completion response
     */
    async complete(params) {
        const requestBody = {
            prompt: params.prompt,
            model: params.model,
            max_tokens: params.max_tokens ?? 256,
            temperature: params.temperature ?? 0.7,
            top_p: params.top_p ?? 0.9,
            top_k: params.top_k ?? 40,
            repetition_penalty: params.repetition_penalty ?? 1.0,
            stream: params.stream ?? false,
            stop: params.stop,
            seed: params.seed
        };

        const response = await this.client.post('/v1/completions', requestBody);
        return response.data;
    }

    /**
     * Simple completion helper
     * @param {string} prompt - Input prompt
     * @param {Object} [options] - Additional options
     * @returns {Promise<string>} Generated text
     */
    async completeSimple(prompt, options = {}) {
        const response = await this.complete({
            prompt,
            ...options
        });
        return response.choices[0]?.text ?? '';
    }

    /**
     * Generate chat completion
     * @param {Object} params - Chat parameters
     * @param {Array<{role: string, content: string}>} params.messages - Chat messages
     * @param {string} [params.model] - Model identifier
     * @param {number} [params.max_tokens=256] - Maximum tokens to generate
     * @param {number} [params.temperature=0.7] - Sampling temperature
     * @param {number} [params.top_p=0.9] - Nucleus sampling threshold
     * @param {boolean} [params.stream=false] - Stream response
     * @returns {Promise<ChatResponse>} Chat response
     */
    async chat(params) {
        const requestBody = {
            messages: params.messages,
            model: params.model,
            max_tokens: params.max_tokens ?? 256,
            temperature: params.temperature ?? 0.7,
            top_p: params.top_p ?? 0.9,
            stream: params.stream ?? false
        };

        const response = await this.client.post('/v1/chat/completions', requestBody);
        return response.data;
    }

    /**
     * Simple chat helper
     * @param {Array<{role: string, content: string}>} messages - Chat messages
     * @param {Object} [options] - Additional options
     * @returns {Promise<string>} Assistant's response
     */
    async chatSimple(messages, options = {}) {
        const response = await this.chat({
            messages,
            ...options
        });
        return response.choices[0]?.message?.content ?? '';
    }

    /**
     * Generate embeddings
     * @param {Object} params - Embedding parameters
     * @param {string} params.input - Text to embed
     * @param {string} [params.model] - Model identifier
     * @param {string} [params.encoding_format='float'] - Encoding format
     * @returns {Promise<EmbeddingResponse>} Embedding response
     */
    async embed(params) {
        const requestBody = {
            input: params.input,
            model: params.model,
            encoding_format: params.encoding_format ?? 'float'
        };

        const response = await this.client.post('/v1/embeddings', requestBody);
        return response.data;
    }

    /**
     * Simple embedding helper
     * @param {string} text - Text to embed
     * @param {Object} [options] - Additional options
     * @returns {Promise<number[]>} Embedding vector
     */
    async embedSimple(text, options = {}) {
        const response = await this.embed({
            input: text,
            ...options
        });
        return response.data[0]?.embedding ?? [];
    }

    /**
     * List available models
     * @returns {Promise<ModelInfo[]>} List of models
     */
    async listModels() {
        const response = await this.client.get('/v1/models');
        return response.data.data;
    }

    /**
     * Check server health
     * @returns {Promise<HealthResponse>} Health status
     */
    async health() {
        const response = await this.client.get('/health');
        return response.data;
    }

    /**
     * Stream completion tokens
     * @param {string} prompt - Input prompt
     * @param {Object} [options] - Additional options
     * @yields {string} Generated tokens
     */
    async *streamComplete(prompt, options = {}) {
        const requestBody = {
            prompt,
            stream: true,
            ...options
        };

        const response = await this.client.post('/v1/completions', requestBody, {
            responseType: 'stream'
        });

        const stream = response.data;
        
        for await (const chunk of stream) {
            const lines = chunk.toString().split('\n');
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const data = line.slice(6);
                    if (data === '[DONE]') return;
                    
                    try {
                        const parsed = JSON.parse(data);
                        const content = parsed.choices[0]?.delta?.content;
                        if (content) yield content;
                    } catch (e) {
                        // Ignore parse errors
                    }
                }
            }
        }
    }

    /**
     * Stream chat completion tokens
     * @param {Array<{role: string, content: string}>} messages - Chat messages
     * @param {Object} [options] - Additional options
     * @yields {string} Generated tokens
     */
    async *streamChat(messages, options = {}) {
        const requestBody = {
            messages,
            stream: true,
            ...options
        };

        const response = await this.client.post('/v1/chat/completions', requestBody, {
            responseType: 'stream'
        });

        const stream = response.data;
        
        for await (const chunk of stream) {
            const lines = chunk.toString().split('\n');
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const data = line.slice(6);
                    if (data === '[DONE]') return;
                    
                    try {
                        const parsed = JSON.parse(data);
                        const content = parsed.choices[0]?.delta?.content;
                        if (content) yield content;
                    } catch (e) {
                        // Ignore parse errors
                    }
                }
            }
        }
    }
}

// Type definitions for JSDoc

/**
 * @typedef {Object} CompletionResponse
 * @property {string} id
 * @property {string} object
 * @property {number} created
 * @property {string} model
 * @property {CompletionChoice[]} choices
 * @property {Usage} usage
 */

/**
 * @typedef {Object} CompletionChoice
 * @property {string} text
 * @property {number} index
 * @property {string} finish_reason
 */

/**
 * @typedef {Object} ChatResponse
 * @property {string} id
 * @property {string} object
 * @property {number} created
 * @property {string} model
 * @property {ChatChoice[]} choices
 * @property {Usage} usage
 */

/**
 * @typedef {Object} ChatChoice
 * @property {number} index
 * @property {ChatMessage} message
 * @property {string} finish_reason
 */

/**
 * @typedef {Object} ChatMessage
 * @property {string} role
 * @property {string} content
 */

/**
 * @typedef {Object} EmbeddingResponse
 * @property {string} object
 * @property {EmbeddingData[]} data
 * @property {string} model
 * @property {Usage} usage
 */

/**
 * @typedef {Object} EmbeddingData
 * @property {string} object
 * @property {number[]} embedding
 * @property {number} index
 */

/**
 * @typedef {Object} ModelInfo
 * @property {string} id
 * @property {string} object
 * @property {number} created
 * @property {string} owned_by
 */

/**
 * @typedef {Object} HealthResponse
 * @property {string} status
 * @property {string} timestamp
 * @property {string} version
 * @property {Object} components
 */

/**
 * @typedef {Object} Usage
 * @property {number} prompt_tokens
 * @property {number} completion_tokens
 * @property {number} total_tokens
 */

module.exports = { RawrXDClient };

// Example usage
async function main() {
    // Create client
    const client = new RawrXDClient('http://localhost:8080');

    // Check health
    try {
        const health = await client.health();
        console.log('Server status:', health.status);
    } catch (error) {
        console.error('Health check failed:', error.message);
    }

    // Simple completion
    try {
        const completion = await client.completeSimple('The capital of France is');
        console.log('Completion:', completion);
    } catch (error) {
        console.error('Completion failed:', error.message);
    }

    // Chat completion
    try {
        const messages = [
            { role: 'system', content: 'You are a helpful assistant.' },
            { role: 'user', content: 'What is Node.js?' }
        ];
        const chatResponse = await client.chatSimple(messages);
        console.log('Chat response:', chatResponse);
    } catch (error) {
        console.error('Chat failed:', error.message);
    }

    // Streaming completion
    try {
        process.stdout.write('Streaming: ');
        for await (const token of client.streamComplete('Count to 5:')) {
            process.stdout.write(token);
        }
        console.log();
    } catch (error) {
        console.error('Streaming failed:', error.message);
    }

    // Embeddings
    try {
        const embedding = await client.embedSimple('Hello, world!');
        console.log('Embedding dimension:', embedding.length);
    } catch (error) {
        console.error('Embedding failed:', error.message);
    }

    // List models
    try {
        const models = await client.listModels();
        console.log('Available models:');
        models.forEach(model => {
            console.log('  -', model.id);
        });
    } catch (error) {
        console.error('List models failed:', error.message);
    }
}

// Run if called directly
if (require.main === module) {
    main().catch(console.error);
}

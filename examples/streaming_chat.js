/**
 * Streaming Chat Example for RawrXD
 * 
 * This example demonstrates how to use streaming responses
 * from the RawrXD API in JavaScript.
 * 
 * Usage:
 *   node streaming_chat.js
 */

const API_BASE = 'http://localhost:8080/v1';
const MODEL = 'llama-2-7b';

/**
 * Make a streaming chat completion request
 */
async function streamChatCompletion(messages, onChunk) {
    const response = await fetch(`${API_BASE}/chat/completions`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            model: MODEL,
            messages: messages,
            stream: true
        })
    });

    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
            if (line.startsWith('data: ')) {
                const data = line.slice(6);
                if (data === '[DONE]') return;

                try {
                    const parsed = JSON.parse(data);
                    const content = parsed.choices[0]?.delta?.content;
                    if (content) {
                        onChunk(content);
                    }
                } catch (e) {
                    // Ignore parse errors
                }
            }
        }
    }
}

/**
 * Example usage
 */
async function main() {
    console.log('RawrXD Streaming Chat Example');
    console.log('=' .repeat(50));

    // Example 1: Simple streaming chat
    console.log('\n1. Simple Streaming Chat:\n');
    
    const messages = [
        { role: 'user', content: 'Count from 1 to 5' }
    ];

    process.stdout.write('Assistant: ');
    await streamChatCompletion(messages, (chunk) => {
        process.stdout.write(chunk);
    });
    console.log('\n');

    // Example 2: Story generation with streaming
    console.log('\n2. Story Generation:\n');
    
    const storyMessages = [
        { role: 'user', content: 'Write a one-sentence story about a robot.' }
    ];

    process.stdout.write('Assistant: ');
    await streamChatCompletion(storyMessages, (chunk) => {
        process.stdout.write(chunk);
    });
    console.log('\n');

    // Example 3: Code generation with streaming
    console.log('\n3. Code Generation:\n');
    
    const codeMessages = [
        { role: 'system', content: 'You are a coding assistant.' },
        { role: 'user', content: 'Write a JavaScript function to reverse a string.' }
    ];

    process.stdout.write('Assistant:\n');
    await streamChatCompletion(codeMessages, (chunk) => {
        process.stdout.write(chunk);
    });
    console.log('\n');
}

main().catch(console.error);

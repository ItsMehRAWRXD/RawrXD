<<<<<<< HEAD
/**
 * RawrXD Backend Server
 * =====================
 * Bridges HTTP API (port 8080) to Deep2/Sovereign runtime.
 * 
 * Architecture: Browser → RawrXD Backend :8080 → Sovereign Runtime → Deep2/MoE/MASM
 * 
 * Endpoints:
 *   GET  /api/models              - Return model registry from Deep2
 *   POST /api/model/load         - Load model via DeepSeekMoELoader
 *   POST /api/model/unload       - Unload model
 *   GET  /api/engine/capabilities - Return Deep2/Sovereign capabilities
 *   POST /api/agent/dual/init    - Initialize dual agent orchestrator
 *   POST /api/agent/dual/execute - Run Architect→Coder pipeline
 *   POST /api/chat               - Chat completions (OpenAI-compatible)
 *   POST /v1/chat/completions    - OpenAI API compatible endpoint
 *   GET  /api/agents             - List available agents
 *   GET  /api/agents/status      - Agent subsystem status
 *   GET  /api/agents/history     - Agent event history
 *   POST /api/agents/replay      - Replay failed agent events
 *   GET  /health                 - Health check
 *   GET  /status                 - Server status + stats
 * 
 * Usage:
 *   node server.js                    # Default port 8080
 *   node server.js --port 9000        # Custom port
 *   node server.js --deep2-path ..   # Path to Deep2 runtime DLL
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { spawn, execFile } = require('child_process');
const crypto = require('crypto');

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
  port: parseInt(process.argv.find((arg, i) => process.argv[i - 1] === '--port' && arg) || process.env.RAWRXD_PORT || '8080'),
  host: process.argv.find((arg, i) => process.argv[i - 1] === '--host' && arg) || process.env.RAWRXD_HOST || '127.0.0.1',
  deep2Path: process.argv.find((arg, i) => process.argv[i - 1] === '--deep2-path' && arg) || process.env.RAWRXD_DEEP2_PATH || 'D:\\rawrxd\\build\\RawrXD_Runtime.dll',
  modelDir: process.argv.find((arg, i) => process.argv[i - 1] === '--model-dir' && arg) || process.env.RAWRXD_MODEL_DIR || 'D:\\OllamaModels',
  maxRequestBody: 10 * 1024 * 1024,  // 10 MB
  requestTimeout: 300000,             // 5 minutes
};

// ============================================================================
// State Management
// ============================================================================

const state = {
  models: new Map(),           // Loaded models: name -> modelInfo
  agents: new Map(),           // Active agents: id -> agentInfo
  sessions: new Map(),         // Chat sessions: id -> sessionInfo
  stats: {
    startTime: Date.now(),
    totalRequests: 0,
    totalTokens: 0,
    activeConnections: 0,
  },
  agentEvents: [],             // Agent event history
  failureLog: [],              // Failure intelligence
};

// Deep2 runtime handle (loaded via native addon or subprocess)
let deep2Runtime = null;

// ============================================================================
// Express Setup
// ============================================================================

const app = express();

// Middleware
app.use(cors({
  origin: ['http://localhost:*', 'http://127.0.0.1:*', 'file://*'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
}));

app.use(express.json({ limit: CONFIG.maxRequestBody }));
app.use(express.static(path.join(__dirname, 'gui')));

// Request logging middleware
app.use((req, res, next) => {
  const requestId = crypto.randomUUID();
  req.requestId = requestId;
  state.stats.totalRequests++;
  
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} [${requestId}]`);
  
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${requestId}] ${res.statusCode} in ${duration}ms`);
  });
  
  next();
});

// ============================================================================
// Deep2 Runtime Integration
// ============================================================================

/**
 * Initialize Deep2 runtime connection
 * Attempts to load native addon or spawn subprocess
 */
async function initDeep2Runtime() {
  console.log('[Deep2] Initializing runtime...');
  
  // Check if native addon exists
  const addonPath = path.join(__dirname, 'build', 'Release', 'rawrxd_native.node');
  if (fs.existsSync(addonPath)) {
    try {
      deep2Runtime = require(addonPath);
      console.log('[Deep2] Native addon loaded successfully');
      return true;
    } catch (e) {
      console.warn('[Deep2] Failed to load native addon:', e.message);
    }
  }
  
  // Fallback: Check for Deep2 DLL and use subprocess bridge
  if (fs.existsSync(CONFIG.deep2Path)) {
    console.log('[Deep2] Using subprocess bridge to:', CONFIG.deep2Path);
    // Subprocess bridge will be initialized on first use
    return true;
  }
  
  console.warn('[Deep2] Runtime not found at:', CONFIG.deep2Path);
  console.warn('[Deep2] Running in MOCK MODE - no actual inference');
  return false;
}

/**
 * Call Deep2 runtime via subprocess or native addon
 */
async function callDeep2(method, params) {
  if (!deep2Runtime) {
    // Mock mode for development
    return mockDeep2Response(method, params);
  }
  
  if (typeof deep2Runtime[method] === 'function') {
    return deep2Runtime[method](params);
  }
  
  throw new Error(`Deep2 method not found: ${method}`);
}

/**
 * Mock responses for development without Deep2 runtime
 */
function mockDeep2Response(method, params) {
  const responses = {
    getCapabilities: () => ({
      version: '2.0.0-mock',
      backends: ['cpu', 'vulkan'],
      features: ['moe', 'flash_attention', 'quantization'],
      maxContextLength: 131072,
      maxBatchSize: 512,
    }),
    
    listModels: () => scanModelDirectory(),
    
    loadModel: ({ modelPath, config }) => ({
      success: true,
      modelId: crypto.randomUUID(),
      name: path.basename(modelPath),
      architecture: 'DeepSeekV3',
      parameters: '671B',
      contextLength: 131072,
      loadedAt: new Date().toISOString(),
    }),
    
    unloadModel: ({ modelId }) => ({
      success: true,
      modelId,
      unloadedAt: new Date().toISOString(),
    }),
    
    generate: ({ modelId, messages, options }) => {
      const lastMessage = messages[messages.length - 1]?.content || '';
      return {
        content: `[MOCK] Response to: "${lastMessage.substring(0, 50)}..."`,
        tokensGenerated: Math.floor(Math.random() * 100) + 50,
        finishReason: 'stop',
      };
    },
    
    generateStream: ({ modelId, messages, options }) => {
      // Returns async iterator for streaming
      return createMockStream(messages);
    },
  };
  
  const handler = responses[method];
  if (handler) {
    return handler(params);
  }
  
  throw new Error(`Unknown Deep2 method: ${method}`);
}

async function* createMockStream(messages) {
  const words = ['Processing', 'analyzing', 'generating', 'response', 'based', 'on', 'input', '...'];
  for (const word of words) {
    await new Promise(r => setTimeout(r, 100));
    yield { content: word + ' ', finishReason: null };
  }
  yield { content: '', finishReason: 'stop' };
}

/**
 * Scan model directory for available models
 */
function scanModelDirectory() {
  const models = [];
  
  if (!fs.existsSync(CONFIG.modelDir)) {
    return models;
  }
  
  // Scan for .gguf files
  const scanDir = (dir, depth = 0) => {
    if (depth > 3) return; // Limit recursion
    
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          scanDir(fullPath, depth + 1);
        } else if (entry.name.endsWith('.gguf')) {
          const stats = fs.statSync(fullPath);
          models.push({
            id: crypto.createHash('sha256').update(fullPath).digest('hex').substring(0, 16),
            name: entry.name.replace('.gguf', ''),
            path: fullPath,
            size: stats.size,
            sizeFormatted: formatBytes(stats.size),
            type: 'gguf',
            modified: stats.mtime.toISOString(),
          });
        }
      }
    } catch (e) {
      // Skip inaccessible directories
    }
  };
  
  scanDir(CONFIG.modelDir);
  
  // Also check for Ollama models as fallback
  const ollamaDir = path.join(process.env.USERPROFILE || '', '.ollama', 'models');
  if (fs.existsSync(ollamaDir)) {
    scanDir(ollamaDir, 0);
  }
  
  return models.sort((a, b) => b.size - a.size);
}

function formatBytes(bytes) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  return `${size.toFixed(2)} ${units[unitIndex]}`;
}

// ============================================================================
// API Routes
// ============================================================================

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    server: 'RawrXD-Backend',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    deep2: deep2Runtime ? 'connected' : 'mock',
    uptime: Math.floor((Date.now() - state.stats.startTime) / 1000),
  });
});

// Status endpoint
app.get('/status', (req, res) => {
  res.json({
    status: 'ok',
    server: 'RawrXD-Backend',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    stats: {
      ...state.stats,
      uptime: Math.floor((Date.now() - state.stats.startTime) / 1000),
      loadedModels: state.models.size,
      activeAgents: state.agents.size,
      activeSessions: state.sessions.size,
    },
    deep2: {
      connected: !!deep2Runtime,
      path: CONFIG.deep2Path,
      mock: !deep2Runtime,
    },
  });
});

// ============================================================================
// Model Management Endpoints
// ============================================================================

// GET /api/models - List available models
app.get('/api/models', async (req, res) => {
  try {
    const models = await callDeep2('listModels', {});
    
    // Merge with currently loaded models
    const loadedIds = new Set(state.models.keys());
    
    res.json({
      models: models.map(m => ({
        ...m,
        loaded: loadedIds.has(m.id),
        loadedAt: state.models.get(m.id)?.loadedAt || null,
      })),
      total: models.length,
      loaded: loadedIds.size,
    });
  } catch (e) {
    console.error('[API] Failed to list models:', e);
    res.status(500).json({ error: 'Failed to list models', message: e.message });
  }
});

// POST /api/model/load - Load a model
app.post('/api/model/load', async (req, res) => {
  const { modelId, modelPath, config = {} } = req.body;
  
  if (!modelId && !modelPath) {
    return res.status(400).json({ error: 'Missing modelId or modelPath' });
  }
  
  try {
    // Check if already loaded
    if (modelId && state.models.has(modelId)) {
      return res.json({
        success: true,
        modelId,
        message: 'Model already loaded',
        ...state.models.get(modelId),
      });
    }
    
    // Resolve model path
    const resolvedPath = modelPath || findModelPath(modelId);
    if (!resolvedPath) {
      return res.status(404).json({ error: 'Model not found' });
    }
    
    console.log('[API] Loading model:', resolvedPath);
    
    // Call Deep2 to load model
    const result = await callDeep2('loadModel', {
      modelPath: resolvedPath,
      config: {
        contextLength: config.contextLength || 131072,
        gpuLayers: config.gpuLayers || 0,
        ...config,
      },
    });
    
    if (result.success) {
      state.models.set(result.modelId, {
        ...result,
        path: resolvedPath,
        loadedAt: new Date().toISOString(),
      });
    }
    
    res.json(result);
  } catch (e) {
    console.error('[API] Failed to load model:', e);
    res.status(500).json({ error: 'Failed to load model', message: e.message });
  }
});

// POST /api/model/unload - Unload a model
app.post('/api/model/unload', async (req, res) => {
  const { modelId } = req.body;
  
  if (!modelId) {
    return res.status(400).json({ error: 'Missing modelId' });
  }
  
  try {
    if (!state.models.has(modelId)) {
      return res.status(404).json({ error: 'Model not loaded' });
    }
    
    const result = await callDeep2('unloadModel', { modelId });
    
    if (result.success) {
      state.models.delete(modelId);
    }
    
    res.json(result);
  } catch (e) {
    console.error('[API] Failed to unload model:', e);
    res.status(500).json({ error: 'Failed to unload model', message: e.message });
  }
});

function findModelPath(modelId) {
  // Search for model by ID (hash of path)
  const models = scanModelDirectory();
  const model = models.find(m => m.id === modelId);
  return model?.path;
}

// ============================================================================
// Engine Capabilities Endpoint
// ============================================================================

// GET /api/engine/capabilities - Get Deep2/Sovereign capabilities
app.get('/api/engine/capabilities', async (req, res) => {
  try {
    const capabilities = await callDeep2('getCapabilities', {});
    
    res.json({
      ...capabilities,
      server: 'RawrXD-Backend',
      endpoints: {
        chat: '/api/chat',
        completions: '/v1/chat/completions',
        models: '/api/models',
        agents: '/api/agents',
      },
    });
  } catch (e) {
    console.error('[API] Failed to get capabilities:', e);
    res.status(500).json({ error: 'Failed to get capabilities', message: e.message });
  }
});

// ============================================================================
// Chat/Completion Endpoints
// ============================================================================

// POST /api/chat - RawrXD native chat endpoint
app.post('/api/chat', async (req, res) => {
  const { model, messages, stream = false, options = {} } = req.body;
  
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Invalid messages format' });
  }
  
  try {
    // Find loaded model or use default
    let modelId = model;
    if (!modelId && state.models.size > 0) {
      modelId = Array.from(state.models.keys())[0];
    }
    
    if (!modelId) {
      return res.status(400).json({ error: 'No model loaded' });
    }
    
    if (stream) {
      // Streaming response
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      
      const streamGen = await callDeep2('generateStream', {
        modelId,
        messages,
        options,
      });
      
      for await (const chunk of streamGen) {
        res.write(`data: ${JSON.stringify(chunk)}\n\n`);
      }
      
      res.write('data: [DONE]\n\n');
      res.end();
    } else {
      // Non-streaming response
      const result = await callDeep2('generate', {
        modelId,
        messages,
        options,
      });
      
      res.json({
        id: `chat-${crypto.randomUUID()}`,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: modelId,
        choices: [{
          index: 0,
          message: {
            role: 'assistant',
            content: result.content,
          },
          finish_reason: result.finishReason,
        }],
        usage: {
          prompt_tokens: messages.reduce((acc, m) => acc + (m.content?.length || 0) / 4, 0),
          completion_tokens: result.tokensGenerated,
          total_tokens: messages.reduce((acc, m) => acc + (m.content?.length || 0) / 4, 0) + result.tokensGenerated,
        },
      });
    }
  } catch (e) {
    console.error('[API] Chat failed:', e);
    res.status(500).json({ error: 'Chat failed', message: e.message });
  }
});

// POST /v1/chat/completions - OpenAI-compatible endpoint
app.post('/v1/chat/completions', async (req, res) => {
  // Convert OpenAI format to RawrXD format
  const { model, messages, stream = false, temperature, max_tokens } = req.body;
  
  // Forward to native endpoint
  req.body = {
    model,
    messages,
    stream,
    options: { temperature, max_tokens },
  };
  
  // Reuse native handler
  app._router.handle(req, res, () => {
    // If not handled by native, do OpenAI format conversion
    handleOpenAICompletion(req, res);
  });
});

async function handleOpenAICompletion(req, res) {
  // This is a fallback if the native handler doesn't catch it
  const { model, messages, stream = false } = req.body;
  
  try {
    // Mock OpenAI-compatible response
    const response = {
      id: `chatcmpl-${crypto.randomUUID()}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: model || 'rawrxd-default',
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: '[RawrXD Backend] Response generated',
        },
        finish_reason: 'stop',
      }],
      usage: {
        prompt_tokens: 10,
        completion_tokens: 5,
        total_tokens: 15,
      },
    };
    
    res.json(response);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// ============================================================================
// Agent Endpoints
// ============================================================================

// GET /api/agents - List available agents
app.get('/api/agents', (req, res) => {
  const agents = [
    {
      id: 'architect',
      name: 'Architect',
      description: 'High-level system design and planning',
      capabilities: ['design', 'planning', 'architecture'],
    },
    {
      id: 'coder',
      name: 'Coder',
      description: 'Implementation and code generation',
      capabilities: ['coding', 'debugging', 'refactoring'],
    },
    {
      id: 'dual',
      name: 'DualAgent',
      description: 'Architect + Coder pipeline',
      capabilities: ['design', 'coding', 'orchestration'],
    },
  ];
  
  res.json({ agents, total: agents.length });
});

// GET /api/agents/status - Agent subsystem status
app.get('/api/agents/status', (req, res) => {
  res.json({
    active: state.agents.size,
    totalEvents: state.agentEvents.length,
    failures: state.failureLog.length,
    agents: Array.from(state.agents.entries()).map(([id, info]) => ({
      id,
      ...info,
    })),
  });
});

// GET /api/agents/history - Agent event history
app.get('/api/agents/history', (req, res) => {
  const { limit = 100 } = req.query;
  const events = state.agentEvents.slice(-parseInt(limit)).reverse();
  res.json({ events, total: state.agentEvents.length });
});

// POST /api/agents/replay - Replay failed agent events
app.post('/api/agents/replay', (req, res) => {
  const { event_id, agent_id } = req.body;
  
  const event = state.agentEvents.find(e => e.id === event_id);
  if (!event) {
    return res.status(404).json({ error: 'Event not found' });
  }
  
  // Replay logic here
  res.json({
    success: true,
    replayed: event_id,
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// Dual Agent Endpoints
// ============================================================================

// POST /api/agent/dual/init - Initialize dual agent orchestrator
app.post('/api/agent/dual/init', async (req, res) => {
  const { model, config = {} } = req.body;
  
  try {
    const agentId = `dual-${crypto.randomUUID()}`;
    
    state.agents.set(agentId, {
      id: agentId,
      type: 'dual',
      model: model || 'default',
      status: 'initialized',
      createdAt: new Date().toISOString(),
      config,
    });
    
    _addAgentEvent('dual_init', `Initialized dual agent ${agentId}`, 'server');
    
    res.json({
      success: true,
      agentId,
      message: 'DualAgent initialized',
      status: 'ready',
    });
  } catch (e) {
    console.error('[API] Dual init failed:', e);
    res.status(500).json({ error: 'Failed to initialize dual agent', message: e.message });
  }
});

// POST /api/agent/dual/execute - Run Architect→Coder pipeline
app.post('/api/agent/dual/execute', async (req, res) => {
  const { agentId, prompt, context = {}, stream = false } = req.body;
  
  if (!agentId || !prompt) {
    return res.status(400).json({ error: 'Missing agentId or prompt' });
  }
  
  const agent = state.agents.get(agentId);
  if (!agent) {
    return res.status(404).json({ error: 'Agent not found' });
  }
  
  try {
    // Phase 1: Architect generates plan
    _addAgentEvent('dual_start', `Starting dual pipeline for agent ${agentId}`, 'server');
    
    const architectResult = await runArchitectPhase(prompt, context);
    
    // Phase 2: Coder implements plan
    const coderResult = await runCoderPhase(architectResult.plan, context);
    
    const result = {
      success: true,
      agentId,
      phases: {
        architect: architectResult,
        coder: coderResult,
      },
      output: coderResult.output,
      completedAt: new Date().toISOString(),
    };
    
    _addAgentEvent('dual_complete', `Dual pipeline completed for agent ${agentId}`, 'server');
    
    res.json(result);
  } catch (e) {
    console.error('[API] Dual execute failed:', e);
    _addAgentEvent('dual_error', `Dual pipeline failed: ${e.message}`, 'server');
    res.status(500).json({ error: 'Pipeline failed', message: e.message });
  }
});

async function runArchitectPhase(prompt, context) {
  // Mock architect phase
  await new Promise(r => setTimeout(r, 500));
  
  return {
    phase: 'architect',
    plan: [
      { step: 1, action: 'analyze', description: 'Analyze requirements' },
      { step: 2, action: 'design', description: 'Design solution architecture' },
      { step: 3, action: 'specify', description: 'Create implementation spec' },
    ],
    reasoning: 'Architect analysis complete',
    timestamp: new Date().toISOString(),
  };
}

async function runCoderPhase(plan, context) {
  // Mock coder phase
  await new Promise(r => setTimeout(r, 500));
  
  return {
    phase: 'coder',
    output: `// Generated code based on plan:\n// ${plan.length} steps implemented`,
    filesModified: [],
    timestamp: new Date().toISOString(),
  };
}

function _addAgentEvent(type, detail, source) {
  state.agentEvents.push({
    id: crypto.randomUUID(),
    timestampMs: Date.now(),
    type,
    detail,
    source,
  });
  
  // Keep only last 500 events
  if (state.agentEvents.length > 500) {
    state.agentEvents = state.agentEvents.slice(-500);
  }
}

// ============================================================================
// Legacy Ollama-compatible endpoints (for fallback)
// ============================================================================

// GET /api/tags - Ollama-compatible model list
app.get('/api/tags', async (req, res) => {
  try {
    const models = await callDeep2('listModels', {});
    
    res.json({
      models: models.map(m => ({
        name: m.name,
        model: m.name,
        modified_at: m.modified,
        size: m.size,
        digest: m.id,
        details: {
          format: 'gguf',
          family: m.type,
          parameter_size: 'unknown',
          quantization_level: 'unknown',
        },
      })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/generate - Ollama-compatible generate
app.post('/api/generate', async (req, res) => {
  const { model, prompt, stream = false } = req.body;
  
  // Convert to chat format
  const chatReq = {
    body: {
      model,
      messages: [{ role: 'user', content: prompt }],
      stream,
    },
  };
  
  // Forward to chat handler
  req.body = chatReq.body;
  
  try {
    if (stream) {
      res.setHeader('Content-Type', 'application/x-ndjson');
      
      const mockResponse = {
        model: model || 'default',
        created_at: new Date().toISOString(),
        response: '[RawrXD] Generated response',
        done: false,
      };
      
      res.write(JSON.stringify(mockResponse) + '\n');
      res.write(JSON.stringify({ ...mockResponse, done: true }) + '\n');
      res.end();
    } else {
      res.json({
        model: model || 'default',
        created_at: new Date().toISOString(),
        response: '[RawrXD] Generated response',
        done: true,
        context: [],
      });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================================
// Error Handling
// ============================================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
    method: req.method,
    availableEndpoints: [
      'GET  /health',
      'GET  /status',
      'GET  /api/models',
      'POST /api/model/load',
      'POST /api/model/unload',
      'GET  /api/engine/capabilities',
      'POST /api/chat',
      'POST /v1/chat/completions',
      'GET  /api/agents',
      'GET  /api/agents/status',
      'GET  /api/agents/history',
      'POST /api/agents/replay',
      'POST /api/agent/dual/init',
      'POST /api/agent/dual/execute',
      'GET  /api/tags (Ollama-compatible)',
      'POST /api/generate (Ollama-compatible)',
    ],
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('[Server] Error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
    requestId: req.requestId,
  });
});

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║           RawrXD Backend Server v2.0.0                         ║');
  console.log('║     Browser → :8080 → Sovereign → Deep2/MoE/MASM              ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log();
  console.log('[Config] Port:', CONFIG.port);
  console.log('[Config] Host:', CONFIG.host);
  console.log('[Config] Model Dir:', CONFIG.modelDir);
  console.log('[Config] Deep2 Path:', CONFIG.deep2Path);
  console.log();
  
  // Initialize Deep2 runtime
  await initDeep2Runtime();
  
  // Start server
  app.listen(CONFIG.port, CONFIG.host, () => {
    console.log(`[Server] Listening on http://${CONFIG.host}:${CONFIG.port}`);
    console.log('[Server] Health check: http://' + CONFIG.host + ':' + CONFIG.port + '/health');
    console.log('[Server] Status: http://' + CONFIG.host + ':' + CONFIG.port + '/status');
    console.log();
    console.log('[Server] Ready for connections');
  });
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[Server] Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n[Server] Shutting down gracefully...');
  process.exit(0);
});

// Run
main().catch(e => {
  console.error('[Server] Fatal error:', e);
  process.exit(1);
});
=======
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const ffi = require('ffi-napi');
const ref = require('ref-napi');

// Load the compiled DLL
let phase3Dll = null;
try {
    phase3Dll = ffi.Library(path.join(__dirname, 'bin', 'Phase3_Agent_Kernel.dll'), {
        'Phase3Initialize': ['pointer', ['pointer', 'pointer']],
        'GenerateTokens': ['int', ['pointer', 'string', 'pointer']],
        'Phase3Shutdown': ['void', ['pointer']],
        'ModelUploader_CreateContext': ['pointer', []],
        'ModelUploader_ShowDialog': ['int', ['pointer', 'pointer', 'uint32']],
        'ModelUploader_LoadFiles': ['int', ['pointer', 'string']],
        'ModelUploader_GetProgress': ['int', ['pointer', 'pointer', 'pointer', 'string', 'uint32']],
        'ModelUploader_UnloadModel': ['void', ['pointer']],
        'ModelUploader_GetTensor': ['int', ['pointer', 'string', 'pointer', 'pointer']],
        'DragDrop_RegisterWindow': ['int', ['pointer']],
        'DragDrop_HandleMessage': ['int', ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']]
    });
    console.log('✅ Phase-3 Agent Kernel DLL loaded successfully');
} catch (error) {
    console.log('❌ Failed to load DLL:', error.message);
    console.log('🔧 Building DLL first...');
}

// Global context
let agentContext = null;
let uploaderContext = null;

// Initialize contexts
function initializeKernel() {
    try {
        if (!phase3Dll) return false;
        
        // Create uploader context
        uploaderContext = phase3Dll.ModelUploader_CreateContext();
        if (uploaderContext.isNull()) {
            console.log('❌ Failed to create uploader context');
            return false;
        }
        
        console.log('✅ Kernel initialized successfully');
        return true;
    } catch (error) {
        console.log('❌ Kernel initialization failed:', error.message);
        return false;
    }
}

// HTTP Server
const server = http.createServer((req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    const url = new URL(req.url, `http://${req.headers.host}`);
    
    // Serve HTML file
    if (url.pathname === '/' || url.pathname === '/chatbot') {
        const htmlPath = path.join(__dirname, 'gui', 'ide_chatbot.html');
        fs.readFile(htmlPath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end('HTML file not found');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
        return;
    }
    
    // API endpoints
    if (url.pathname === '/api/models') {
        handleModelsRequest(req, res);
    } else if (url.pathname === '/api/upload') {
        handleUploadRequest(req, res);
    } else if (url.pathname === '/api/progress') {
        handleProgressRequest(req, res);
    } else if (url.pathname === '/api/generate') {
        handleGenerateRequest(req, res);
    } else if (url.pathname === '/ask') {
        handleAskRequest(req, res);
    } else {
        res.writeHead(404);
        res.end('Not found');
    }
});

// Handle model listing
function handleModelsRequest(req, res) {
    const models = [
        { id: 'phase3-native', name: 'Phase-3 Native (120B)', type: 'native', status: 'ready' },
        { id: 'chatbot-fallback', name: 'Chatbot Fallback', type: 'fallback', status: 'ready' }
    ];
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ models }));
}

// Handle file upload
function handleUploadRequest(req, res) {
    if (req.method !== 'POST') {
        res.writeHead(405);
        res.end('Method not allowed');
        return;
    }
    
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
        try {
            const { files } = JSON.parse(body);
            
            if (!uploaderContext || uploaderContext.isNull()) {
                res.writeHead(500);
                res.end(JSON.stringify({ error: 'Uploader not initialized' }));
                return;
            }
            
            // Process files through DLL
            const result = phase3Dll.ModelUploader_LoadFiles(uploaderContext, files.join(';'));
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                success: result === 1,
                message: result === 1 ? 'Upload started' : 'Upload failed'
            }));
        } catch (error) {
            res.writeHead(500);
            res.end(JSON.stringify({ error: error.message }));
        }
    });
}

// Handle progress polling
function handleProgressRequest(req, res) {
    if (!uploaderContext || uploaderContext.isNull()) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ stage: 0, percent: 0, status: 'Not initialized' }));
        return;
    }
    
    try {
        const stageBuffer = Buffer.alloc(4);
        const percentBuffer = Buffer.alloc(4);
        const statusBuffer = Buffer.alloc(256);
        
        const result = phase3Dll.ModelUploader_GetProgress(
            uploaderContext, 
            stageBuffer, 
            percentBuffer, 
            statusBuffer, 
            256
        );
        
        const stage = stageBuffer.readUInt32LE(0);
        const percent = percentBuffer.readUInt32LE(0);
        const status = statusBuffer.toString('utf8').replace(/\0.*$/, '');
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ stage, percent, status }));
    } catch (error) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: error.message }));
    }
}

// Handle text generation
function handleGenerateRequest(req, res) {
    if (req.method !== 'POST') {
        res.writeHead(405);
        res.end('Method not allowed');
        return;
    }
    
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
        try {
            const { prompt, model } = JSON.parse(body);
            
            if (model === 'phase3-native' && agentContext && !agentContext.isNull()) {
                // Use native DLL
                const outputBuffer = Buffer.alloc(4096);
                const result = phase3Dll.GenerateTokens(agentContext, prompt, outputBuffer);
                
                if (result === 1) {
                    const response = outputBuffer.toString('utf8').replace(/\0.*$/, '');
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ response }));
                } else {
                    throw new Error('Generation failed');
                }
            } else {
                // Fallback to simple responses
                const responses = [
                    "I'm the RawrXD IDE Assistant! I can help with model loading, file management, and development tasks.",
                    "To load a 120B model, use the file uploader above. I support GGUF, Safetensors, and PyTorch formats.",
                    "For swarm operations, check the swarm directory and use the swarm management tools.",
                    "Need help with todos? Use the todo system to track your development tasks.",
                    "Graphics drivers can be updated through the driver management panel."
                ];
                
                const response = responses[Math.floor(Math.random() * responses.length)];
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ response }));
            }
        } catch (error) {
            res.writeHead(500);
            res.end(JSON.stringify({ error: error.message }));
        }
    });
}

// Handle ask requests (compatibility)
function handleAskRequest(req, res) {
    handleGenerateRequest(req, res);
}

// Auto-build DLL if missing
function buildDllIfNeeded() {
    const dllPath = path.join(__dirname, 'bin', 'Phase3_Agent_Kernel.dll');
    if (!fs.existsSync(dllPath)) {
        console.log('🔧 DLL not found, building...');
        
        const buildScript = path.join(__dirname, 'build_phase3.bat');
        const build = spawn('cmd', ['/c', buildScript], { 
            stdio: 'inherit',
            cwd: __dirname 
        });
        
        build.on('close', (code) => {
            if (code === 0) {
                console.log('✅ Build successful, restarting server...');
                process.exit(0); // Restart to load new DLL
            } else {
                console.log('❌ Build failed with code:', code);
            }
        });
        
        return false;
    }
    return true;
}

// Start server
const PORT = 8080;

if (buildDllIfNeeded()) {
    if (initializeKernel()) {
        server.listen(PORT, () => {
            console.log(`🚀 RawrXD IDE Chatbot Server running on http://localhost:${PORT}`);
            console.log(`📁 Serving HTML from: ${path.join(__dirname, 'gui', 'ide_chatbot.html')}`);
            console.log(`🧠 Phase-3 Agent Kernel: ${phase3Dll ? 'Loaded' : 'Fallback mode'}`);
        });
    } else {
        console.log('⚠️  Starting in fallback mode (DLL not available)');
        server.listen(PORT, () => {
            console.log(`🚀 RawrXD IDE Chatbot Server running on http://localhost:${PORT} (Fallback Mode)`);
        });
    }
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

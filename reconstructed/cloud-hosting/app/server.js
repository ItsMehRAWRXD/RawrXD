const http = require("http");
const { Pool } = require("pg");
const Redis = require("ioredis");
const crypto = require("crypto");

const PORT = parseInt(process.env.PORT || "3000", 10);
const API_KEY = process.env.API_KEY || "";
const JWT_SECRET = process.env.JWT_SECRET || "";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});
const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379", {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 200, 5000),
});

const routes = new Map();

function route(method, path, handler, { auth = true } = {}) {
  routes.set(`${method}:${path}`, { handler, auth });
}

function json(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(data));
}

function setCors(req, res) {
  res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,X-API-Key,Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
}

function validateApiKey(req) {
  if (!API_KEY) return true; // no key configured = open (dev mode)
  const provided = req.headers["x-api-key"] || "";
  return provided.length > 0 && crypto.timingSafeEqual(
    Buffer.from(provided.padEnd(256, "\0")),
    Buffer.from(API_KEY.padEnd(256, "\0"))
  );
}

function parseBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > maxBytes) { req.destroy(); reject(new Error("Payload too large")); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
      catch { resolve({}); }
    });
    req.on("error", reject);
  });
}

// ── Routes ──────────────────────────────────────────────────────────────────
route("GET", "/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    await redis.ping();
    json(res, 200, { status: "healthy", uptime: process.uptime() });
  } catch (err) {
    json(res, 503, { status: "unhealthy", error: err.message });
  }
}, { auth: false });

route("GET", "/api/status", async (_req, res) => {
  const cached = await redis.get("status");
  if (cached) return json(res, 200, JSON.parse(cached));

  const { rows } = await pool.query(
    "SELECT COUNT(*) as total FROM information_schema.tables WHERE table_schema = 'public'"
  );
  const data = { tables: parseInt(rows[0].total), ts: Date.now() };
  await redis.setex("status", 60, JSON.stringify(data));
  json(res, 200, data);
});

route("POST", "/api/data", async (req, res) => {
  const body = await parseBody(req);
  if (!body.key || typeof body.key !== "string" || body.key.length > 256) {
    return json(res, 400, { error: "key required (string, max 256 chars)" });
  }
  if (body.value === undefined || body.value === null) {
    return json(res, 400, { error: "value required" });
  }

  await pool.query(
    "INSERT INTO kv_store (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
    [body.key, JSON.stringify(body.value)]
  );
  await redis.del(`kv:${body.key}`);
  json(res, 201, { ok: true });
});

route("GET", "/api/data", async (req, res) => {
  const url = new URL(req.url, `http://localhost`);
  const key = url.searchParams.get("key");
  if (!key || key.length > 256) return json(res, 400, { error: "key query param required (max 256 chars)" });

  const cached = await redis.get(`kv:${key}`);
  if (cached) return json(res, 200, JSON.parse(cached));

  const { rows } = await pool.query("SELECT value FROM kv_store WHERE key = $1", [key]);
  if (rows.length === 0) return json(res, 404, { error: "not found" });

  const result = { key, value: JSON.parse(rows[0].value) };
  await redis.setex(`kv:${key}`, 300, JSON.stringify(result));
  json(res, 200, result);
});

route("DELETE", "/api/data", async (req, res) => {
  const url = new URL(req.url, `http://localhost`);
  const key = url.searchParams.get("key");
  if (!key || key.length > 256) return json(res, 400, { error: "key query param required (max 256 chars)" });

  const { rowCount } = await pool.query("DELETE FROM kv_store WHERE key = $1", [key]);
  if (rowCount === 0) return json(res, 404, { error: "not found" });

  await redis.del(`kv:${key}`);
  await pool.query(
    "INSERT INTO audit_log (action, entity, details) VALUES ($1, $2, $3)",
    ["delete", "kv_store", JSON.stringify({ key })]
  );
  json(res, 200, { ok: true, deleted: key });
});

// ── Rate Limiter (in-memory, per IP) ────────────────────────────────────────
const rateLimits = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 120;

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = rateLimits.get(ip);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    entry = { windowStart: now, count: 0 };
    rateLimits.set(ip, entry);
  }
  entry.count++;
  return entry.count <= RATE_MAX_REQUESTS;
}

// Periodic cleanup of stale rate-limit entries
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS * 2;
  for (const [ip, entry] of rateLimits) {
    if (entry.windowStart < cutoff) rateLimits.delete(ip);
  }
}, RATE_WINDOW_MS);

// ── Server ──────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const start = Date.now();
  setCors(req, res);

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://localhost`);
  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;

  // Rate limiting
  if (!checkRateLimit(clientIp)) {
    console.warn(`[RATE] ${clientIp} exceeded ${RATE_MAX_REQUESTS} req/${RATE_WINDOW_MS}ms`);
    json(res, 429, { error: "Too Many Requests" });
    return;
  }

  const entry = routes.get(`${req.method}:${url.pathname}`);

  if (!entry) {
    console.log(`[${req.method}] ${url.pathname} 404 ${Date.now() - start}ms — ${clientIp}`);
    return json(res, 404, { error: "Not Found" });
  }

  // API key check
  if (entry.auth && !validateApiKey(req)) {
    console.warn(`[AUTH] 401 ${req.method} ${url.pathname} — ${clientIp}`);
    return json(res, 401, { error: "Unauthorized — provide X-API-Key header" });
  }

  try {
    await entry.handler(req, res);
    console.log(`[${req.method}] ${url.pathname} ${res.statusCode} ${Date.now() - start}ms — ${clientIp}`);
  } catch (err) {
    console.error(`[ERR] ${req.method} ${url.pathname}:`, err);
    json(res, 500, { error: "Internal Server Error" });
  }
});

server.listen(PORT, () => console.log(`[RawrXD] Server listening on :${PORT}`));

process.on("SIGTERM", async () => {
  console.log("[RawrXD] Graceful shutdown...");
  server.close();
  await pool.end();
  redis.disconnect();
  process.exit(0);
});

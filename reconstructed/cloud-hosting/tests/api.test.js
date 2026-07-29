#!/usr/bin/env node
// ============================================================================
// RawrXD Cloud Hosting — API Integration Tests
// ============================================================================
// Usage: DATABASE_URL=... REDIS_URL=... API_KEY=test node tests/api.test.js
// Exit 0 = all pass, Exit 1 = failures
// ============================================================================

const http = require("http");

const BASE = `http://localhost:${process.env.PORT || 3000}`;
const API_KEY = process.env.API_KEY || "test-key";

let passed = 0;
let failed = 0;

async function request(method, path, body = null, headers = {}) {
  const url = new URL(path, BASE);
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...headers },
    };
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString();
        let data;
        try { data = JSON.parse(raw); } catch { data = raw; }
        resolve({ status: res.statusCode, data, headers: res.headers });
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function assert(name, condition) {
  if (condition) {
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } else {
    failed++;
    console.error(`  \x1b[31m✗\x1b[0m ${name}`);
  }
}

async function run() {
  console.log("\n╔═══════════════════════════════════════════╗");
  console.log("║  RawrXD Cloud API Tests                   ║");
  console.log("╚═══════════════════════════════════════════╝\n");

  // ── Health ──
  console.log("[Health]");
  const health = await request("GET", "/health", null, { "X-API-Key": "" });
  assert("GET /health returns 200", health.status === 200);
  assert("status is healthy", health.data?.status === "healthy");

  // ── Auth ──
  console.log("\n[Auth]");
  const noKey = await request("GET", "/api/status", null, { "X-API-Key": "" });
  assert("Missing API key returns 401", noKey.status === 401);

  const badKey = await request("GET", "/api/status", null, { "X-API-Key": "wrong-key" });
  assert("Bad API key returns 401", badKey.status === 401);

  // ── Status ──
  console.log("\n[Status]");
  const status = await request("GET", "/api/status");
  assert("GET /api/status returns 200", status.status === 200);
  assert("Has tables count", typeof status.data?.tables === "number");

  // ── CRUD: Create ──
  console.log("\n[CRUD]");
  const testKey = `test_${Date.now()}`;
  const create = await request("POST", "/api/data", { key: testKey, value: { msg: "hello" } });
  assert("POST /api/data returns 201", create.status === 201);
  assert("POST result ok", create.data?.ok === true);

  // ── CRUD: Read ──
  const read = await request("GET", `/api/data?key=${testKey}`);
  assert("GET /api/data returns 200", read.status === 200);
  assert("GET returns correct key", read.data?.key === testKey);
  assert("GET returns correct value", read.data?.value?.msg === "hello");

  // ── CRUD: Update (upsert) ──
  const update = await request("POST", "/api/data", { key: testKey, value: { msg: "updated" } });
  assert("Upsert returns 201", update.status === 201);
  const readUpdated = await request("GET", `/api/data?key=${testKey}`);
  assert("Updated value reads back", readUpdated.data?.value?.msg === "updated");

  // ── CRUD: Delete ──
  const del = await request("DELETE", `/api/data?key=${testKey}`);
  assert("DELETE returns 200", del.status === 200);
  assert("DELETE confirms key", del.data?.deleted === testKey);

  const readAfterDel = await request("GET", `/api/data?key=${testKey}`);
  assert("GET after DELETE returns 404", readAfterDel.status === 404);

  // ── CRUD: Delete non-existent ──
  const delMissing = await request("DELETE", `/api/data?key=nonexistent_key_${Date.now()}`);
  assert("DELETE missing key returns 404", delMissing.status === 404);

  // ── Validation ──
  console.log("\n[Validation]");
  const noBody = await request("POST", "/api/data", {});
  assert("POST without key returns 400", noBody.status === 400);

  const noValue = await request("POST", "/api/data", { key: "x" });
  assert("POST without value returns 400", noValue.status === 400);

  const badKeyLen = await request("GET", `/api/data?key=${"x".repeat(300)}`);
  assert("Overlong key returns 400", badKeyLen.status === 400);

  // ── 404 ──
  console.log("\n[Routing]");
  const notFound = await request("GET", "/nonexistent");
  assert("Unknown route returns 404", notFound.status === 404);

  // ── CORS ──
  console.log("\n[Security]");
  assert("Has CORS header", !!health.headers["access-control-allow-origin"]);
  assert("Has X-Content-Type-Options", health.headers["x-content-type-options"] === "nosniff");
  assert("Has X-Frame-Options", health.headers["x-frame-options"] === "DENY");
  assert("Has Cache-Control no-store", health.headers["cache-control"] === "no-store");

  // ── Summary ──
  console.log(`\n${"═".repeat(44)}`);
  console.log(`  Passed: ${passed}  Failed: ${failed}  Total: ${passed + failed}`);
  console.log(`${"═".repeat(44)}\n`);

  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("Test harness error:", err);
  process.exit(1);
});

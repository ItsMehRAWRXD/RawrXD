(() => {
  "use strict";

  const API_BASE =
    (location.protocol === "http:" &&
      (location.hostname === "127.0.0.1" || location.hostname === "localhost"))
      ? `${location.protocol}//${location.host}`
      : "http://127.0.0.1:11437";

  let sessionToken = "";
  let currentMode = "agent";
  let activeRequestId = "";

  const $ = (sel) => document.querySelector(sel);

  const els = {
    prompt: $("#rawrPrompt"),
    send: $("#rawrSend"),
    stop: $("#rawrStop"),
    output: $("#rawrOutput"),
    model: $("#rawrModel"),
    workspace: $("#rawrWorkspace"),
    status: $("#rawrStatus"),
    modes: [...document.querySelectorAll("[data-rawr-mode]")]
  };

  function setStatus(text) {
    if (els.status) els.status.textContent = text;
  }

  function appendOutput(text) {
    if (!els.output) return;
    els.output.textContent += text;
    els.output.scrollTop = els.output.scrollHeight;
  }

  function setMode(mode) {
    currentMode = mode;
    for (const btn of els.modes) {
      btn.classList.toggle("active", btn.dataset.rawrMode === mode);
      btn.setAttribute("aria-pressed", btn.dataset.rawrMode === mode ? "true" : "false");
    }
    setStatus(`mode: ${mode.toUpperCase()}`);
  }

  async function ensureSession() {
    if (sessionToken) return sessionToken;
    const r = await fetch(`${API_BASE}/api/session`, { method: "POST" });
    if (!r.ok) throw new Error(`session failed: HTTP ${r.status}`);
    const j = await r.json();
    sessionToken = j.token;
    return sessionToken;
  }

  async function health() {
    try {
      const r = await fetch(`${API_BASE}/api/health`, { cache: "no-store" });
      const j = await r.json();
      if (!r.ok || !j.ok) throw new Error(j.error || `HTTP ${r.status}`);
      setStatus(`local bridge online · ${currentMode.toUpperCase()}`);
      return j;
    } catch (e) {
      setStatus("local bridge offline");
      throw e;
    }
  }

  async function runAgent() {
    const prompt = els.prompt?.value?.trim() || "";
    const model = els.model?.value?.trim() || "";
    const workspace = els.workspace?.value?.trim() || "";
    if (!prompt || !model || !workspace) {
      setStatus("model, workspace and prompt are required");
      return;
    }

    await ensureSession();

    activeRequestId =
      (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);

    if (els.output) els.output.textContent = "";
    if (els.send) els.send.disabled = true;
    if (els.stop) els.stop.disabled = false;
    setStatus(`running · ${currentMode.toUpperCase()}`);

    try {
      const r = await fetch(`${API_BASE}/api/agent/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-RawrXD-Session": sessionToken
        },
        body: JSON.stringify({
          requestId: activeRequestId,
          mode: currentMode,
          model,
          workspace,
          prompt
        })
      });

      if (!r.ok) {
        const body = await r.text();
        throw new Error(`run failed: HTTP ${r.status} ${body}`);
      }

      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let pending = "";

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        pending += decoder.decode(value, { stream: true });

        let nl;
        while ((nl = pending.indexOf("\n")) >= 0) {
          const line = pending.slice(0, nl).trim();
          pending = pending.slice(nl + 1);
          if (!line) continue;

          let evt;
          try { evt = JSON.parse(line); }
          catch { appendOutput(line + "\n"); continue; }

          if (evt.type === "output") appendOutput(evt.data || "");
          else if (evt.type === "started") setStatus(`running · ${currentMode.toUpperCase()}`);
          else if (evt.type === "exit") {
            setStatus(`finished · exit ${evt.data}`);
          } else if (evt.type === "bridge_error") {
            appendOutput(`\n[bridge] ${evt.data}\n`);
            setStatus("bridge error");
          }
        }
      }
    } catch (e) {
      appendOutput(`\n[ScreenPilot] ${e.message}\n`);
      setStatus("run failed");
    } finally {
      activeRequestId = "";
      if (els.send) els.send.disabled = false;
      if (els.stop) els.stop.disabled = true;
    }
  }

  async function stopAgent() {
    if (!activeRequestId) return;
    try {
      await ensureSession();
      await fetch(`${API_BASE}/api/agent/cancel`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-RawrXD-Session": sessionToken
        },
        body: JSON.stringify({ requestId: activeRequestId })
      });
      setStatus("cancellation requested");
    } catch (e) {
      appendOutput(`\n[ScreenPilot] cancel failed: ${e.message}\n`);
    }
  }

  for (const btn of els.modes) {
    btn.addEventListener("click", () => setMode(btn.dataset.rawrMode));
  }

  els.send?.addEventListener("click", runAgent);
  els.stop?.addEventListener("click", stopAgent);
  els.prompt?.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runAgent();
  });

  window.ScreenPilotAgent = {
    health,
    run: runAgent,
    stop: stopAgent,
    setMode
  };

  setMode("agent");
  health().catch(() => {});
})();

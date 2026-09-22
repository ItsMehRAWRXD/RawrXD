(() => {
  "use strict";

  const API = "/api/v1/screenpilot";
  let token = "";
  let mode = "agent";
  let activeRequestId = "";

  const q = (s) => document.querySelector(s);
  const qa = (s) => [...document.querySelectorAll(s)];

  const el = {
    model: q("#rawrModel"),
    workspace: q("#rawrWorkspace"),
    prompt: q("#rawrPrompt"),
    send: q("#rawrSend"),
    stop: q("#rawrStop"),
    output: q("#rawrOutput"),
    status: q("#rawrStatus"),
    modes: qa("[data-rawr-mode]")
  };

  function status(s) {
    if (el.status) el.status.textContent = s;
  }

  function append(s) {
    if (!el.output) return;
    el.output.textContent += s;
    el.output.scrollTop = el.output.scrollHeight;
  }

  function setMode(m) {
    mode = m;
    for (const b of el.modes) {
      const on = b.dataset.rawrMode === m;
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    }
    status(`mode: ${m.toUpperCase()}`);
  }

  async function session() {
    if (token) return token;
    const r = await fetch(`${API}/session`, {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin"
    });
    if (!r.ok) throw new Error(`session HTTP ${r.status}`);
    const j = await r.json();
    if (!j.token) throw new Error("session token missing");
    token = j.token;
    return token;
  }

  async function health() {
    const r = await fetch(`${API}/health`, {
      cache: "no-store",
      credentials: "same-origin"
    });
    if (!r.ok) throw new Error(`health HTTP ${r.status}`);
    const j = await r.json();
    status(`local · canonical authority · ${mode.toUpperCase()}`);
    return j;
  }

  async function run() {
    const model = el.model?.value?.trim() || "";
    const workspace = el.workspace?.value?.trim() || "";
    const prompt = el.prompt?.value?.trim() || "";

    if (!model || !workspace || !prompt) {
      status("model, workspace and prompt required");
      return;
    }

    await session();

    activeRequestId = crypto.randomUUID
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;

    if (el.output) el.output.textContent = "";
    if (el.send) el.send.disabled = true;
    if (el.stop) el.stop.disabled = false;
    status(`running · ${mode.toUpperCase()}`);

    try {
      const r = await fetch(`${API}/agent/run`, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-RawrXD-Session": token
        },
        body: JSON.stringify({
          requestId: activeRequestId,
          mode,
          model,
          workspace,
          prompt
        })
      });

      if (!r.ok) throw new Error(`run HTTP ${r.status}: ${await r.text()}`);
      if (!r.body) throw new Error("stream body unavailable");

      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let pending = "";

      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        pending += decoder.decode(value, {stream:true});

        let nl;
        while ((nl = pending.indexOf("\n")) >= 0) {
          const line = pending.slice(0, nl).trim();
          pending = pending.slice(nl + 1);
          if (!line) continue;

          let evt;
          try { evt = JSON.parse(line); }
          catch { append(line + "\n"); continue; }

          if (evt.type === "output" ||
              evt.type === "assistant" ||
              evt.type === "tool" ||
              evt.type === "receipt") {
            append(evt.data || "");
            if (!String(evt.data || "").endsWith("\n")) append("\n");
          } else if (evt.type === "started") {
            status(`running · ${mode.toUpperCase()}`);
          } else if (evt.type === "exit") {
            status(`finished · exit ${evt.data}`);
          }
        }
      }
    } catch (e) {
      append(`[ScreenPilot] ${e.message}\n`);
      status("run failed");
    } finally {
      activeRequestId = "";
      if (el.send) el.send.disabled = false;
      if (el.stop) el.stop.disabled = true;
    }
  }

  async function stop() {
    if (!activeRequestId) return;
    await session();
    await fetch(`${API}/agent/cancel`, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-RawrXD-Session": token
      },
      body: JSON.stringify({requestId: activeRequestId})
    });
    status("cancellation requested");
  }

  for (const b of el.modes) {
    b.addEventListener("click", () => setMode(b.dataset.rawrMode));
  }
  el.send?.addEventListener("click", run);
  el.stop?.addEventListener("click", stop);
  el.prompt?.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run();
  });

  window.ScreenPilotAgent = {health, run, stop, setMode};
  setMode("agent");
  health().catch(e => status(`offline · ${e.message}`));
})();

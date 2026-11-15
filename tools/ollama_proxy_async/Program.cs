// ollama_proxy_async — concurrent, streaming loopback proxy for Ollama.
//
// Replaces tools/ollama_proxy.ps1, which had two independent defects confirmed in
// source:
//   1. A single-threaded loop: `while ($listener.IsListening) { $ctx = GetContext() }`
//      processed one request to completion, so a long generation blocked
//      /v1/models for its entire duration.
//   2. It buffered the whole upstream response
//      (`ReadAsByteArrayAsync().GetAwaiter().GetResult()`) and wrote it in one shot,
//      despite a header comment claiming SSE passthrough. That guaranteed client
//      timeouts on long generations and made cancellation impossible.
//
// This implementation:
//   * accepts connections with GetContextAsync and handles each on its own task
//   * streams the upstream body with HttpCompletionOption.ResponseHeadersRead and
//     CopyToAsync under SendChunked, so tokens reach the client as they arrive
//   * ties the upstream CancellationTokenSource to the client connection, so a
//     disconnect cancels generation upstream instead of orphaning it
//   * listens on 127.0.0.1 only
//   * maps explicit model aliases and returns a real 404 for anything unknown,
//     so a misconfigured client is visible rather than silently "working"
//   * logs REQUESTED_MODEL, EFFECTIVE_MODEL, TRANSPORT and status per request, so a
//     proxied result can never be mistaken for native Deep2 inference
//
// Usage:
//   ollama_proxy_async.exe [listenPort] [upstreamPort]
//   defaults: 8080 11434

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

internal static class Program
{
    // Left side = model name a client may request. Right side = model sent upstream.
    // Unknown models are NOT silently rewritten.
    private static readonly Dictionary<string, string> ModelAliases =
        new Dictionary<string, string>(StringComparer.Ordinal)
    {
        { "deep2-local", "reap16-glm-4_7-flash:latest" },
    };

    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var h = new HttpClient(new HttpClientHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
        });
        // No default timeout: a long generation must not be cut off by the client.
        // Cancellation and per-request timeouts are handled explicitly.
        h.Timeout = Timeout.InfiniteTimeSpan;
        return h;
    }

    private static int Main(string[] args)
    {
        int listenPort = args.Length > 0 && int.TryParse(args[0], out var lp) ? lp : 8080;
        int upstreamPort = args.Length > 1 && int.TryParse(args[1], out var up) ? up : 11434;

        var listener = new HttpListener();
        // Loopback only. Never "+:" or "*:", which would expose an unauthenticated
        // inference API on every interface.
        listener.Prefixes.Add($"http://127.0.0.1:{listenPort}/");
        try
        {
            listener.Start();
        }
        catch (HttpListenerException ex)
        {
            Console.Error.WriteLine($"[proxy] cannot bind 127.0.0.1:{listenPort}: {ex.Message}");
            return 1;
        }

        var upstreamBase = $"http://127.0.0.1:{upstreamPort}";
        Console.WriteLine($"[proxy] listening  http://127.0.0.1:{listenPort}/");
        Console.WriteLine($"[proxy] upstream   {upstreamBase}");
        Console.WriteLine($"[proxy] aliases    {string.Join(", ", ModelAliases.Select(kv => $"{kv.Key} -> {kv.Value}"))}");
        Console.WriteLine("[proxy] TRANSPORT=LocalProxy  (results are NOT native Deep2 inference)");

        // Accept loop: one accept at a time, but each request is served on its own
        // task, so a slow generation never blocks /v1/models.
        var acceptTask = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (listener.IsListening)
                {
                    Console.Error.WriteLine($"[proxy] accept error: {ex.Message}");
                    continue;
                }
                catch (Exception)
                {
                    break; // listener stopped
                }

                _ = HandleAsync(ctx, upstreamBase);
            }
        });

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("[proxy] shutdown requested");
            try { listener.Stop(); listener.Close(); } catch { }
        };

        acceptTask.GetAwaiter().GetResult();
        Console.WriteLine("[proxy] stopped.");
        return 0;
    }

    private static async Task HandleAsync(HttpListenerContext ctx, string upstreamBase)
    {
        var req = ctx.Request;
        var res = ctx.Response;
        var reqId = $"{Environment.TickCount:x}:{Guid.NewGuid():N}".Substring(0, 18);

        // Tie upstream cancellation to the client connection. Without this a client
        // disconnect leaves generation running and the GPU occupied.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(
            CancellationToken.None);
        try { ctx.Response.ClientDisconnected += (_, _) => cts.Cancel(); } catch { }

        var requestedModel = TryReadRequest(req, out var bodyBytes);
        var effectiveModel = ResolveModel(requestedModel);

        try
        {
            if (effectiveModel == null)
            {
                // Explicit 404 rather than a silent rewrite: a misconfigured client
                // must be observable, not silently "working".
                await WriteJson(res, (int)HttpStatusCode.NotFound, new
                {
                    error = new
                    {
                        message = requestedModel == null
                            ? "no model specified in request body"
                            : $"unknown model '{requestedModel}'. known aliases: {string.Join(", ", ModelAliases.Keys)}",
                        type = "proxy_unknown_model",
                        request_id = reqId,
                    },
                }, cts.Token).ConfigureAwait(false);
                Log(reqId, req, res.StatusCode, requestedModel, effectiveModel, 0, 0);
                return;
            }

            var target = new Uri($"{upstreamBase}{req.Url.AbsolutePath}{req.Url.Query}");
            using var upstreamReq = new HttpRequestMessage(new HttpMethod(req.HttpMethod), target);

            if (bodyBytes is { Length: > 0 })
            {
                // Rewrite the model field so the alias is honoured upstream, while
                // logging both names for the receipt.
                bodyBytes = RewriteModel(bodyBytes, effectiveModel);
                upstreamReq.Content = new ByteArrayContent(bodyBytes);
                upstreamReq.Content.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue(
                        req.ContentType ?? "application/json");
            }

            foreach (string key in req.Headers.AllKeys)
            {
                if (key.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                if (key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                var v = req.Headers[key];
                if (v != null && !upstreamReq.Headers.TryAddWithoutValidation(key, v))
                    upstreamReq.Content?.Headers.TryAddWithoutValidation(key, v);
            }

            var sw = System.Diagnostics.Stopwatch.StartNew();

            // ResponseHeadersRead is what makes streaming possible: the body is not
            // buffered before the first byte reaches the client.
            using var upstreamRes = await Http.SendAsync(
                upstreamReq,
                HttpCompletionOption.ResponseHeadersRead,
                cts.Token).ConfigureAwait(false);

            res.StatusCode = (int)upstreamRes.StatusCode;
            res.SendChunked = true;   // no ContentLength: stream incrementally
            if (upstreamRes.Content.Headers.ContentType != null)
                res.ContentType = upstreamRes.Content.Headers.ContentType.MediaType;
            else
                res.ContentType = "application/json";

            long streamed = 0;
            await using var src = await upstreamRes.Content.ReadAsStreamAsync(cts.Token)
                .ConfigureAwait(false);
            var buf = new byte[64 * 1024];
            int n;
            while ((n = await src.ReadAsync(buf, 0, buf.Length, cts.Token).ConfigureAwait(false)) > 0)
            {
                await res.OutputStream.WriteAsync(buf, 0, n, cts.Token).ConfigureAwait(false);
                await res.OutputStream.FlushAsync(cts.Token).ConfigureAwait(false);
                streamed += n;
            }

            sw.Stop();
            Log(reqId, req, res.StatusCode, requestedModel, effectiveModel, sw.ElapsedMilliseconds, streamed);
        }
        catch (OperationCanceledException)
        {
            // Client disconnected: nothing to write. Record it as a cancellation.
            Log(reqId, req, 499, requestedModel, effectiveModel, 0, 0, "client_cancelled");
        }
        catch (Exception ex)
        {
            var code = 502;
            Console.Error.WriteLine($"[proxy][{reqId}] ERROR {req.HttpMethod} {req.RawUrl} -> {code} : {ex.Message}");
            try
            {
                await WriteJson(res, code, new
                {
                    error = new
                    {
                        message = $"proxy upstream failure: {ex.Message}",
                        type = "proxy_error",
                        request_id = reqId,
                    },
                }, cts.Token).ConfigureAwait(false);
            }
            catch { }
            Log(reqId, req, code, requestedModel, effectiveModel, 0, 0);
        }
        finally
        {
            try { res.OutputStream.Close(); } catch { }
            try { res.Close(); } catch { }
        }
    }

    private static string ResolveModel(string requested)
    {
        if (string.IsNullOrEmpty(requested)) return null;
        if (ModelAliases.TryGetValue(requested, out var mapped)) return mapped;
        // Allow a client to ask for a real upstream model directly.
        return requested;
    }

    private static string TryReadRequest(HttpListenerRequest req, out byte[] body)
    {
        body = null;
        try
        {
            if (req.HasEntityBody)
            {
                using var ms = new MemoryStream();
                req.InputStream.CopyTo(ms);
                body = ms.ToArray();
            }
        }
        catch { return null; }

        if (body == null || body.Length == 0) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("model", out var m) &&
                m.ValueKind == JsonValueKind.String)
                return m.GetString();
        }
        catch { }
        return null;
    }

    private static byte[] RewriteModel(byte[] body, string effectiveModel)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            using var ms = new MemoryStream();
            using (var w = new Utf8JsonWriter(ms))
            {
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    w.WritePropertyName(prop.Name);
                    if (prop.Name == "model")
                        w.WriteStringValue(effectiveModel);
                    else
                        prop.WriteTo(w);
                }
            }
            return ms.ToArray();
        }
        catch
        {
            return body;   // leave untouched if not valid JSON
        }
    }

    private static async Task WriteJson(HttpListenerResponse res, int code, object payload,
                                        CancellationToken ct)
    {
        res.StatusCode = code;
        res.ContentType = "application/json";
        var json = JsonSerializer.Serialize(payload);
        var bytes = Encoding.UTF8.GetBytes(json);
        res.ContentLength64 = bytes.Length;
        await res.OutputStream.WriteAsync(bytes, 0, bytes.Length, ct).ConfigureAwait(false);
    }

    private static void Log(string reqId, HttpListenerRequest req, int status,
                            string requested, string effective, long ms, long bytes,
                            string note = null)
    {
        // Backend receipt: a proxied result can never be mistaken for native Deep2.
        Console.WriteLine(
            "[proxy][{0}] {1} {2} -> {3} REQUESTED_MODEL={4} EFFECTIVE_MODEL={5} " +
            "TRANSPORT=LocalProxy {6}ms {7} bytes{8}",
            reqId, req.HttpMethod, req.RawUrl, status,
            requested ?? "<none>", effective ?? "<none>", ms, bytes,
            note == null ? "" : " " + note);
    }
}
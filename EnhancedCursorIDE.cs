// EnhancedCursorIDE.cs  --  csc /r:System.Net.Http.dll EnhancedCursorIDE.cs EditorCLI.cs
using System;
using System.Collections;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

public sealed class EnhancedCursorIDE
{
    private static readonly string[] Providers = { "openai", "gemini", "claude" };

    private readonly HttpClient _client = new HttpClient();
    private readonly Dictionary<string, string> _keys = new Dictionary<string, string>();
    private string _active = "openai";

    public Task<string> Complete(string code)
    {
        switch (_active)
        {
            case "openai": return OpenAi(code);
            case "gemini": return Gemini(code);
            case "claude": return Claude(code);
            default: return Task.FromException<string>(new InvalidOperationException("Unknown provider"));
        }
    }

    private Task<string> OpenAi(string code)
    {
        var payload = new Dictionary<string, object>
        {
            ["model"] = "gpt-3.5-turbo",
            ["messages"] = new[] { new Dictionary<string, string> { ["role"] = "user", ["content"] = code } }
        };
        var req = new HttpRequestMessage(HttpMethod.Post, "https://api.openai.com/v1/chat/completions");
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Key("openai"));
        return Send(req, payload, r => Str(At(At(At(r, "choices"), 0), "message"), "content"));
    }

    private Task<string> Gemini(string code)
    {
        var payload = new Dictionary<string, object>
        {
            ["contents"] = new[]
            {
                new Dictionary<string, object>
                {
                    ["parts"] = new[] { new Dictionary<string, string> { ["text"] = code } }
                }
            }
        };
        var req = new HttpRequestMessage(HttpMethod.Post,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=" + Key("gemini"));
        return Send(req, payload, r => Str(At(At(At(At(At(r, "candidates"), 0), "content"), "parts"), 0), "text"));
    }

    private Task<string> Claude(string code)
    {
        var payload = new Dictionary<string, object>
        {
            ["model"] = "claude-3-haiku-20240307",
            ["messages"] = new[] { new Dictionary<string, string> { ["role"] = "user", ["content"] = code } }
        };
        var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages");
        req.Headers.TryAddWithoutValidation("x-api-key", Key("claude"));
        return Send(req, payload, r => Str(At(At(r, "content"), 0), "text"));
    }

    private async Task<string> Send(HttpRequestMessage req, object payload, Func<object, string> extract)
    {
        // Serialize through the JSON serializer so the snippet is escaped correctly.
        req.Content = new StringContent(new JavaScriptSerializer().Serialize(payload), Encoding.UTF8, "application/json");
        try
        {
            var resp = await _client.SendAsync(req).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return "Error: " + (int)resp.StatusCode;
            var v = extract(new JavaScriptSerializer().DeserializeObject(body));
            return v ?? "Error: missing field";
        }
        catch (HttpRequestException ex) { return "Error: " + ex.Message; }
    }

    // At: index into a JSON array by int, or fetch a member by name.
    private static object At(object node, object key)
    {
        if (node is ArrayList list) return key is int i && i >= 0 && i < list.Count ? list[i] : null;
        if (node is Dictionary<string, object> map && key is string name) return map.TryGetValue(name, out var v) ? v : null;
        return null;
    }

    private static string Str(object node, string key) => At(node, key) as string;

    private string Key(string provider) => _keys.TryGetValue(provider, out var k) ? k : "";

    public void SetApiKey(string provider, string key) => _keys[provider] = key;
    public void SwitchProvider(string provider) => _active = provider;
    public bool HasApiKey(string provider) => _keys.ContainsKey(provider);
    public string ActiveProvider => _active;
    public string[] GetProviders() => (string[])Providers.Clone();
    public void Shutdown() { _client.Dispose(); }
}

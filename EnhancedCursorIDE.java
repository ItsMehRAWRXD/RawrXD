// EnhancedCursorIDE.java  --  javac EnhancedCursorIDE.java EditorCLI.java && java EditorCLI
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class EnhancedCursorIDE {
    private final HttpClient client = HttpClient.newHttpClient();
    private final Map<String, String> keys = new ConcurrentHashMap<>();
    private String active = "openai";

    public CompletableFuture<String> complete(String code, int cursor) {
        return switch (active) {
            case "openai" -> openAI(code);
            case "gemini" -> gemini(code);
            case "claude" -> claude(code);
            default -> CompletableFuture.failedFuture(new IllegalStateException("Unknown provider"));
        };
    }

    private CompletableFuture<String> openAI(String code) {
        String json = "{\"model\":\"gpt-3.5-turbo\",\"messages\":[{\"role\":\"user\",\"content\":"
                + quote(code) + "}]}";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://api.openai.com/v1/chat/completions"))
                .header("Authorization", "Bearer " + keys.get("openai"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        return call(req, "choices", 0, "message", "content");
    }

    private CompletableFuture<String> gemini(String code) {
        String json = "{\"contents\":[{\"parts\":[{\"text\":" + quote(code) + "}]}]}";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key="
                        + keys.get("gemini")))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        return call(req, "candidates", 0, "content", "parts", 0, "text");
    }

    private CompletableFuture<String> claude(String code) {
        String json = "{\"model\":\"claude-3-haiku-20240307\",\"messages\":[{\"role\":\"user\",\"content\":"
                + quote(code) + "}]}";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("https://api.anthropic.com/v1/messages"))
                .header("x-api-key", keys.get("claude"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        return call(req, "content", 0, "text");
    }

    // path elements: a String key, or an Integer array index
    private CompletableFuture<String> call(HttpRequest req, Object... path) {
        return client.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                .thenApply(resp -> {
                    if (resp.statusCode() != 200) return "Error: " + resp.statusCode();
                    try {
                        String v = extract(resp.body(), 0, path);
                        return v == null ? "Error: missing field" : v;
                    } catch (RuntimeException ex) {
                        return "Error: " + ex.getMessage();
                    }
                });
    }

    // JSON-escape into a quoted string literal
    private static String quote(String s) {
        StringBuilder b = new StringBuilder(s.length() + 16).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                default -> {
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        return b.append('"').toString();
    }

    // Walk a parsed JSON string by object key / array index, then unescape.
    private static String extract(String s, int from, Object... path) {
        int i = from;
        for (Object step : path) {
            if (step instanceof String key) {
                String needle = "\"" + key + "\"";
                int k = s.indexOf(needle, i);
                if (k < 0) return null;
                int c = s.indexOf(':', k + needle.length());
                if (c < 0) return null;
                i = skipWs(s, c + 1);
            } else { // Integer index
                if (s.charAt(i) != '[') return null;
                int idx = (Integer) step;
                i = skipWs(s, i + 1);
                for (int n = 0; n < idx; n++) {
                    i = endOfValue(s, i);
                    if (i < 0) return null;
                    i = skipWs(s, i + 1); // step past ',' or ']'
                }
            }
        }
        if (s.charAt(i) != '"') return null;
        return unescape(s, i);
    }

    private static int skipWs(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return i;
    }

    // Index just past the value starting at i (handles strings, {}, []).
    private static int endOfValue(String s, int i) {
        if (i >= s.length()) return -1;
        char c = s.charAt(i);
        if (c == '"') {
            int j = i + 1;
            while (j < s.length()) {
                if (s.charAt(j) == '\\') { j += 2; continue; }
                if (s.charAt(j) == '"') return j + 1;
                j++;
            }
            return -1;
        }
        if (c == '{' || c == '[') {
            int depth = 0;
            for (int j = i; j < s.length(); j++) {
                char d = s.charAt(j);
                if (d == '"') { j = endOfValue(s, j) - 1; continue; }
                if (d == '{' || d == '[') depth++;
                else if (d == '}' || d == ']') { depth--; if (depth == 0) return j + 1; }
            }
            return -1;
        }
        int j = i;
        while (j < s.length() && ",}] \t\r\n".indexOf(s.charAt(j)) < 0) j++;
        return j;
    }

    private static String unescape(String s, int openQuote) {
        StringBuilder b = new StringBuilder();
        for (int i = openQuote + 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') return b.toString();
            if (c != '\\') { b.append(c); continue; }
            char e = s.charAt(++i);
            switch (e) {
                case 'n' -> b.append('\n');
                case 'r' -> b.append('\r');
                case 't' -> b.append('\t');
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case '"' -> b.append('"');
                case '\\' -> b.append('\\');
                case '/' -> b.append('/');
                case 'u' -> {
                    b.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                    i += 4;
                }
                default -> b.append(e);
            }
        }
        return b.toString();
    }

    public void setApiKey(String provider, String key) { keys.put(provider, key); }
    public void switchProvider(String provider) { this.active = provider; }
    public boolean hasApiKey(String provider) { return keys.containsKey(provider); }
    public String getActiveProvider() { return active; }
    public String[] getProviders() { return new String[]{"openai", "gemini", "claude"}; }
    public void shutdown() { /* nothing to close */ }
}

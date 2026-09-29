import socket, time, sys
s = socket.create_connection(("127.0.0.1", 11436), timeout=60)
body = '{"model":"qwen2.5-coder-1.5b-base","messages":[{"role":"user","content":"Count: one two three four five six seven"}],"max_tokens":12,"stream":true}'
req = (f"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}")
s.sendall(req.encode())
s.settimeout(60)
buf = b""
chunks = 0
try:
    while chunks < 3:  # read just a few SSE chunks then abort
        d = s.recv(4096)
        if not d: break
        buf += d
        chunks += 1
finally:
    s.close()   # abrupt client disconnect mid-stream
print("ABORTED_AFTER_CHUNKS", chunks)
print(buf[:300])

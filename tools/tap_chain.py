#!/usr/bin/env python3
"""Chained TCP tap: listen on 11435, forward bidirectionally to real Ollama on
11434, and log every byte in both directions with timestamps.

Chain: proxy(11437) -> tap(11435) -> ollama(11434)
Log:   tap_chain.log
"""

import socket
import threading
import time

LISTEN = ("127.0.0.1", 11435)
UPSTREAM = ("127.0.0.1", 11434)
LOG = "tap_chain.log"

log_lock = threading.Lock()


def log(msg):
    with log_lock:
        with open(LOG, "a") as f:
            f.write(msg + "\n")
    print(msg, flush=True)


def pump(src, dst, label):
    src.settimeout(600)
    try:
        while True:
            b = src.recv(65536)
            if not b:
                log("[%s] EOF" % label)
                break
            log("[%s] %d bytes %r" % (label, len(b), b[:80]))
            dst.sendall(b)
            if b.startswith(b"HTTP/1.1 200"):
                log("[%s] response head seen" % label)
    except socket.timeout:
        log("[%s] timeout" % label)
    except OSError as e:
        log("[%s] oserror %r" % (label, e))
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client):
    log("[tap] connection from proxy")
    try:
        up = socket.create_connection(UPSTREAM, timeout=30)
    except OSError as e:
        log("[tap] upstream connect failed %r" % e)
        client.close()
        return
    t1 = threading.Thread(target=pump, args=(client, up, "C2S"), daemon=True)
    t2 = threading.Thread(target=pump, args=(up, client, "S2C"), daemon=True)
    t1.start()
    t2.start()
    t1.join(600)
    t2.join(600)
    try:
        up.close()
    except OSError:
        pass
    try:
        client.close()
    except OSError:
        pass
    log("[tap] connection closed")


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(LISTEN)
srv.listen(8)
log("[tap] listening on %s:%d -> %s:%d" % (LISTEN + UPSTREAM))
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
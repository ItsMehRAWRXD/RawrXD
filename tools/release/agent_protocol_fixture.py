"""Deterministic protocol regression server; never counted as model inference."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

SOURCE = ('#include <cstdio>\nint add(int a, int b) { return a + b; }\n'
          'int main() { std::printf("AGENT_RESULT=%d\\n", add(2, 3)); return 0; }\n')


class Handler(BaseHTTPRequestHandler):
    step = 0

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        Handler.step += 1
        messages = request['messages']
        last = messages[-1]['content']
        if Handler.step == 2 and 'target has not been read' not in last:
            self.send_error(400, 'missing prerequisite feedback')
            return
        if Handler.step == 3 and 'Binary content' not in last:
            self.send_error(400, 'binary observation was not rejected')
            return
        commands = ['TOOL finish', 'TOOL read payload.bin', 'TOOL read bug.cpp',
                    'TOOL write bug.cpp @@' + SOURCE + '@@', 'TOOL finish']
        reply = commands[min(Handler.step - 1, len(commands) - 1)]
        payload = json.dumps({'model': 'fixture-protocol', 'done': True,
                              'message': {'role': 'assistant', 'content': reply}}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        print('PROTOCOL_STEP', Handler.step, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    server = HTTPServer(('127.0.0.1', args.port), Handler)
    print('READY', args.port, flush=True)
    server.serve_forever()

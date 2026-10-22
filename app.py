"""Local-only dashboard server. No third-party dependencies."""
import argparse
import json
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from firewall import policy, save_policy, simulate

ROOT = Path(__file__).resolve().parent


def make_handler(directory):
    directory = Path(directory)
    config_path, log_path = directory / 'policy.json', directory / 'traffic.jsonl'
    if not config_path.exists():
        save_policy(config_path, json.loads((ROOT / 'examples/policy.json').read_text()))

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, data, kind='application/json'):
            body = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def valid_host(self):
            return self.headers.get('Host') in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}

        def do_GET(self):
            if not self.valid_host():
                return self.reply(403, {'error': 'Invalid host'})
            try:
                if self.path == '/':
                    return self.reply(200, (ROOT / 'dashboard.html').read_bytes(), 'text/html; charset=utf-8')
                if self.path == '/api/state':
                    logs = []
                    if log_path.exists():
                        with log_path.open() as stream:
                            logs = [json.loads(line) for line in deque(stream, maxlen=200)]
                    return self.reply(200, {'policy': policy(json.loads(config_path.read_text())), 'logs': logs})
                if self.path == '/api/export':
                    return self.reply(200, log_path.read_bytes() if log_path.exists() else b'', 'application/x-ndjson')
                return self.reply(404, {'error': 'Not found'})
            except (ValueError, OSError) as error:
                self.reply(500, {'error': str(error)})

        def do_POST(self):
            origin = self.headers.get('Origin')
            if not self.valid_host() or (origin and origin not in {f'http://127.0.0.1:{self.server.server_port}', f'http://localhost:{self.server.server_port}'}):
                return self.reply(403, {'error': 'Local same-origin requests only'})
            if self.headers.get('Content-Type') != 'application/json':
                return self.reply(415, {'error': 'Use application/json'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 262144:
                    return self.reply(413, {'error': 'Request must be between 1 byte and 256 KiB'})
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError('Expected a JSON object')
                if self.path == '/api/policy':
                    save_policy(config_path, data)
                    return self.reply(200, {'ok': True})
                if self.path == '/api/simulate':
                    result = simulate(json.loads(config_path.read_text()), data, log_path)
                    return self.reply(200, result)
                return self.reply(404, {'error': 'Not found'})
            except (ValueError, KeyError, TypeError, AttributeError) as error:
                self.reply(400, {'error': str(error)})
            except OSError as error:
                self.reply(500, {'error': str(error)})
    return Handler


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--data-dir', default=str(ROOT / 'data'))
    args = parser.parse_args()
    server = HTTPServer(('127.0.0.1', args.port), make_handler(args.data_dir))
    print(f'Sentinel is ready at http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
    finally:
        server.server_close()

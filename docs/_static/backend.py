#!/usr/bin/env python3
"""
WebSocket backend for TCP proxying and HTTP fetching.
"""

import asyncio
import json
import base64
import struct
import hashlib
import logging
import urllib.request
import urllib.error
import ssl
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('proxy')

sessions = {}

class WS:
    def __init__(self, r, w):
        self.r, self.w, self.closed = r, w, False

    async def send(self, data):
        if self.closed: return
        if isinstance(data, str): data = data.encode()
        f = bytearray([0x81])
        if len(data) < 126: f.append(len(data))
        elif len(data) < 65536: f.append(126); f.extend(struct.pack('>H', len(data)))
        else: f.append(127); f.extend(struct.pack('>Q', len(data)))
        f.extend(data)
        try: self.w.write(bytes(f)); await self.w.drain()
        except: self.closed = True

    async def recv(self):
        try:
            h = await self.r.readexactly(2)
            op, ln = h[0] & 0x0f, h[1] & 0x7f
            if op == 0x8: return None
            if ln == 126: ln = struct.unpack('>H', await self.r.readexactly(2))[0]
            elif ln == 127: ln = struct.unpack('>Q', await self.r.readexactly(8))[0]
            if h[1] & 0x80:
                mask = await self.r.readexactly(4)
                data = bytearray(await self.r.readexactly(ln))
                for i in range(ln): data[i] ^= mask[i % 4]
            else: data = await self.r.readexactly(ln)
            return data.decode() if op == 1 else data
        except: self.closed = True; return None


async def handle_fetch(ws, req_id, url, method='GET', headers_str='', body='', timeout=30, follow=True, insecure=True, cookies='', user_agent=''):
    """Fetch a URL and return the response with headers (curl-like)."""
    try:
        if insecure:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
        else:
            ctx = ssl.create_default_context()

        hdrs = {'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        if cookies:
            hdrs['Cookie'] = cookies
        if headers_str:
            for h in headers_str.split(','):
                if ':' in h:
                    k, v = h.split(':', 1)
                    hdrs[k.strip()] = v.strip()

        data = body.encode() if body else None
        current_url = url
        redirects = 0
        max_redirects = 10 if follow else 0

        while True:
            req = urllib.request.Request(current_url, headers=hdrs, method=method, data=data if redirects == 0 else None)
            try:
                opener = urllib.request.build_opener(urllib.request.HTTPErrorProcessor()) if not follow else None
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    resp_hdrs = '\n'.join(f'{k}: {v}' for k, v in resp.getheaders())
                    resp_body = resp.read(1024*1024).decode('utf-8', errors='replace')
                    await ws.send(json.dumps({
                        'type': 'fetch_response',
                        'id': req_id,
                        'status': resp.status,
                        'headers': resp_hdrs,
                        'body': resp_body
                    }))
                    log.info(f'{method} {url[:50]} -> {resp.status}')
                    return
            except urllib.error.HTTPError as e:
                if follow and e.code in (301, 302, 303, 307, 308) and redirects < max_redirects:
                    loc = e.headers.get('Location')
                    if loc:
                        if not loc.startswith('http'):
                            from urllib.parse import urljoin
                            loc = urljoin(current_url, loc)
                        current_url = loc
                        redirects += 1
                        if e.code == 303:
                            method = 'GET'
                        continue
                raise
    except Exception as e:
        await ws.send(json.dumps({
            'type': 'fetch_response',
            'id': req_id,
            'error': str(e)
        }))
        log.error(f'Fetch error: {e}')


async def handle_tcp(ws, session, host, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
        sessions[session] = {'r': reader, 'w': writer, 'ws': ws}
        await ws.send(json.dumps({'type': 'connected', 'session': session}))
        log.info(f'TCP [{session}] -> {host}:{port}')
        while True:
            data = await reader.read(4096)
            if not data: break
            await ws.send(json.dumps({'type': 'data', 'session': session, 'data': base64.b64encode(data).decode()}))
    except Exception as e:
        await ws.send(json.dumps({'type': 'error', 'session': session, 'msg': str(e)}))
    finally:
        if session in sessions:
            sessions[session]['w'].close()
            del sessions[session]
        await ws.send(json.dumps({'type': 'closed', 'session': session}))


async def handle_client(reader, writer):
    req = b''
    while b'\r\n\r\n' not in req and len(req) < 8192:
        c = await reader.read(1024)
        if not c: return
        req += c

    headers = {}
    lines = req.decode(errors='ignore').split('\r\n')
    for l in lines[1:]:
        if ':' in l: k, v = l.split(':', 1); headers[k.lower().strip()] = v.strip()

    # Check for WebSocket upgrade FIRST
    if headers.get('upgrade', '').lower() == 'websocket':
        key = headers.get('sec-websocket-key', '')
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        writer.write(f'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n'.encode())
        await writer.drain()
        ws = WS(reader, writer)
        log.info('Dashboard connected')
        await handle_ws(ws)
        writer.close()
        log.info('Dashboard disconnected')
        return

    # Serve static files
    if lines[0].startswith('GET '):
        path = lines[0].split(' ')[1].split('?')[0].lstrip('/')
        if not path or path == 'dashboard': path = 'dashboard.html'
        # Sanitize path - prevent traversal
        path = os.path.basename(path)
        ALLOWED_FILES = {'dashboard.html', 'socks-bridge.txt', 'socks-bridge.ps1', 'socks-bridge.py', 'port-forward.txt', 'backend.py'}
        if path in ALLOWED_FILES:
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                ct = 'text/html' if path.endswith('.html') else 'application/octet-stream'
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: ' + ct.encode() + b'\r\nContent-Length: ' + str(len(data)).encode() + b'\r\nAccess-Control-Allow-Origin: *\r\n\r\n' + data)
            except:
                writer.write(b'HTTP/1.1 404 Not Found\r\n\r\nFile not found: ' + path.encode())
            await writer.drain(); writer.close(); return

    # Unknown request
    writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
    await writer.drain(); writer.close()


async def handle_ws(ws):
    """Handle WebSocket messages from dashboard."""
    ws_sessions = set()
    try:
        while not ws.closed:
            data = await ws.recv()
            if data is None: break
            msg = json.loads(data)
            t = msg.get('type')

            if t == 'connect':
                s = msg.get('session') or msg.get('sid')
                ws_sessions.add(s)
                asyncio.create_task(handle_tcp(ws, s, msg['host'], msg['port']))
            elif t == 'data':
                s = msg.get('session') or msg.get('sid')
                if s in sessions:
                    sessions[s]['w'].write(base64.b64decode(msg['data']))
                    await sessions[s]['w'].drain()
            elif t == 'fetch_request':
                asyncio.create_task(handle_fetch(
                    ws, msg['id'], msg['url'], msg.get('method','GET'), msg.get('headers',''), msg.get('body',''),
                    timeout=msg.get('timeout',30), follow=msg.get('follow',True), insecure=msg.get('insecure',True),
                    cookies=msg.get('cookies',''), user_agent=msg.get('userAgent','')
                ))
            elif t == 'close':
                s = msg.get('session') or msg.get('sid')
                if s in sessions:
                    sessions[s]['w'].close()
                    del sessions[s]
                ws_sessions.discard(s)
    except Exception as e:
        log.error(f'Error: {e}')
    finally:
        for s in list(ws_sessions):
            if s in sessions:
                try: sessions[s]['w'].close()
                except: pass
                del sessions[s]
        log.info(f'Cleaned up {len(ws_sessions)} sessions')


async def main():
    server = await asyncio.start_server(handle_client, '127.0.0.1', 9999)
    log.info('=' * 40)
    log.info('Dashboard: http://127.0.0.1:9999/')
    log.info('WebSocket: ws://127.0.0.1:9999')
    log.info('=' * 40)
    log.info('Put dashboard.html in same directory')
    async with server: await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())

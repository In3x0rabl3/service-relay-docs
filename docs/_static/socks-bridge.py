#!/usr/bin/env python3
"""
SOCKS5 Bridge - Python version
Relays SOCKS5 traffic through Ably pub/sub to a peer dashboard+backend.

Modes:
  direct (default) - connects to Ably directly, no browser needed
  browser          - relays through a browser dashboard WebSocket
"""

import asyncio
import json
import base64
import hashlib
import struct
import sys
import time
import os
import platform
import subprocess
import atexit
import signal
import threading
import urllib.request
import http.client
import ssl

BRIDGE_PORT = 9998
SOCKS_PORT = 1080
ABLY_KEY = 'gAgqHA.yZ5GzA:6o4_ysot75A7YNoDEicN23KmBcI3isDJL3uYIUp3Ibg'
ABLY_AUTH = base64.b64encode(ABLY_KEY.encode()).decode()

room = ""
mode = "direct"
my_id = ""
browser_ws = None
sessions = {}
connect_waiters = {}
ready_event = asyncio.Event()
ably_queue = None
main_loop = None
revocation_was_on = False

def disable_revocation_check():
    global revocation_was_on
    if platform.system() != 'Windows':
        return
    try:
        result = subprocess.run(
            ['reg', 'query', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings', '/v', 'CertificateRevocation'],
            capture_output=True, text=True
        )
        if '0x1' in result.stdout:
            revocation_was_on = True
        subprocess.run(
            ['reg', 'add', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings', '/v', 'CertificateRevocation', '/t', 'REG_DWORD', '/d', '0', '/f'],
            capture_output=True
        )
        print("SSL revocation check disabled (fixes HTTPS errors)")
    except Exception:
        pass

def restore_revocation_check():
    if platform.system() != 'Windows' or not revocation_was_on:
        return
    try:
        subprocess.run(
            ['reg', 'add', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings', '/v', 'CertificateRevocation', '/t', 'REG_DWORD', '/d', '1', '/f'],
            capture_output=True
        )
        print("SSL revocation check restored")
    except Exception:
        pass


# -- Ably helpers (direct mode) -------------------------------------------

def ably_publish(data):
    payload = json.dumps({'name': 'data', 'data': data}).encode()
    req = urllib.request.Request(
        f'https://rest.ably.io/channels/relay-{room}/messages',
        data=payload,
        headers={'Authorization': f'Basic {ABLY_AUTH}', 'Content-Type': 'application/json'})
    urllib.request.urlopen(req, timeout=10)

def ably_sse_thread():
    global main_loop
    while True:
        try:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection('realtime.ably.io', context=ctx, timeout=120)
            conn.request('GET', f'/sse?channels=relay-{room}&v=1.2',
                         headers={'Authorization': f'Basic {ABLY_AUTH}', 'Accept': 'text/event-stream'})
            resp = conn.getresponse()
            if resp.status != 200:
                print(f"  SSE error: {resp.status}")
                time.sleep(3)
                continue
            print(f"  Ably connected (SSE)")
            buf = b''
            while True:
                byte = resp.read(1)
                if not byte:
                    break
                buf += byte
                if buf.endswith(b'\n\n'):
                    lines = buf.decode(errors='replace').strip().split('\n')
                    buf = b''
                    for l in lines:
                        if l.startswith('data:'):
                            try:
                                env = json.loads(l[5:].strip())
                                d = env.get('data', '')
                                if isinstance(d, str):
                                    try:
                                        d = json.loads(d)
                                    except Exception:
                                        pass
                                if isinstance(d, dict) and d.get('from') != my_id:
                                    if main_loop and ably_queue:
                                        asyncio.run_coroutine_threadsafe(ably_queue.put(d), main_loop)
                            except Exception:
                                pass
        except Exception as e:
            print(f"  SSE reconnecting... ({e})")
            time.sleep(3)

seen_ids = set()

def ably_poll_thread():
    global main_loop
    while True:
        time.sleep(2)
        if not connect_waiters:
            continue
        try:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection('rest.ably.io', context=ctx, timeout=10)
            conn.request('GET', f'/channels/relay-{room}/messages?limit=10&direction=backwards',
                         headers={'Authorization': f'Basic {ABLY_AUTH}', 'Accept': 'application/json'})
            resp = conn.getresponse()
            if resp.status != 200:
                continue
            msgs = json.loads(resp.read())
            for msg in reversed(msgs):
                mid = msg.get('id', '')
                if mid in seen_ids:
                    continue
                seen_ids.add(mid)
                if len(seen_ids) > 500:
                    seen_ids.clear()
                d = msg.get('data', '')
                if isinstance(d, str):
                    try:
                        d = json.loads(d)
                    except Exception:
                        pass
                if isinstance(d, dict) and d.get('from') != my_id:
                    t = d.get('type', '')
                    if t in ('tcp_connected', 'tcp_data', 'tcp_closed', 'tcp_error'):
                        print(f"  [poll] {t} {d.get('session','')[:12]}")
                        if main_loop and ably_queue:
                            asyncio.run_coroutine_threadsafe(ably_queue.put(d), main_loop)
        except Exception:
            pass


async def handle_ably_messages():
    global sessions, connect_waiters
    while True:
        d = await ably_queue.get()
        msg_type = d.get('type', '')
        sid = d.get('session', '')
        fr = str(d.get('from', ''))[:8]

        if msg_type == 'tcp_connected':
            print(f"  TCP connected: {sid[:12]} (from {fr})")
            if sid in connect_waiters:
                connect_waiters[sid].set_result(True)

        elif msg_type == 'tcp_data':
            b64 = d.get('data', '')
            if sid in sessions:
                try:
                    data = base64.b64decode(b64)
                    sessions[sid]['writer'].write(data)
                    await sessions[sid]['writer'].drain()
                    print(f"  << {sid[:12]} {len(data)}B")
                except Exception as e:
                    print(f"  << {sid[:12]} WRITE ERR: {e}")

        elif msg_type == 'tcp_closed':
            print(f"  TCP closed: {sid[:12]} (from {fr})")
            if sid in connect_waiters:
                connect_waiters[sid].set_result(False)
            if sid in sessions:
                try:
                    sessions[sid]['writer'].close()
                except Exception:
                    pass
                del sessions[sid]

        elif msg_type == 'tcp_error':
            err = d.get('error', 'unknown')
            print(f"  TCP error [{sid[:12]}]: {err}")
            if sid in connect_waiters:
                connect_waiters[sid].set_result(False)
            if sid in sessions:
                try:
                    sessions[sid]['writer'].close()
                except Exception:
                    pass
                del sessions[sid]

        elif msg_type == 'hello':
            print(f"  Peer online: {fr}")
            ably_publish({'type': 'hello', 'from': my_id})

        elif msg_type == 'ping':
            pass


async def send_to_relay(msg):
    if mode == 'direct':
        msg['from'] = my_id
        t = msg.get('type', '')
        sid = msg.get('session', '')[:12]
        print(f"  -> relay: {t} {sid}")
        try:
            await asyncio.get_running_loop().run_in_executor(None, ably_publish, msg)
        except Exception as e:
            print(f"  -> relay: PUBLISH ERR: {e}")
    else:
        await send_to_browser(msg)


# -- Browser WS helpers (browser mode) ------------------------------------

class WebSocketServer:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.closed = False

    async def send(self, data):
        if self.closed:
            return
        if isinstance(data, str):
            data = data.encode()
        frame = bytearray([0x81])
        if len(data) < 126:
            frame.append(len(data))
        elif len(data) < 65536:
            frame.append(126)
            frame.extend(struct.pack('>H', len(data)))
        else:
            frame.append(127)
            frame.extend(struct.pack('>Q', len(data)))
        frame.extend(data)
        try:
            self.writer.write(bytes(frame))
            await self.writer.drain()
        except Exception:
            self.closed = True

    async def recv(self):
        try:
            header = await self.reader.readexactly(2)
            opcode = header[0] & 0x0F
            if opcode == 0x8:
                return None
            masked = (header[1] & 0x80) != 0
            length = header[1] & 0x7F
            if length == 126:
                length = struct.unpack('>H', await self.reader.readexactly(2))[0]
            elif length == 127:
                length = struct.unpack('>Q', await self.reader.readexactly(8))[0]
            if length > 16 << 20:
                self.closed = True
                return None
            mask = None
            if masked:
                mask = await self.reader.readexactly(4)
            if length == 0:
                return b''
            payload = bytearray(await self.reader.readexactly(length))
            if masked:
                for i in range(length):
                    payload[i] ^= mask[i % 4]
            return bytes(payload)
        except Exception:
            self.closed = True
            return None


async def send_to_browser(msg):
    global browser_ws
    if browser_ws and not browser_ws.closed:
        data = json.dumps(msg)
        print(f"  -> browser: {msg.get('type', '')} {msg.get('session', '')[:12]}")
        await browser_ws.send(data)
    else:
        print(f"  -> browser: DROPPED (no ws) {msg.get('type', '')}")


async def handle_browser_message(data):
    global sessions, connect_waiters
    try:
        msg = json.loads(data)
    except Exception:
        return

    msg_type = msg.get('type', '')
    sid = msg.get('session', '')

    if msg_type == 'tcp_connected':
        print(f"  TCP connected: {sid[:12]}")
        if sid in connect_waiters:
            connect_waiters[sid].set_result(True)

    elif msg_type == 'tcp_data':
        b64 = msg.get('data', '')
        if sid in sessions:
            try:
                raw = base64.b64decode(b64)
                sessions[sid]['writer'].write(raw)
                await sessions[sid]['writer'].drain()
                print(f"  << {sid[:12]} {len(raw)}B")
            except Exception as e:
                print(f"  << {sid[:12]} WRITE ERR: {e}")

    elif msg_type == 'tcp_closed':
        print(f"  TCP closed: {sid[:12]}")
        if sid in sessions:
            try:
                sessions[sid]['writer'].close()
            except Exception:
                pass
            del sessions[sid]

    elif msg_type == 'tcp_error':
        err = msg.get('error', 'unknown')
        print(f"  TCP error [{sid[:12]}]: {err}")
        if sid in connect_waiters:
            connect_waiters[sid].set_result(False)
        if sid in sessions:
            try:
                sessions[sid]['writer'].close()
            except Exception:
                pass
            del sessions[sid]


async def handle_browser_conn(reader, writer):
    global browser_ws, room

    req = b''
    while b'\r\n\r\n' not in req and len(req) < 8192:
        chunk = await reader.read(1024)
        if not chunk:
            writer.close()
            return
        req += chunk

    req_str = req.decode(errors='ignore')
    if 'Upgrade: websocket' not in req_str:
        writer.close()
        return

    key = ''
    for line in req_str.split('\r\n'):
        if line.lower().startswith('sec-websocket-key:'):
            key = line.split(':', 1)[1].strip()
            break

    accept = base64.b64encode(
        hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
    ).decode()

    response = f'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n'
    writer.write(response.encode())
    await writer.drain()

    ws = WebSocketServer(reader, writer)

    if browser_ws:
        browser_ws.closed = True
    browser_ws = ws

    await ws.send(json.dumps({'type': 'bridge_init', 'room': room}))
    ready_event.set()

    print("Browser connected!")

    while not ws.closed:
        data = await ws.recv()
        if data is None:
            break
        await handle_browser_message(data)

    if browser_ws is ws:
        browser_ws = None
        print("Browser disconnected")
        for sid in list(sessions):
            try:
                sessions[sid]['writer'].close()
            except Exception:
                pass
        sessions.clear()
        for sid, waiter in list(connect_waiters.items()):
            if not waiter.done():
                waiter.set_result(False)
        connect_waiters.clear()
    writer.close()


# -- SOCKS5 handler -------------------------------------------------------

async def handle_socks(reader, writer):
    global sessions, connect_waiters

    try:
        greeting = await asyncio.wait_for(reader.read(512), timeout=10)
        if len(greeting) < 2 or greeting[0] != 5:
            writer.close()
            return
        writer.write(b'\x05\x00')
        await writer.drain()

        request = await asyncio.wait_for(reader.read(512), timeout=10)
        if len(request) < 7 or request[1] != 1:
            writer.close()
            return

        atyp = request[3]
        if atyp == 1:
            host = f"{request[4]}.{request[5]}.{request[6]}.{request[7]}"
            port = (request[8] << 8) | request[9]
        elif atyp == 3:
            length = request[4]
            host = request[5:5+length].decode()
            port = (request[5+length] << 8) | request[6+length]
        else:
            writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            return

        print(f"\nCONNECT {host}:{port}")

        sid = f"s{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}"

        # Send SOCKS success early so client starts sending data
        writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()

        # Read initial data from client (TLS ClientHello / HTTP request)
        initial_data = b''
        try:
            initial_data = await asyncio.wait_for(reader.read(4096), timeout=2)
            if initial_data:
                print(f"  {sid[:12]} pre-read {len(initial_data)}B")
        except asyncio.TimeoutError:
            pass

        waiter = asyncio.get_running_loop().create_future()
        connect_waiters[sid] = waiter
        sessions[sid] = {'reader': reader, 'writer': writer}

        msg = {
            'type': 'tcp_connect',
            'session': sid,
            'host': host,
            'port': port
        }
        if initial_data:
            msg['initial_data'] = base64.b64encode(initial_data).decode()
        await send_to_relay(msg)

        try:
            result = await asyncio.wait_for(waiter, timeout=20)
            if not result:
                print(f"  {sid[:12]} connect REJECTED by peer")
                if sid in sessions:
                    del sessions[sid]
                writer.close()
                return
        except asyncio.TimeoutError:
            print(f"  {sid[:12]} connect TIMEOUT (20s, no response from relay)")
            if sid in sessions:
                del sessions[sid]
            writer.close()
            return
        finally:
            if sid in connect_waiters:
                del connect_waiters[sid]

        print(f"  {sid[:12]} tunnel open")

        while sid in sessions:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                if not data:
                    break
                print(f"  >> {sid[:12]} {len(data)}B")
                await send_to_relay({
                    'type': 'tcp_data',
                    'session': sid,
                    'data': base64.b64encode(data).decode()
                })
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"  {sid[:12]} relay error: {e}")
                break

        if sid in sessions:
            del sessions[sid]

        await send_to_relay({'type': 'tcp_close', 'session': sid})

    except Exception as e:
        print(f"SOCKS error: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


# -- Main -----------------------------------------------------------------

async def main():
    global room, mode, my_id, ably_queue, main_loop

    print("=== SOCKS5 Bridge ===")
    print()
    print("Usage: python3 socks-bridge.py <ROOM> [local] [browser]")
    print("  local   - listen on 127.0.0.1 only (default: 0.0.0.0)")
    print("  browser - use browser dashboard relay (default: direct Ably)")
    print()

    disable_revocation_check()
    atexit.register(restore_revocation_check)

    listen_addr = "0.0.0.0"
    mode = "direct"

    if len(sys.argv) < 2:
        room = input("Enter room code: ").strip().upper()
    else:
        room = sys.argv[1].upper()
        for arg in sys.argv[2:]:
            if arg.lower() == 'local':
                listen_addr = "127.0.0.1"
            elif arg.lower() == 'browser':
                mode = "browser"

    if len(room) < 4:
        print("ERROR: Room code must be at least 4 characters")
        sys.exit(1)

    my_id = hashlib.sha256(os.urandom(4)).hexdigest()[:8]

    print(f"Room: {room}")
    print(f"Mode: {mode}")
    print(f"ID:   {my_id}")
    print()

    main_loop = asyncio.get_running_loop()

    if mode == 'direct':
        ably_queue = asyncio.Queue()
        threading.Thread(target=ably_sse_thread, daemon=True).start()
        threading.Thread(target=ably_poll_thread, daemon=True).start()
        await asyncio.sleep(2)

        ably_publish({'type': 'hello', 'from': my_id})
        print("Sent hello, waiting for peer...")

        got_peer = False
        for _ in range(15):
            try:
                d = await asyncio.wait_for(ably_queue.get(), timeout=2)
                if d.get('type') == 'hello':
                    print(f"Peer found: {str(d.get('from',''))[:8]}")
                    got_peer = True
                    break
            except asyncio.TimeoutError:
                continue

        if not got_peer:
            print("WARNING: No peer responded to hello (continuing anyway)")
            print("Make sure the peer dashboard is open on the same room.")
        print()

        ably_task = asyncio.create_task(handle_ably_messages())

        socks_server = await asyncio.start_server(handle_socks, listen_addr, SOCKS_PORT)
        print(f"SOCKS5 proxy running on {listen_addr}:{SOCKS_PORT}")
        print()
        if listen_addr == "127.0.0.1":
            print(f"Configure apps to use: SOCKS5 127.0.0.1:{SOCKS_PORT}")
        else:
            print(f"Configure apps to use: SOCKS5 <this-ip>:{SOCKS_PORT}")
        print()

        await socks_server.serve_forever()

    else:
        bridge_server = await asyncio.start_server(handle_browser_conn, '127.0.0.1', BRIDGE_PORT)
        print(f"Bridge server: ws://127.0.0.1:{BRIDGE_PORT}")
        print("Waiting for browser connection...")
        print()
        print("In your browser, open the dashboard and enter this room code.")
        print("The dashboard will connect to this bridge automatically.")
        print()

        try:
            await asyncio.wait_for(ready_event.wait(), timeout=120)
        except asyncio.TimeoutError:
            print("ERROR: Timeout waiting for browser")
            sys.exit(1)

        socks_server = await asyncio.start_server(handle_socks, listen_addr, SOCKS_PORT)
        print(f"\nSOCKS5 proxy running on {listen_addr}:{SOCKS_PORT}")
        print()
        if listen_addr == "127.0.0.1":
            print(f"Configure apps to use: SOCKS5 127.0.0.1:{SOCKS_PORT}")
        else:
            print(f"Configure apps to use: SOCKS5 <this-ip>:{SOCKS_PORT}")
        print()

        await asyncio.gather(
            bridge_server.serve_forever(),
            socks_server.serve_forever()
        )


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...")

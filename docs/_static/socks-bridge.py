#!/usr/bin/env python3
"""
SOCKS5 Bridge (Browser Mode) - Python version
Connects through your browser dashboard to relay SOCKS5 traffic.
"""

import asyncio
import json
import base64
import hashlib
import struct
import sys
import time
import platform
import subprocess
import atexit
import signal

BRIDGE_PORT = 9998
SOCKS_PORT = 1080

room = ""
browser_ws = None
sessions = {}
connect_waiters = {}
ready_event = asyncio.Event()
revocation_was_on = False

def disable_revocation_check():
    """Disable Windows SSL revocation check to fix CRYPT_E_REVOCATION_OFFLINE."""
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
    """Restore Windows SSL revocation check on exit."""
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
        except:
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
        except:
            self.closed = True
            return None


async def send_to_browser(msg):
    global browser_ws
    if browser_ws and not browser_ws.closed:
        await browser_ws.send(json.dumps(msg))


async def handle_browser_message(data):
    global sessions, connect_waiters
    try:
        msg = json.loads(data)
    except:
        return

    msg_type = msg.get('type', '')
    sid = msg.get('session', '')

    if msg_type == 'tcp_connected':
        print(f"TCP connected: {sid}")
        if sid in connect_waiters:
            connect_waiters[sid].set_result(True)

    elif msg_type == 'tcp_data':
        b64 = msg.get('data', '')
        if sid in sessions:
            try:
                data = base64.b64decode(b64)
                sessions[sid]['writer'].write(data)
                await sessions[sid]['writer'].drain()
            except:
                pass

    elif msg_type == 'tcp_closed':
        print(f"TCP closed: {sid}")
        if sid in sessions:
            try:
                sessions[sid]['writer'].close()
            except:
                pass
            del sessions[sid]

    elif msg_type == 'tcp_error':
        err = msg.get('error', 'unknown')
        print(f"TCP error [{sid}]: {err}")
        if sid in connect_waiters:
            connect_waiters[sid].set_result(False)
        if sid in sessions:
            try:
                sessions[sid]['writer'].close()
            except:
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

    browser_ws = None
    print("Browser disconnected")
    writer.close()


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
        if atyp == 1:  # IPv4
            host = f"{request[4]}.{request[5]}.{request[6]}.{request[7]}"
            port = (request[8] << 8) | request[9]
        elif atyp == 3:  # Domain
            length = request[4]
            host = request[5:5+length].decode()
            port = (request[5+length] << 8) | request[6+length]
        else:
            writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            return

        print(f"CONNECT {host}:{port}")

        sid = f"s{int(time.time()*1000) % 1000000}"

        waiter = asyncio.get_event_loop().create_future()
        connect_waiters[sid] = waiter
        sessions[sid] = {'reader': reader, 'writer': writer}

        await send_to_browser({
            'type': 'tcp_connect',
            'session': sid,
            'host': host,
            'port': port
        })

        try:
            result = await asyncio.wait_for(waiter, timeout=15)
            if not result:
                writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                del sessions[sid]
                writer.close()
                return
        except asyncio.TimeoutError:
            writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            if sid in sessions:
                del sessions[sid]
            writer.close()
            return
        finally:
            if sid in connect_waiters:
                del connect_waiters[sid]

        writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()

        while sid in sessions:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                if not data:
                    break
                await send_to_browser({
                    'type': 'tcp_data',
                    'session': sid,
                    'data': base64.b64encode(data).decode()
                })
            except asyncio.TimeoutError:
                continue
            except:
                break

        if sid in sessions:
            del sessions[sid]

        await send_to_browser({'type': 'tcp_close', 'session': sid})

    except Exception as e:
        print(f"SOCKS error: {e}")
    finally:
        try:
            writer.close()
        except:
            pass


async def main():
    global room

    print("=== SOCKS5 Bridge (Browser Mode) ===")
    print()
    print("This bridge connects through your browser.")
    print()
    print("Usage: python3 socks-bridge.py <ROOM> [local]")
    print("  local - listen on 127.0.0.1 only (default: 0.0.0.0)")
    print()

    # Disable Windows SSL revocation check (fixes CRYPT_E_REVOCATION_OFFLINE)
    disable_revocation_check()
    atexit.register(restore_revocation_check)

    listen_addr = "0.0.0.0"

    if len(sys.argv) < 2:
        room = input("Enter room code: ").strip().upper()
    else:
        room = sys.argv[1].upper()
        if len(sys.argv) >= 3 and sys.argv[2].lower() == 'local':
            listen_addr = "127.0.0.1"

    if len(room) < 4:
        print("ERROR: Room code must be at least 4 characters")
        sys.exit(1)

    print(f"Room: {room}")
    print()

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

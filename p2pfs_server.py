#!/usr/bin/env python3
"""p2pfs_server.py - relay + peer registry for P2PFS clients.

Run behind a playit.gg TCP tunnel. No files are ever written to disk;
all payload bytes are opaque ciphertext from the client's E2E layer.

Design:
- one asyncio loop owns accepting, the control channel and relay pairing
- once two relay sockets are paired they are handed to a pair of plain
  threads running blocking recv_into/sendall on a reusable 1 MiB buffer;
  socket calls release the GIL, so every relay runs on its own core
- control connections must prove they own the ed25519 key behind their ID
- relay pairing needs a single-use token minted by the server for exactly
  the two peers involved
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

HOST = os.environ.get("P2PFS_SERVER_HOST", "0.0.0.0")
PORT = int(os.environ.get("P2PFS_SERVER_PORT", "47777"))
MAX_CLIENTS = int(os.environ.get("P2PFS_MAX_CLIENTS", "2000"))
MAX_RELAYS = int(os.environ.get("P2PFS_MAX_RELAYS", "256"))
LOG = logging.getLogger("p2pfs.server")

RELAY_BUF = 1024 * 1024
SOCK_BUF = 4 * 1024 * 1024
IDLE_TIMEOUT = 600.0
PAIRING_TIMEOUT = 60.0
HANDSHAKE_TIMEOUT = 15.0
MAX_LINE = 8192
MAX_USERNAME = 64
MAX_MSGS_PER_SEC = 50
MAX_WRITE_BACKLOG = 1024 * 1024
AUTH_CONTEXT = b"p2pfs-auth-v2|"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")


@dataclass
class Client:
    cid: str
    username: str
    ed_public: str
    x_public: str
    fingerprint: str
    writer: asyncio.StreamWriter
    connected_at: float = field(default_factory=time.time)


@dataclass
class Ticket:
    requester: str
    target: str
    waiting: Optional[socket.socket] = None
    timer: Optional[asyncio.TimerHandle] = None


CLIENTS: dict[str, Client] = {}
TICKETS: dict[str, Ticket] = {}
_relay_lock = threading.Lock()
_active_relays = 0


def _close(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _tune(sock: socket.socket, bulk: bool) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if bulk:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
    except OSError:
        pass


def _fingerprint(ed_raw: bytes) -> str:
    return hashlib.sha256(ed_raw).hexdigest()


# ---------------------------------------------------------------------------
# relay data path (threads)
# ---------------------------------------------------------------------------

def _pump(src: socket.socket, dst: socket.socket, label: str, stats: dict) -> None:
    buf = bytearray(RELAY_BUF)
    view = memoryview(buf)
    total = 0
    clean = False
    try:
        while True:
            n = src.recv_into(buf)
            if not n:
                clean = True
                break
            dst.sendall(view[:n])
            total += n
    except OSError as exc:
        LOG.debug("relay %s ended: %s", label, exc)
    finally:
        stats[label] = total
        if clean:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        else:
            # hard failure: tear down both directions so the peer notices
            _close(src)
            _close(dst)


def _relay_pair(a: socket.socket, b: socket.socket, label: str) -> None:
    global _active_relays
    started = time.monotonic()
    stats: dict[str, int] = {}
    try:
        for s in (a, b):
            s.setblocking(True)
            s.settimeout(IDLE_TIMEOUT)
            _tune(s, bulk=True)
        reverse = threading.Thread(
            target=_pump, args=(b, a, "b->a", stats), daemon=True,
            name="p2pfs-relay-rev",
        )
        reverse.start()
        _pump(a, b, "a->b", stats)
        reverse.join()
    finally:
        _close(a)
        _close(b)
        with _relay_lock:
            _active_relays -= 1
        elapsed = time.monotonic() - started
        total = sum(stats.values())
        if elapsed > 0.5 and total:
            LOG.info(
                "relay %s forwarded %d bytes in %.1fs (%.1f Mbps)",
                label, total, elapsed, total * 8 / 1_000_000 / elapsed,
            )


def _start_relay(a: socket.socket, b: socket.socket, label: str) -> bool:
    global _active_relays
    with _relay_lock:
        if _active_relays >= MAX_RELAYS:
            return False
        _active_relays += 1
    threading.Thread(
        target=_relay_pair, args=(a, b, label), daemon=True, name="p2pfs-relay",
    ).start()
    return True


# ---------------------------------------------------------------------------
# control channel
# ---------------------------------------------------------------------------

async def read_line(loop: asyncio.AbstractEventLoop, sock: socket.socket) -> bytes:
    # byte-wise on purpose: nothing past the newline may be consumed, because
    # relay sockets are handed to blocking threads and control sockets to asyncio
    out = bytearray()
    while len(out) < MAX_LINE:
        b = await loop.sock_recv(sock, 1)
        if not b:
            raise ConnectionError("closed before newline")
        if b == b"\n":
            return bytes(out)
        out += b
    raise ValueError("line too long")


def _push(client: Client, payload: bytes) -> None:
    transport = client.writer.transport
    if transport.is_closing():
        return
    if transport.get_write_buffer_size() > MAX_WRITE_BACKLOG:
        LOG.info("dropping slow client %s", client.cid)
        client.writer.close()
        return
    client.writer.write(payload)


def _encode(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode() + b"\n"


def peer_list() -> list[dict]:
    return [
        {"id": c.cid, "username": c.username, "fingerprint": c.fingerprint}
        for c in CLIENTS.values()
    ]


def broadcast_peers() -> None:
    payload = _encode({"type": "peers", "peers": peer_list()})
    for c in list(CLIENTS.values()):
        _push(c, payload)


def _clean_username(raw) -> str:
    if not isinstance(raw, str):
        raise ValueError("username must be a string")
    name = "".join(ch for ch in raw if ch.isprintable()).strip()
    if not name or len(name) > MAX_USERNAME:
        raise ValueError("username length out of range")
    return name


def _expire_ticket(token: str) -> None:
    ticket = TICKETS.pop(token, None)
    if ticket is not None:
        _close(ticket.waiting)
        LOG.info("relay pairing timed out for %s <-> %s", ticket.requester, ticket.target)


async def _authenticate(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, hello: dict
) -> Client:
    if hello.get("type") != "hello":
        raise ValueError("expected hello")
    cid = hello["id"]
    if not isinstance(cid, str) or not ID_RE.match(cid):
        raise ValueError("bad id")
    ed_b64 = hello["ed_public"]
    ed_raw = base64.b64decode(ed_b64, validate=True)
    if len(ed_raw) != 32:
        raise ValueError("bad ed25519 key")
    fp = _fingerprint(ed_raw)
    if not cid.endswith("-" + fp[:10]):
        raise ValueError("id does not match key fingerprint")
    username = _clean_username(hello["username"])
    x_public = str(hello.get("x_public", ""))[:128]

    nonce = os.urandom(32)
    writer.write(_encode({"type": "challenge", "nonce": base64.b64encode(nonce).decode()}))
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), timeout=HANDSHAKE_TIMEOUT)
    msg = json.loads(line)
    if msg.get("type") != "auth":
        raise ValueError("expected auth")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(ed_raw).verify(
            base64.b64decode(msg["sig"], validate=True),
            AUTH_CONTEXT + nonce + cid.encode(),
        )
    except InvalidSignature as exc:
        raise ValueError("bad signature") from exc
    return Client(cid, username, ed_b64, x_public, fp, writer)


async def handle_control(sock: socket.socket, first_line: bytes) -> None:
    reader, writer = await asyncio.open_connection(sock=sock, limit=MAX_LINE)
    client: Optional[Client] = None
    try:
        try:
            client = await _authenticate(reader, writer, json.loads(first_line))
        except (ValueError, KeyError, TypeError, asyncio.TimeoutError) as exc:
            LOG.info("control auth rejected: %s", exc)
            writer.write(_encode({"type": "error", "message": f"auth failed: {exc}"}))
            return

        old = CLIENTS.get(client.cid)
        if old is not None:
            old.writer.close()
        if old is None and len(CLIENTS) >= MAX_CLIENTS:
            writer.write(_encode({"type": "error", "message": "server full"}))
            return
        CLIENTS[client.cid] = client
        LOG.info("client %s (%s) connected", client.cid, client.username)

        writer.write(_encode({"type": "welcome", "peers": peer_list()}))
        broadcast_peers()

        window_start = time.monotonic()
        window_count = 0
        loop = asyncio.get_running_loop()
        while True:
            line = await reader.readline()
            if not line:
                break
            now = time.monotonic()
            if now - window_start >= 1.0:
                window_start, window_count = now, 0
            window_count += 1
            if window_count > MAX_MSGS_PER_SEC:
                LOG.info("client %s exceeded message rate; dropping", client.cid)
                break

            msg = json.loads(line)
            mtype = msg.get("type")
            req = msg.get("req")
            if mtype == "relay_request":
                target = CLIENTS.get(msg.get("target"))
                if target is None or target.cid == client.cid:
                    _push(client, _encode({
                        "type": "error", "req": req, "message": "peer not online",
                    }))
                    continue
                if len(TICKETS) >= MAX_RELAYS * 4:
                    _push(client, _encode({
                        "type": "error", "req": req, "message": "server busy",
                    }))
                    continue
                token = secrets.token_urlsafe(24)
                ticket = Ticket(client.cid, target.cid)
                ticket.timer = loop.call_later(PAIRING_TIMEOUT, _expire_ticket, token)
                TICKETS[token] = ticket
                _push(target, _encode({
                    "type": "relay_incoming", "from": client.cid,
                    "from_username": client.username, "token": token,
                }))
                _push(client, _encode({
                    "type": "relay_ticket", "req": req, "token": token,
                }))
            elif mtype == "ping":
                _push(client, _encode({"type": "pong"}))
    except (ConnectionError, OSError, ValueError) as exc:
        LOG.debug("control ended: %s", exc)
    except Exception:
        LOG.exception("control error")
    finally:
        if client is not None and CLIENTS.get(client.cid) is client:
            del CLIENTS[client.cid]
            LOG.info("client %s disconnected", client.cid)
            broadcast_peers()
        try:
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# relay pairing
# ---------------------------------------------------------------------------

def handle_relay(sock: socket.socket, line: bytes) -> None:
    parts = line.split()
    if len(parts) != 2 or parts[0] != b"relay":
        _close(sock)
        return
    token = parts[1].decode("ascii", errors="replace")
    ticket = TICKETS.get(token)
    if ticket is None:
        LOG.info("relay connection with unknown token rejected")
        _close(sock)
        return
    if ticket.waiting is None:
        ticket.waiting = sock
        return
    del TICKETS[token]
    if ticket.timer is not None:
        ticket.timer.cancel()
    label = f"{ticket.requester}<->{ticket.target}"
    if _start_relay(ticket.waiting, sock, label):
        LOG.info("relay paired %s", label)
    else:
        LOG.warning("relay limit reached; refusing %s", label)
        _close(ticket.waiting)
        _close(sock)


async def handle_connection(sock: socket.socket) -> None:
    loop = asyncio.get_running_loop()
    handed_off = False
    try:
        sock.setblocking(False)
        _tune(sock, bulk=False)
        line = await asyncio.wait_for(read_line(loop, sock), timeout=HANDSHAKE_TIMEOUT)
        if line.startswith(b"relay "):
            handle_relay(sock, line)
            handed_off = True
        else:
            handed_off = True
            await handle_control(sock, line)
    except (asyncio.TimeoutError, ConnectionError, OSError, ValueError) as exc:
        LOG.debug("connection rejected before handshake: %s", exc)
    except Exception:
        LOG.exception("connection error")
    finally:
        if not handed_off:
            _close(sock)


async def main() -> None:
    logging.basicConfig(
        level=os.environ.get("P2PFS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    loop = asyncio.get_running_loop()
    listener = socket.create_server((HOST, PORT), backlog=1024)
    listener.setblocking(False)
    LOG.info(
        "P2PFS relay listening on %s:%d (max relays %d)", HOST, PORT, MAX_RELAYS
    )
    tasks: set[asyncio.Task] = set()
    try:
        while True:
            conn, _addr = await loop.sock_accept(listener)
            task = asyncio.create_task(handle_connection(conn))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
    finally:
        listener.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

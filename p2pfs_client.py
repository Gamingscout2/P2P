#!/usr/bin/env python3
"""p2pfs_client.py - GUI P2P file sharing with relay fallback.

Dependencies:
    pip install PySide6 cryptography warpgate aionetiface pystun3

Transfer design:
- sender: read -> (hash | encrypt on a worker pool) -> ordered socket writer
- receiver: ordered socket reader -> decrypt on a worker pool -> (write | hash)
  every stage runs on its own thread, so disk, SHA-256, AES-GCM and the
  network overlap instead of taking turns on the event loop
- bounded queues everywhere, so a slow disk or link never balloons memory
- per-direction counter nonces: a replayed, dropped or reordered frame
  fails authentication
- ephemeral X25519 per session, signed by the long-term ed25519 identity
  (forward secrecy)

Stability features:
- OS-level TCP keepalive on every socket
- automatic retry with exponential backoff (up to 30 attempts)
- transparent resume via .part file offset negotiation
- cancellation that interrupts retry backoff sleeps
- receiver keeps .part files across connection drops; per-file locks
  prevent concurrent offers for the same transfer from racing
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time
import traceback
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QGroupBox, QHBoxLayout, QInputDialog,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QStatusBar,
    QVBoxLayout, QWidget,
)

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# warpgate costs ~1s to import; it is loaded on the network thread so the
# window can paint first
Gate: Any = None
TCP: Any = None
peer: Any = None
SUB_ALL: Any = None


def _load_warpgate() -> None:
    global Gate, TCP, peer, SUB_ALL
    from warpgate import Gate as _gate, TCP as _tcp, peer as _peer
    from aionetiface import SUB_ALL as _sub_all
    Gate, TCP, peer, SUB_ALL = _gate, _tcp, _peer, _sub_all


# ---------------------------------------------------------------------------
# Logging / resources
# ---------------------------------------------------------------------------

def _setup_logging() -> None:
    level = os.environ.get("P2PFS_LOG_LEVEL", "INFO").upper()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(level)
    # windowed builds have no stderr, so always keep a log file as well
    if sys.stderr is not None:
        stream = logging.StreamHandler()
        stream.setFormatter(fmt)
        root.addHandler(stream)
    try:
        from logging.handlers import RotatingFileHandler
        fileh = RotatingFileHandler(
            APP_DIR / "p2pfs.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8"
        )
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
    except OSError:
        pass

    def _hook(exc_type, exc, tb):
        logging.getLogger("p2pfs").critical(
            "uncaught exception", exc_info=(exc_type, exc, tb)
        )

    sys.excepthook = _hook


def resource_path(relative: str) -> str:
    base = getattr(sys, "_MEIPASS", None)
    if base is None:
        return str(Path(__file__).parent / relative)
    return str(Path(base) / relative)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

APP_DIR = Path.home() / ".p2pfs"
APP_DIR.mkdir(parents=True, exist_ok=True)

IDENTITY_FILE = APP_DIR / "identity.json"
TRUST_FILE = APP_DIR / "trusted_peers.json"
CONFIG_FILE = APP_DIR / "config.json"

CPU_COUNT = os.cpu_count() or 4
CRYPTO_WORKERS = max(2, min(CPU_COUNT, 16))
PIPELINE_DEPTH = max(3, min(CPU_COUNT // 2, 8))

CHUNK_SIZE = 4 * 1024 * 1024
MAX_FRAME = CHUNK_SIZE + 64 * 1024
STREAM_BACKLOG = (PIPELINE_DEPTH + 2) * CHUNK_SIZE
INLINE_CRYPTO_LIMIT = 64 * 1024
AAD = b"p2pfs-v2-frame"
NONCE_PREFIX = b"\x00\x00\x00\x00"
PROTOCOL_VERSION = 2

PROGRESS_INTERVAL = 0.25
ACK_INTERVAL = 1.0
KEEPALIVE_INTERVAL = 15.0
ACK_TIMEOUT = 90.0
CHUNK_TIMEOUT = 180.0
SEND_TIMEOUT = 180.0
HANDSHAKE_TIMEOUT = 120.0
OFFER_TIMEOUT = 310.0
USER_PROMPT_TIMEOUT = 300.0
DIRECT_TIMEOUT = 30.0
DIRECT_RETRY_BLOCK = 300.0
HASH_BLOCK = 4 * 1024 * 1024
MAX_RETRY_ATTEMPTS = 30
MAX_BACKOFF = 60.0

SOCK_BUF = 4 * 1024 * 1024
STREAM_LIMIT = 4 * 1024 * 1024
AUTH_CONTEXT = b"p2pfs-auth-v2|"

# Socket keepalive settings (Windows and Linux both support these)
TCP_KEEPIDLE_SECONDS = 60
TCP_KEEPINTVL_SECONDS = 15
TCP_KEEPCNT = 4


class HashMismatch(Exception):
    """Full-file SHA256 mismatch - the .part file must be discarded."""


class UserDeclined(Exception):
    """The remote peer declined the handshake or the offer."""


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_config(cfg: dict) -> None:
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


def _tune_socket(writer: asyncio.StreamWriter, bulk: bool = False) -> None:
    """Enable OS-level TCP keepalive; bulk sockets also get big buffers."""
    try:
        sock = writer.get_extra_info("socket")
        if sock is None:
            return
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, TCP_KEEPIDLE_SECONDS)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, TCP_KEEPINTVL_SECONDS)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, TCP_KEEPCNT)
        if hasattr(socket, "TCP_NODELAY"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if bulk:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
            # let one whole frame sit in the transport so the link never idles
            # between frames waiting on drain()
            writer.transport.set_write_buffer_limits(
                high=2 * CHUNK_SIZE, low=CHUNK_SIZE // 2
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_endpoint_name(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9-]", "-", name).strip("-").lower()
    return value or "peer"


def get_public_ip_info() -> tuple[str, str, str]:
    try:
        import stun
        nat_type, external_ip, external_port = stun.get_ip_info()
        if external_ip:
            return str(external_ip), str(external_port), str(nat_type)
    except Exception:
        pass
    try:
        import urllib.request
        ip = (
            urllib.request.urlopen("https://api.ipify.org", timeout=5)
            .read().decode("ascii").strip()
        )
        return ip, "", "unknown"
    except Exception:
        return "unknown", "", "unknown"


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def human_eta(seconds: float) -> str:
    if seconds < 0 or seconds > 86400:
        return "—"
    if seconds < 60:
        return f"{int(seconds)}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def hash_prefix(path: Path, length: int):
    """SHA-256 of the first `length` bytes. Returns (hasher, bytes_missing)."""
    h = hashlib.sha256()
    remaining = length
    buf = bytearray(HASH_BLOCK)
    view = memoryview(buf)
    with path.open("rb", buffering=0) as fh:
        while remaining > 0:
            n = fh.readinto(view[:min(HASH_BLOCK, remaining)])
            if not n:
                break
            h.update(view[:n])
            remaining -= n
    return h, remaining


# ---------------------------------------------------------------------------
# Identity / TrustStore
# ---------------------------------------------------------------------------

class Identity:
    def __init__(self, username, ed_private, x_private):
        self.username = username
        self.ed_private = ed_private
        self.x_private = x_private
        self.ed_public_bytes = ed_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.x_public_bytes = x_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def fingerprint(self) -> str:
        return sha256_hex(self.ed_public_bytes)

    @classmethod
    def load_or_create(cls, path: Path, username: str) -> "Identity":
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return cls(
                    data["username"],
                    ed25519.Ed25519PrivateKey.from_private_bytes(b64d(data["ed_private"])),
                    x25519.X25519PrivateKey.from_private_bytes(b64d(data["x_private"])),
                )
            except Exception:
                pass
        ed_private = ed25519.Ed25519PrivateKey.generate()
        x_private = x25519.X25519PrivateKey.generate()
        identity = cls(username or "peer", ed_private, x_private)
        path.write_text(
            json.dumps({
                "username": identity.username,
                "ed_private": b64e(identity.ed_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )),
                "x_private": b64e(identity.x_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )),
            }, indent=2),
            encoding="utf-8",
        )
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return identity

    def sign(self, payload: bytes) -> bytes:
        return self.ed_private.sign(payload)


class TrustStore:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {}
        if path.exists():
            try:
                self.data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                self.data = {}

    def get(self, username: str):
        return self.data.get(username)

    def is_trusted(self, username: str, ed_public_b64: str) -> bool:
        rec = self.get(username)
        if not rec:
            return False
        return secrets.compare_digest(rec.get("ed_public", ""), ed_public_b64)

    def add(self, username: str, ed_public_b64: str, x_public_b64: str = "") -> None:
        self.data[username] = {
            "ed_public": ed_public_b64,
            "x_public": x_public_b64,
            "trusted_at": str(int(time.time())),
        }
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Framing / transport
# ---------------------------------------------------------------------------

def pack_frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME:
        raise ValueError(f"frame too large: {len(payload)} bytes")
    return struct.pack("!I", len(payload)) + payload


class FrameStream:
    """Length-prefixed frame reassembly with byte-bounded backpressure."""

    def __init__(self, backlog: int = STREAM_BACKLOG):
        self.buffer = bytearray()
        self._pos = 0
        self.queue: asyncio.Queue = asyncio.Queue()
        self.error: Optional[Exception] = None
        self._pending = 0
        self._backlog = backlog
        self._space = asyncio.Event()
        self._space.set()

    def feed(self, data: bytes) -> None:
        buf = self.buffer
        buf += data
        pos = self._pos
        while True:
            avail = len(buf) - pos
            if avail < 4:
                break
            frame_len = int.from_bytes(buf[pos:pos + 4], "big")
            if frame_len > MAX_FRAME:
                self.queue.put_nowait(ValueError("incoming frame too large"))
                buf.clear()
                pos = 0
                break
            if avail < 4 + frame_len:
                break
            self.queue.put_nowait(buf[pos + 4:pos + 4 + frame_len])
            self._pending += frame_len
            pos += 4 + frame_len
        if pos == len(buf):
            buf.clear()
            pos = 0
        elif pos > STREAM_LIMIT:
            del buf[:pos]
            pos = 0
        self._pos = pos
        if self._pending > self._backlog:
            self._space.clear()

    async def wait_space(self) -> None:
        await self._space.wait()

    def _account(self, item):
        if isinstance(item, Exception):
            self.error = item
            return item
        self._pending -= len(item)
        if self._pending <= self._backlog // 2:
            self._space.set()
        return item

    def pop_nowait(self):
        return self._account(self.queue.get_nowait())

    async def pop(self, timeout: float):
        if self.error is not None and self.queue.empty():
            raise self.error
        item = await asyncio.wait_for(self.queue.get(), timeout=timeout)
        return self._account(item)

    async def read(self, timeout: float = CHUNK_TIMEOUT) -> bytes:
        item = await self.pop(timeout)
        if isinstance(item, Exception):
            raise item
        return item


class RelayLink:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self._closed = False

    async def send(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("link closed")
        self.writer.write(data)
        try:
            await asyncio.wait_for(self.writer.drain(), timeout=SEND_TIMEOUT)
        except asyncio.TimeoutError as exc:
            raise ConnectionError("send timeout") from exc

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        try:
            data = await self.reader.read(1024 * 1024)
        except (ConnectionError, OSError):
            raise StopAsyncIteration
        if not data:
            raise StopAsyncIteration
        return data

    def close(self) -> None:
        self._closed = True
        try:
            self.writer.close()
        except Exception:
            pass


async def feed_async_iterable(link, stream: FrameStream) -> None:
    try:
        async for msg in link:
            stream.feed(msg)
            await stream.wait_space()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        stream.queue.put_nowait(exc)
    else:
        # normal close: wake the reader instead of letting it time out
        stream.queue.put_nowait(ConnectionError("link closed"))


async def feed_warpgate_pipe(pipe, stream: FrameStream) -> None:
    try:
        if hasattr(pipe, "subscribe"):
            try:
                pipe.subscribe(SUB_ALL)
            except Exception:
                pass
        while True:
            try:
                msg = await pipe.recv(SUB_ALL, timeout=CHUNK_TIMEOUT)
            except TypeError:
                msg = await pipe.recv()
            if msg:
                stream.feed(msg)
                await stream.wait_space()
            else:
                break
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        stream.queue.put_nowait(exc)
    else:
        stream.queue.put_nowait(ConnectionError("warpgate pipe closed"))


# ---------------------------------------------------------------------------
# Secure session
# ---------------------------------------------------------------------------

def _raw_public(key: x25519.X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class SecureSession:
    """Signed ephemeral-DH handshake, then counter-nonce AES-256-GCM frames.

    Frames are sealed on a worker pool but counters are assigned, and frames
    written, in strict submission order by a single writer task.
    """

    def __init__(self, role, local_identity, trust_store, stream, link, bridge, pool):
        self.role = role
        self.local = local_identity
        self.trust_store = trust_store
        self.stream = stream
        self.link = link
        self.bridge = bridge
        self.remote: Optional[dict] = None
        self._pool = pool
        self._loop = asyncio.get_running_loop()
        self._send_aead: Optional[AESGCM] = None
        self._recv_aead: Optional[AESGCM] = None
        self._send_ctr = 0
        self._recv_ctr = 0
        self._submit_lock = asyncio.Lock()
        self._out: asyncio.Queue = asyncio.Queue(maxsize=PIPELINE_DEPTH)
        self._writer_task: Optional[asyncio.Task] = None
        self._failure: Optional[BaseException] = None

    # handshake -----------------------------------------------------------
    async def _send_plain(self, obj):
        await self.link.send(pack_frame(canonical_json(obj)))

    async def handshake_initiator(self, trust_callback):
        eph = x25519.X25519PrivateKey.generate()
        hello = {
            "v": PROTOCOL_VERSION,
            "username": self.local.username,
            "ed_public": b64e(self.local.ed_public_bytes),
            "x_public": b64e(_raw_public(eph)),
            "nonce": b64e(os.urandom(16)),
            "ts": int(time.time()),
        }
        hello["sig"] = b64e(self.local.sign(canonical_json(hello)))
        hello["type"] = "hello"
        await self._send_plain(hello)

        frame = await self.stream.read(timeout=HANDSHAKE_TIMEOUT)
        ack = json.loads(frame.decode())
        if ack.get("type") == "error":
            raise PermissionError(f"peer refused: {ack.get('message', 'unknown')}")
        if ack.get("type") != "hello_ack":
            raise ValueError("expected hello_ack")
        remote = self._verify_hello(ack, extra=("init_nonce",))
        if not secrets.compare_digest(str(ack["init_nonce"]), hello["nonce"]):
            raise ValueError("hello_ack does not answer our hello")
        if not await trust_callback(remote):
            raise PermissionError(f"user declined to trust {remote['username']}")
        self._derive_keys(
            eph, hello, ack, initiator=True,
        )
        self.remote = remote

    async def handshake_responder(self, first_frame: bytes, trust_callback):
        hello = json.loads(first_frame.decode())
        if hello.get("type") != "hello":
            raise ValueError("expected hello")
        remote = self._verify_hello(hello)
        if not await trust_callback(remote):
            await self._send_plain({"type": "error", "message": "untrusted"})
            raise PermissionError(f"user declined to trust {remote['username']}")
        eph = x25519.X25519PrivateKey.generate()
        ack = {
            "v": PROTOCOL_VERSION,
            "username": self.local.username,
            "ed_public": b64e(self.local.ed_public_bytes),
            "x_public": b64e(_raw_public(eph)),
            "nonce": b64e(os.urandom(16)),
            "init_nonce": hello["nonce"],
            "ts": int(time.time()),
        }
        ack["sig"] = b64e(self.local.sign(canonical_json(ack)))
        ack["type"] = "hello_ack"
        await self._send_plain(ack)
        self._derive_keys(eph, hello, ack, initiator=False)
        self.remote = remote

    def _verify_hello(self, obj, extra=()):
        signed = ("v", "username", "ed_public", "x_public", "nonce", "ts") + tuple(extra)
        for key in signed + ("sig",):
            if key not in obj:
                raise ValueError(f"handshake missing {key}")
        if int(obj["v"]) != PROTOCOL_VERSION:
            raise ValueError(
                f"unsupported protocol version {obj['v']} "
                f"(this build speaks {PROTOCOL_VERSION}); update both peers"
            )
        if abs(time.time() - int(obj["ts"])) > 300:
            raise ValueError("handshake timestamp outside allowed skew")
        payload = {k: obj[k] for k in signed}
        pk = ed25519.Ed25519PublicKey.from_public_bytes(b64d(obj["ed_public"]))
        try:
            pk.verify(b64d(obj["sig"]), canonical_json(payload))
        except InvalidSignature as exc:
            raise ValueError("invalid signature") from exc
        return {
            "username": obj["username"],
            "ed_public": obj["ed_public"],
            "x_public": obj["x_public"],
            "nonce": obj["nonce"],
        }

    def _derive_keys(self, eph, hello, ack, initiator):
        remote_eph = ack["x_public"] if initiator else hello["x_public"]
        shared = eph.exchange(
            x25519.X25519PublicKey.from_public_bytes(b64d(remote_eph))
        )
        salt = b64d(hello["nonce"]) + b64d(ack["nonce"])
        info = (
            b"p2pfs-v2|" + b64d(hello["ed_public"]) + b64d(ack["ed_public"])
            + b64d(hello["x_public"]) + b64d(ack["x_public"])
        )
        okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info).derive(shared)
        c2s, s2c = okm[:32], okm[32:]
        send_key, recv_key = (c2s, s2c) if initiator else (s2c, c2s)
        self._send_aead = AESGCM(send_key)
        self._recv_aead = AESGCM(recv_key)

    # sealing -------------------------------------------------------------
    def _seal_at(self, ctr: int, plaintext: bytes) -> bytes:
        nonce = NONCE_PREFIX + ctr.to_bytes(8, "big")
        ct = self._send_aead.encrypt(nonce, plaintext, AAD)
        if len(ct) > MAX_FRAME:
            raise ValueError(f"frame too large: {len(ct)} bytes")
        return len(ct).to_bytes(4, "big") + ct

    def _seal_json(self, ctr: int, payload: bytes) -> bytes:
        return self._seal_at(ctr, b"J" + payload)

    def _seal_chunk(self, ctr: int, seq: int, data: bytes) -> bytes:
        return self._seal_at(ctr, b"".join((b"C", seq.to_bytes(8, "big"), data)))

    def _open_at(self, ctr: int, frame):
        nonce = NONCE_PREFIX + ctr.to_bytes(8, "big")
        try:
            pt = self._recv_aead.decrypt(nonce, frame, AAD)
        except InvalidTag as exc:
            raise ValueError(
                "AES-GCM auth failed (tampered, replayed or reordered frame)"
            ) from exc
        kind = pt[:1]
        if kind == b"J":
            return "json", json.loads(pt[1:]), None
        if kind == b"C":
            if len(pt) < 9:
                raise ValueError("chunk frame too short")
            return "chunk", int.from_bytes(pt[1:9], "big"), memoryview(pt)[9:]
        raise ValueError("unknown message kind")

    # ordered send pipeline ----------------------------------------------
    async def _enqueue(self, fn, *args, offload: bool = False) -> None:
        if self._failure is not None:
            raise ConnectionError(f"link failed: {self._failure}") from self._failure
        if self._writer_task is None:
            self._writer_task = asyncio.create_task(self._writer_loop())
        async with self._submit_lock:
            ctr = self._send_ctr
            self._send_ctr += 1
            if offload:
                fut = self._loop.run_in_executor(self._pool, fn, ctr, *args)
            else:
                fut = self._loop.create_future()
                try:
                    fut.set_result(fn(ctr, *args))
                except Exception as exc:
                    fut.set_exception(exc)
            await self._out.put(fut)

    async def _writer_loop(self) -> None:
        try:
            while True:
                fut = await self._out.get()
                try:
                    data = await fut
                    await self.link.send(data)
                finally:
                    self._out.task_done()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._failure = exc
            self.stream.queue.put_nowait(exc)
            while True:
                try:
                    stale = self._out.get_nowait()
                except asyncio.QueueEmpty:
                    break
                stale.cancel()
                self._out.task_done()

    async def send_json(self, obj) -> None:
        await self._enqueue(self._seal_json, canonical_json(obj))

    async def send_chunk(self, seq: int, data: bytes) -> None:
        await self._enqueue(self._seal_chunk, seq, data, offload=True)

    async def aclose(self, flush: bool = True) -> None:
        task = self._writer_task
        if task is None:
            return
        if flush and self._failure is None:
            try:
                await asyncio.wait_for(self._out.join(), timeout=5.0)
            except asyncio.TimeoutError:
                pass
        task.cancel()
        await asyncio.wait([task])

    def abort(self) -> None:
        try:
            self.link.close()
        except Exception:
            pass

    # ordered receive pipeline -------------------------------------------
    def _start_open(self, item) -> asyncio.Future:
        if isinstance(item, Exception):
            fut = self._loop.create_future()
            fut.set_exception(item)
            return fut
        ctr = self._recv_ctr
        self._recv_ctr += 1
        if len(item) > INLINE_CRYPTO_LIMIT:
            return self._loop.run_in_executor(self._pool, self._open_at, ctr, item)
        fut = self._loop.create_future()
        try:
            fut.set_result(self._open_at(ctr, item))
        except Exception as exc:
            fut.set_exception(exc)
        return fut

    def recv_start_nowait(self) -> Optional[asyncio.Future]:
        if self.stream.queue.empty():
            return None
        return self._start_open(self.stream.pop_nowait())

    async def recv_start(self, timeout: float) -> asyncio.Future:
        return self._start_open(await self.stream.pop(timeout))

    async def recv_message(self, timeout: float = CHUNK_TIMEOUT):
        return await (await self.recv_start(timeout))


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

class Bridge(QObject):
    log = Signal(str)
    public_ip = Signal(str, str, str)
    peers = Signal(list)
    incoming_offer = Signal(dict)
    trust_request = Signal(dict)
    transfer_started = Signal(str, str)
    transfer_progress = Signal(str, object, object)
    transfer_retrying = Signal(str, int, str)
    transfer_finished = Signal(str, bool, str)
    error = Signal(str)


# ---------------------------------------------------------------------------
# ServerControl
# ---------------------------------------------------------------------------

class ServerControl:
    def __init__(self, host: str, port: int, network: "P2PNetwork"):
        self.host = host
        self.port = port
        self.network = network
        self.bridge = network.bridge
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False
        self._task: Optional[asyncio.Task] = None
        self._ping_task: Optional[asyncio.Task] = None
        self._should_stop = False
        self._relay_waiters: dict[str, asyncio.Future] = {}

    def _send(self, obj: dict) -> None:
        assert self.writer is not None
        self.writer.write(json.dumps(obj).encode() + b"\n")

    async def _read_msg(self, timeout: float = 30.0) -> dict:
        assert self.reader is not None
        line = await asyncio.wait_for(self.reader.readline(), timeout=timeout)
        if not line:
            raise ConnectionError("server closed the connection")
        return json.loads(line.decode())

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        _tune_socket(self.writer)
        ident = self.network.identity
        self._send({
            "type": "hello",
            "id": self.network.endpoint_name,
            "username": ident.username,
            "ed_public": b64e(ident.ed_public_bytes),
            "x_public": b64e(ident.x_public_bytes),
        })
        await self.writer.drain()

        challenge = await self._read_msg()
        if challenge.get("type") == "error":
            raise ConnectionError(challenge.get("message", "server rejected hello"))
        if challenge.get("type") != "challenge":
            raise ConnectionError("server did not send an auth challenge")
        sig = ident.sign(
            AUTH_CONTEXT + b64d(challenge["nonce"]) + self.network.endpoint_name.encode()
        )
        self._send({"type": "auth", "sig": b64e(sig)})
        await self.writer.drain()

        welcome = await self._read_msg()
        if welcome.get("type") != "welcome":
            raise ConnectionError(welcome.get("message", "server did not send welcome"))
        self.connected = True
        self.bridge.log.emit(f"Connected to relay server {self.host}:{self.port}")
        self.bridge.peers.emit(welcome.get("peers", []))
        self._task = asyncio.create_task(self._read_loop())
        self._ping_task = asyncio.create_task(self._ping_loop())

    async def _ping_loop(self) -> None:
        try:
            while self.connected and self.writer is not None:
                await asyncio.sleep(30.0)
                if not self.connected or self.writer is None:
                    break
                self._send({"type": "ping"})
                await self.writer.drain()
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    async def _read_loop(self) -> None:
        try:
            while True:
                msg = await self._read_msg(timeout=3600.0)
                mtype = msg.get("type")
                if mtype == "peers":
                    self.bridge.peers.emit(msg.get("peers", []))
                elif mtype == "relay_incoming":
                    self.network.spawn(
                        self.network.accept_relay(msg["from"], msg["token"])
                    )
                elif mtype == "relay_ticket":
                    waiter = self._relay_waiters.get(msg.get("req"))
                    if waiter is not None and not waiter.done():
                        waiter.set_result(msg["token"])
                elif mtype == "error":
                    waiter = self._relay_waiters.get(msg.get("req"))
                    if waiter is not None and not waiter.done():
                        waiter.set_exception(ConnectionError(msg.get("message")))
                    else:
                        self.bridge.log.emit(f"Server: {msg.get('message')}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.bridge.log.emit(f"Server control loop ended: {exc}")
        finally:
            self.connected = False
            for waiter in self._relay_waiters.values():
                if not waiter.done():
                    waiter.set_exception(ConnectionError("server connection lost"))
            if not self._should_stop:
                self.network.spawn(self.network.reconnect_server())

    async def request_relay(self, target_id: str) -> str:
        if not self.connected or self.writer is None:
            raise ConnectionError("not connected to relay server")
        req = secrets.token_hex(8)
        waiter = asyncio.get_running_loop().create_future()
        self._relay_waiters[req] = waiter
        try:
            self._send({"type": "relay_request", "target": target_id, "req": req})
            await self.writer.drain()
            return await asyncio.wait_for(waiter, timeout=15.0)
        finally:
            self._relay_waiters.pop(req, None)

    def close(self) -> None:
        self._should_stop = True
        for t in (self._task, self._ping_task):
            if t:
                t.cancel()
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
        self.connected = False


# ---------------------------------------------------------------------------
# P2PNetwork
# ---------------------------------------------------------------------------

class P2PNetwork:
    def __init__(self, identity, trust_store, bridge):
        self.identity = identity
        self.trust_store = trust_store
        self.bridge = bridge

        base = sanitize_endpoint_name(identity.username)[:24]
        self.endpoint_name = f"p2pfs-{base}-{identity.fingerprint[:10]}"

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        self.gate: Any = None
        self.stop_event: Optional[asyncio.Event] = None
        self._loop_ready = threading.Event()
        self._tasks: set[asyncio.Task] = set()
        self._crypto_pool = ThreadPoolExecutor(
            max_workers=CRYPTO_WORKERS, thread_name_prefix="p2pfs-crypto"
        )

        self._pending_answers: dict[str, asyncio.Future] = {}

        self.server: Optional[ServerControl] = None
        self.server_host: Optional[str] = None
        self.server_port: Optional[int] = None
        self._should_auto_reconnect = True

        self._send_lock: Optional[asyncio.Lock] = None
        self._cancelled: set[str] = set()
        self._cancel_lock = threading.Lock()
        self._cancel_events: dict[str, asyncio.Event] = {}

        # receiver-side resume helpers
        self._receive_locks: dict[str, asyncio.Lock] = {}
        self._offer_decisions: dict[str, tuple[bool, Optional[str]]] = {}
        # peers whose direct path failed recently: try the relay first
        self._direct_blocked_until: dict[str, float] = {}

    # lifecycle -----------------------------------------------------------
    def start(self) -> None:
        self.thread = threading.Thread(
            target=self._run_loop, daemon=True, name="p2pfs-network"
        )
        self.thread.start()

    def stop(self) -> None:
        self._should_auto_reconnect = False
        if self.loop and self.stop_event:
            self.loop.call_soon_threadsafe(self.stop_event.set)
        self._crypto_pool.shutdown(wait=False, cancel_futures=True)

    def spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _run_loop(self) -> None:
        if sys.platform == "win32":
            self.loop = asyncio.SelectorEventLoop()
        else:
            self.loop = asyncio.new_event_loop()
        self._loop_ready.set()
        try:
            self.loop.run_until_complete(self._main())
        except Exception:
            self.bridge.error.emit(traceback.format_exc())
        finally:
            try:
                self.loop.close()
            except Exception:
                pass

    async def _main(self) -> None:
        self.stop_event = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self.bridge.log.emit(f"Identity fingerprint: {self.identity.fingerprint}")
        self.spawn(self._refresh_public_ip())
        try:
            await asyncio.to_thread(_load_warpgate)
            self.gate = Gate(self.endpoint_name)
        except Exception as exc:
            self.gate = None
            self.bridge.log.emit(
                f"Direct transport unavailable ({exc}); relay-only mode"
            )
        if self.gate is None:
            await self.stop_event.wait()
            return
        async with self.gate:
            self.bridge.log.emit(f"Registered Warpgate endpoint: {self.endpoint_name}")
            listener = asyncio.create_task(
                self.gate.listen(self._handle_warpgate_incoming)
            )
            await self.stop_event.wait()
            listener.cancel()

    async def _refresh_public_ip(self) -> None:
        try:
            ip, port, nat = await asyncio.to_thread(get_public_ip_info)
            self.bridge.public_ip.emit(ip, port, nat)
            self.bridge.log.emit(f"Public endpoint: {ip}:{port}  NAT: {nat}")
        except Exception as exc:
            self.bridge.log.emit(f"Public IP lookup failed: {exc}")

    # cancel --------------------------------------------------------------
    def cancel_transfer(self, file_id: str) -> None:
        with self._cancel_lock:
            self._cancelled.add(file_id)
        evt = self._cancel_events.get(file_id)
        if evt is not None and self.loop is not None:
            try:
                self.loop.call_soon_threadsafe(evt.set)
            except Exception:
                pass
        self.bridge.log.emit(f"Cancel requested for {file_id[:8]}...")

    def _is_cancelled(self, file_id: str) -> bool:
        with self._cancel_lock:
            return file_id in self._cancelled

    def _clear_cancel(self, file_id: str) -> None:
        with self._cancel_lock:
            self._cancelled.discard(file_id)
        self._cancel_events.pop(file_id, None)

    def _get_cancel_event(self, file_id: str) -> asyncio.Event:
        evt = self._cancel_events.get(file_id)
        if evt is None:
            evt = asyncio.Event()
            self._cancel_events[file_id] = evt
        return evt

    # user prompts --------------------------------------------------------
    async def _ask_user(self, signal, payload: dict):
        """Emit `payload` to the GUI and wait for answer(); None on timeout."""
        req = secrets.token_hex(8)
        fut = asyncio.get_running_loop().create_future()
        self._pending_answers[req] = fut
        payload["req"] = req
        signal.emit(payload)
        try:
            return await asyncio.wait_for(fut, timeout=USER_PROMPT_TIMEOUT)
        except asyncio.TimeoutError:
            return None
        finally:
            self._pending_answers.pop(req, None)

    def answer(self, req: str, value) -> None:
        """Called from the GUI thread."""
        if self.loop is None:
            return

        def _resolve():
            fut = self._pending_answers.get(req)
            if fut is not None and not fut.done():
                fut.set_result(value)

        self.loop.call_soon_threadsafe(_resolve)

    # trust ---------------------------------------------------------------
    async def _trust_callback(self, remote: dict) -> bool:
        username = remote["username"]
        ed_public = remote["ed_public"]
        if self.trust_store.is_trusted(username, ed_public):
            self.bridge.log.emit(f"Trusted peer {username}")
            return True
        existing = self.trust_store.get(username)
        payload = dict(remote)
        if existing and existing.get("ed_public") != ed_public:
            payload["key_changed"] = True
            self.bridge.log.emit(
                f"SECURITY WARNING: {username} presented a different key!"
            )
        allowed = await self._ask_user(self.bridge.trust_request, payload)
        if allowed:
            self.trust_store.add(username, ed_public)
            return True
        return False

    # server control ------------------------------------------------------
    def connect_server(self, host: str, port: int) -> None:
        if not self._loop_ready.wait(timeout=5.0) or not self.loop:
            self.bridge.error.emit("network loop not running")
            return
        self.server_host, self.server_port = host, port
        self._should_auto_reconnect = True
        asyncio.run_coroutine_threadsafe(self._connect_server_loop(), self.loop)

    async def _connect_server_loop(self) -> None:
        backoff = 1.0
        while self._should_auto_reconnect:
            if self.server:
                self.server.close()
            self.server = ServerControl(self.server_host, self.server_port, self)
            try:
                await self.server.connect()
                return
            except Exception as exc:
                self.bridge.log.emit(
                    f"Server connect failed: {exc}; retrying in {backoff:.0f}s"
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)

    async def reconnect_server(self) -> None:
        if not self._should_auto_reconnect:
            return
        self.bridge.log.emit("Reconnecting to relay server...")
        await self._connect_server_loop()

    async def _open_relay_socket(self, token: str):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.server_host, self.server_port, limit=STREAM_LIMIT
            ),
            timeout=30.0,
        )
        _tune_socket(writer, bulk=True)
        writer.write(f"relay {token}\n".encode())
        await writer.drain()
        return reader, writer

    # send ----------------------------------------------------------------
    def send_file(self, target_id: str, file_path: str) -> None:
        if not self.loop:
            self.bridge.error.emit("network loop not running")
            return
        asyncio.run_coroutine_threadsafe(
            self._send_file(target_id, Path(file_path)), self.loop
        )

    async def _send_file(self, target_id: str, path: Path) -> None:
        assert self._send_lock is not None
        if self._send_lock.locked():
            self.bridge.log.emit("Another send is in progress; queuing this one.")
        async with self._send_lock:
            file_id = secrets.token_hex(16)
            self.bridge.transfer_started.emit(file_id, path.name)
            try:
                await self._send_file_with_retry(target_id, path, file_id)
            finally:
                self._clear_cancel(file_id)

    async def _send_file_with_retry(
        self, target_id: str, path: Path, file_id: str
    ) -> None:
        backoff = 1.0
        attempt = 0
        while True:
            attempt += 1
            try:
                await self._send_file_once(target_id, path, file_id, attempt)
                self.bridge.transfer_finished.emit(file_id, True, path.name)
                return
            except UserDeclined as exc:
                self.bridge.log.emit(f"Peer declined: {exc}")
                self.bridge.transfer_finished.emit(file_id, False, "peer declined")
                return
            except FileNotFoundError as exc:
                self.bridge.transfer_finished.emit(file_id, False, str(exc))
                return
            except asyncio.CancelledError:
                self.bridge.transfer_finished.emit(file_id, False, "cancelled")
                raise
            except (ConnectionError, asyncio.TimeoutError, OSError) as exc:
                if attempt >= MAX_RETRY_ATTEMPTS:
                    self.bridge.log.emit(f"Max retries reached: {exc}")
                    self.bridge.transfer_finished.emit(
                        file_id, False, f"max retries: {exc}"
                    )
                    return
                self.bridge.log.emit(
                    f"Transfer dropped ({exc}); resuming in {backoff:.0f}s "
                    f"(attempt {attempt + 1})"
                )
                self.bridge.transfer_retrying.emit(file_id, attempt + 1, str(exc))
                evt = self._get_cancel_event(file_id)
                try:
                    await asyncio.wait_for(evt.wait(), timeout=backoff)
                    # user cancelled during backoff
                    self.bridge.transfer_finished.emit(file_id, False, "cancelled")
                    return
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, MAX_BACKOFF)
            except Exception as exc:
                self.bridge.log.emit(f"Send failed: {exc}")
                self.bridge.transfer_finished.emit(file_id, False, str(exc))
                return

    async def _send_file_once(
        self, target_id: str, path: Path, file_id: str, attempt: int
    ) -> None:
        if not path.is_file():
            raise FileNotFoundError(path)

        relay_ready = self.server is not None and self.server.connected
        direct_blocked = time.monotonic() < self._direct_blocked_until.get(target_id, 0.0)
        order = ["direct", "relay"]
        if relay_ready and direct_blocked:
            order.reverse()

        last_exc: Optional[Exception] = None
        for kind in order:
            try:
                if kind == "direct":
                    await self._send_warpgate(target_id, path, file_id, attempt)
                else:
                    await self._send_relay(target_id, path, file_id, attempt)
                return
            except (UserDeclined, FileNotFoundError, asyncio.CancelledError):
                raise
            except Exception as exc:
                last_exc = exc
                self.bridge.log.emit(f"{kind} path failed ({exc})")
        if not relay_ready and last_exc is not None:
            raise ConnectionError(
                f"direct path failed and no relay server connected: {last_exc}"
            ) from last_exc
        assert last_exc is not None
        raise last_exc

    async def _send_relay(
        self, target_id: str, path: Path, file_id: str, attempt: int
    ) -> None:
        if not self.server or not self.server.connected:
            raise ConnectionError("no relay server connected")
        try:
            token = await self.server.request_relay(target_id)
            reader, writer = await self._open_relay_socket(token)
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            raise ConnectionError(f"relay connect failed: {exc}") from exc
        link = RelayLink(reader, writer)
        await self._run_outgoing(
            link, feed_async_iterable, "relay", path, file_id, attempt
        )

    async def _send_warpgate(
        self, target_id: str, path: Path, file_id: str, attempt: int
    ) -> None:
        if self.gate is None:
            raise ConnectionError("direct transport not available")
        try:
            target = peer.find(target_id)
        except Exception:
            target = target_id

        try:
            result = await self.gate.connect(
                target, transport=TCP, timeout=DIRECT_TIMEOUT
            )
            if result is None:
                raise ConnectionError("all Warpgate strategies exhausted")
            pipe, plugin = result if isinstance(result, tuple) else (result, None)
            if pipe is None:
                raise ConnectionError("no pipe returned")
        except Exception as exc:
            self._direct_blocked_until[target_id] = time.monotonic() + DIRECT_RETRY_BLOCK
            raise ConnectionError(f"Warpgate connect failed: {exc}") from exc
        self._direct_blocked_until.pop(target_id, None)

        self.bridge.log.emit(
            f"Connected via {getattr(plugin, 'winner_plugin', 'unknown')}"
        )
        await self._run_outgoing(
            pipe, feed_warpgate_pipe, "warpgate", path, file_id, attempt
        )

    async def _run_outgoing(
        self, link, feeder, label: str, path: Path, file_id: str, attempt: int
    ) -> None:
        stream = FrameStream()
        feed = asyncio.create_task(feeder(link, stream))
        session = SecureSession(
            "initiator", self.identity, self.trust_store, stream, link,
            self.bridge, self._crypto_pool,
        )
        try:
            try:
                await session.handshake_initiator(self._trust_callback)
            except PermissionError as exc:
                raise UserDeclined(str(exc)) from exc
            self.bridge.log.emit(
                f"E2E session with {session.remote['username']} ({label})"
            )
            await self._transfer_out(session, path, file_id, attempt)
        finally:
            feed.cancel()
            await session.aclose()
            try:
                link.close()
            except Exception:
                pass

    async def _keepalive_loop(self, session, stop_evt):
        try:
            while not stop_evt.is_set():
                try:
                    await asyncio.wait_for(
                        stop_evt.wait(), timeout=KEEPALIVE_INTERVAL
                    )
                    break
                except asyncio.TimeoutError:
                    pass
                if stop_evt.is_set():
                    break
                try:
                    await session.send_json({"type": "keepalive"})
                except Exception:
                    return
        except asyncio.CancelledError:
            raise

    async def _ack_loop(self, session) -> None:
        """Consume everything the receiver sends; finishes on 'saved'."""
        try:
            while True:
                kind, obj, _ = await session.recv_message(timeout=ACK_TIMEOUT)
                t = obj.get("type") if kind == "json" else None
                if t in ("progress", "keepalive"):
                    continue
                if t == "saved":
                    return
                if t == "error":
                    raise ValueError(obj.get("message", "peer error"))
                raise ValueError(f"unexpected message from receiver: {obj}")
        except asyncio.TimeoutError as exc:
            raise ConnectionError("receiver stopped acknowledging") from exc

    async def _transfer_out(
        self, session, path: Path, file_id: str, attempt: int
    ) -> None:
        name = path.name
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise FileNotFoundError(f"stat failed: {exc}")
        loop = asyncio.get_running_loop()

        keepalive_stop = asyncio.Event()
        keepalive_task = asyncio.create_task(
            self._keepalive_loop(session, keepalive_stop)
        )
        ack_task: Optional[asyncio.Task] = None
        read_pool = ThreadPoolExecutor(1, thread_name_prefix="p2pfs-read")
        hash_pool = ThreadPoolExecutor(1, thread_name_prefix="p2pfs-hash")
        reads: deque = deque()
        hashes_pending: deque = deque()

        try:
            await session.send_json({
                "type": "offer",
                "file_id": file_id,
                "name": name,
                "size": size,
                "chunk_size": CHUNK_SIZE,
                "attempt": attempt,
            })

            kind, response, _ = await session.recv_message(timeout=OFFER_TIMEOUT)
            if kind != "json":
                raise ValueError("expected JSON")
            if response.get("type") == "decline":
                raise UserDeclined(f"peer declined {name}")
            if response.get("type") != "accept":
                raise ValueError(f"unexpected response: {response}")

            offset = int(response.get("offset", 0))
            if offset < 0 or offset > size:
                raise ValueError(f"invalid resume offset {offset}")
            if offset > 0:
                self.bridge.log.emit(
                    f"Resuming {name} from {human_bytes(offset)}"
                )

            # whole-file SHA-256 for end-to-end verification
            h = hashlib.sha256()
            if offset > 0:
                h, missing = await asyncio.to_thread(hash_prefix, path, offset)
                if missing:
                    raise ValueError("file shrank since last attempt")

            ack_task = asyncio.create_task(self._ack_loop(session))

            def _on_ack_done(task: asyncio.Task) -> None:
                if not task.cancelled() and task.exception() is not None:
                    session.abort()  # unblock a writer stuck on a dead link

            ack_task.add_done_callback(_on_ack_done)

            sent = offset
            seq = offset // CHUNK_SIZE
            last_progress = time.monotonic()

            with path.open("rb") as f:
                if offset > 0:
                    f.seek(offset)
                for _ in range(2):
                    reads.append(loop.run_in_executor(read_pool, f.read, CHUNK_SIZE))

                while True:
                    if self._is_cancelled(file_id):
                        raise asyncio.CancelledError("cancelled by user")
                    if ack_task.done():
                        break

                    chunk = await reads.popleft()
                    if not chunk:
                        break
                    reads.append(loop.run_in_executor(read_pool, f.read, CHUNK_SIZE))
                    hashes_pending.append(
                        loop.run_in_executor(hash_pool, h.update, chunk)
                    )
                    if len(hashes_pending) > PIPELINE_DEPTH:
                        await hashes_pending.popleft()

                    await session.send_chunk(seq, chunk)
                    seq += 1
                    sent += len(chunk)

                    now = time.monotonic()
                    if now - last_progress >= PROGRESS_INTERVAL:
                        self.bridge.transfer_progress.emit(file_id, sent, size)
                        last_progress = now

                await asyncio.gather(*reads, return_exceptions=True)
                reads.clear()

            if not ack_task.done():
                await asyncio.gather(*hashes_pending)
                hashes_pending.clear()
                await session.send_json({
                    "type": "done", "file_id": file_id, "sha256": h.hexdigest(),
                })
                self.bridge.transfer_progress.emit(file_id, size, size)

            await ack_task
            self.bridge.log.emit(f"Peer confirmed receipt of {name}")

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if ack_task is not None and ack_task.done() and not ack_task.cancelled():
                peer_exc = ack_task.exception()
                if peer_exc is not None and peer_exc is not exc:
                    raise peer_exc from exc
            raise
        finally:
            keepalive_stop.set()
            keepalive_task.cancel()
            if ack_task is not None:
                ack_task.cancel()
            await asyncio.gather(*reads, *hashes_pending, return_exceptions=True)
            read_pool.shutdown(wait=False)
            hash_pool.shutdown(wait=False)

    # receive -------------------------------------------------------------
    async def accept_relay(self, from_id: str, token: str) -> None:
        try:
            reader, writer = await self._open_relay_socket(token)
            link = RelayLink(reader, writer)
            await self._handle_incoming(link)
        except Exception as exc:
            self.bridge.error.emit(f"Relay accept failed: {exc}")

    async def _handle_warpgate_incoming(self, link) -> None:
        await self._handle_incoming(link)

    async def _handle_incoming(self, link) -> None:
        stream = FrameStream()
        feed = asyncio.create_task(feed_async_iterable(link, stream))
        session = SecureSession(
            "responder", self.identity, self.trust_store, stream, link,
            self.bridge, self._crypto_pool,
        )
        try:
            first = await stream.read(timeout=HANDSHAKE_TIMEOUT)
            try:
                await session.handshake_responder(first, self._trust_callback)
            except PermissionError as exc:
                self.bridge.log.emit(f"Rejected untrusted peer: {exc}")
                return
            self.bridge.log.emit(
                f"E2E session from {session.remote['username']}"
            )
            await self._receive_file(session)
        except (
            ConnectionError, ConnectionAbortedError, ConnectionResetError,
            BrokenPipeError, asyncio.TimeoutError, OSError,
        ) as exc:
            self.bridge.log.emit(
                f"Connection dropped: {exc} "
                "(kept .part for resume if transfer was in progress)"
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.bridge.error.emit(f"Incoming connection failed: {exc}")
        finally:
            feed.cancel()
            await session.aclose()
            try:
                link.close()
            except Exception:
                pass

    async def _receive_file(self, session) -> None:
        kind, offer, _ = await session.recv_message()
        if kind != "json" or offer.get("type") != "offer":
            raise ValueError("expected offer")

        file_id = offer["file_id"]
        name = offer["name"]
        size = int(offer["size"])
        attempt = int(offer.get("attempt", 1))
        offer["sender"] = session.remote["username"]
        offer["sender_fingerprint"] = sha256_hex(b64d(session.remote["ed_public"]))
        loop = asyncio.get_running_loop()

        # serialize concurrent offers for the same file_id (retries)
        lock = self._receive_locks.setdefault(file_id, asyncio.Lock())
        async with lock:
            decision = self._offer_decisions.get(file_id)
            if decision is None:
                decision = await self._ask_user(
                    self.bridge.incoming_offer, offer
                ) or (False, None)
                self._offer_decisions[file_id] = decision

            accepted, save_path_str = decision
            if not accepted or not save_path_str:
                await session.send_json({"type": "decline"})
                return

            save_path = Path(save_path_str)
            part_path = save_path.with_name(save_path.name + ".part")

            existing = 0
            if part_path.exists():
                try:
                    existing = part_path.stat().st_size
                except OSError:
                    existing = 0
                if existing > size:
                    try:
                        part_path.unlink()
                    except Exception:
                        pass
                    existing = 0
                aligned = (existing // CHUNK_SIZE) * CHUNK_SIZE
                if aligned != existing:
                    try:
                        with part_path.open("r+b") as fh:
                            fh.truncate(aligned)
                    except Exception:
                        pass
                    existing = aligned

            await session.send_json({"type": "accept", "offset": existing})

            self.bridge.transfer_started.emit(file_id, name)
            if attempt > 1:
                self.bridge.transfer_retrying.emit(
                    file_id, attempt, "resuming from .part"
                )

            self.bridge.log.emit(
                f"Receiving {name} ({human_bytes(size)}) from {offer['sender']}"
                + (f", resuming at {human_bytes(existing)}" if existing else "")
            )

            keepalive_stop = asyncio.Event()
            keepalive_task = asyncio.create_task(
                self._keepalive_loop(session, keepalive_stop)
            )

            h = hashlib.sha256()
            received = existing
            expected_seq = existing // CHUNK_SIZE
            last_progress = time.monotonic()
            last_ack = time.monotonic()
            expected_sha: Optional[str] = None
            io_pool = ThreadPoolExecutor(1, thread_name_prefix="p2pfs-write")
            hash_pool = ThreadPoolExecutor(1, thread_name_prefix="p2pfs-hash")
            inflight: deque = deque()
            pending: deque = deque()

            try:
                if existing > 0:
                    h, missing = await asyncio.to_thread(hash_prefix, part_path, existing)
                    if missing:
                        raise ValueError(".part shrank while resuming")

                f = part_path.open("ab" if existing > 0 else "wb")
                try:
                    while True:
                        if self._is_cancelled(file_id):
                            raise asyncio.CancelledError("cancelled by user")

                        # decrypt everything already queued in parallel, then
                        # consume strictly in order
                        while len(inflight) < PIPELINE_DEPTH:
                            fut = session.recv_start_nowait()
                            if fut is None:
                                break
                            inflight.append(fut)
                        if not inflight:
                            inflight.append(await session.recv_start(CHUNK_TIMEOUT))
                        kind, obj, data = await inflight.popleft()

                        if kind == "json":
                            t = obj.get("type")
                            if t == "done":
                                expected_sha = obj.get("sha256")
                                break
                            if t == "error":
                                raise ValueError(obj.get("message", "peer error"))
                            if t == "keepalive":
                                continue
                            raise ValueError(f"unexpected message: {obj}")

                        if obj != expected_seq:
                            raise ValueError(
                                f"sequence mismatch: expected {expected_seq}, "
                                f"got {obj}"
                            )
                        expected_seq += 1
                        received += len(data)
                        if received > size:
                            raise ValueError("peer sent more data than it offered")

                        pending.append(asyncio.gather(
                            loop.run_in_executor(io_pool, f.write, data),
                            loop.run_in_executor(hash_pool, h.update, data),
                        ))
                        if len(pending) > PIPELINE_DEPTH:
                            await pending.popleft()

                        now = time.monotonic()
                        if now - last_progress >= PROGRESS_INTERVAL:
                            self.bridge.transfer_progress.emit(
                                file_id, received, size
                            )
                            last_progress = now
                        if now - last_ack >= ACK_INTERVAL:
                            await session.send_json({
                                "type": "progress",
                                "file_id": file_id,
                                "bytes": received,
                            })
                            last_ack = now

                    await asyncio.gather(*pending)
                    pending.clear()
                finally:
                    await asyncio.gather(*pending, return_exceptions=True)
                    f.close()

                actual_sha = h.hexdigest()
                if expected_sha and actual_sha != expected_sha:
                    raise HashMismatch(
                        f"SHA256 mismatch (expected {expected_sha}, got {actual_sha})"
                    )

                part_path.replace(save_path)
                await session.send_json({"type": "saved", "file_id": file_id})
                self.bridge.transfer_progress.emit(file_id, size, size)
                self.bridge.log.emit(
                    f"Saved {name} -> {save_path} (verified)"
                )
                self.bridge.transfer_finished.emit(file_id, True, str(save_path))
                self._offer_decisions.pop(file_id, None)

            except asyncio.CancelledError:
                self.bridge.log.emit(f"Receiving {name} cancelled")
                try:
                    await asyncio.wait_for(
                        session.send_json({
                            "type": "error", "file_id": file_id,
                            "message": "cancelled",
                        }),
                        timeout=2.0,
                    )
                except Exception:
                    pass
                try:
                    part_path.unlink(missing_ok=True)
                except Exception:
                    pass
                self.bridge.transfer_finished.emit(file_id, False, "cancelled")
                self._offer_decisions.pop(file_id, None)
                raise

            except HashMismatch as exc:
                self.bridge.log.emit(
                    f"Hash mismatch on {name}; deleting .part"
                )
                try:
                    part_path.unlink(missing_ok=True)
                except Exception:
                    pass
                self.bridge.transfer_finished.emit(file_id, False, str(exc))
                self._offer_decisions.pop(file_id, None)
                raise

            except Exception as exc:
                self.bridge.log.emit(
                    f"Receive failed: {exc} "
                    f"(kept {part_path.name} for resume)"
                )
                self.bridge.transfer_finished.emit(file_id, False, str(exc))
                raise

            finally:
                keepalive_stop.set()
                keepalive_task.cancel()
                io_pool.shutdown(wait=False)
                hash_pool.shutdown(wait=False)
                self._clear_cancel(file_id)


# ---------------------------------------------------------------------------
# Speed tracker
# ---------------------------------------------------------------------------

class SpeedTracker:
    def __init__(self, window: float = 3.0):
        self.window = window
        self.samples: deque = deque()

    def reset(self) -> None:
        self.samples.clear()

    def update(self, total_bytes: int) -> None:
        now = time.monotonic()
        self.samples.append((now, total_bytes))
        cutoff = now - self.window
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def speed(self) -> float:
        if len(self.samples) < 2:
            return 0.0
        t0, b0 = self.samples[0]
        t1, b1 = self.samples[-1]
        dt = t1 - t0
        return (b1 - b0) / dt if dt > 0 else 0.0


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

SELECTABLE = (
    Qt.TextInteractionFlag.TextSelectableByMouse
    | Qt.TextInteractionFlag.TextSelectableByKeyboard
    | Qt.TextInteractionFlag.LinksAccessibleByMouse
)


class SelectableLabels(QObject):
    """App-wide filter: every QLabel (dialogs included) becomes selectable.

    Qt labels and message boxes are not selectable by default, which is why
    highlighting and copying text did nothing.
    """

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Show and isinstance(obj, QLabel):
            if not obj.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse:
                obj.setTextInteractionFlags(SELECTABLE)
        return False


def copy_text(text: str) -> None:
    QGuiApplication.clipboard().setText(text)


ROLE_ID = Qt.ItemDataRole.UserRole
ROLE_FP = Qt.ItemDataRole.UserRole + 1


class PeerList(QListWidget):
    """Peer list with Ctrl+C and a context menu for copying ID / fingerprint."""

    def keyPressEvent(self, event):
        item = self.currentItem()
        if item is not None and event.matches(QKeySequence.StandardKey.Copy):
            copy_text(item.text())
            return
        super().keyPressEvent(event)

    def contextMenuEvent(self, event):
        item = self.itemAt(event.pos())
        if item is None:
            return
        menu = QMenu(self)
        menu.addAction("Copy peer ID", lambda: copy_text(item.data(ROLE_ID)))
        menu.addAction("Copy full fingerprint", lambda: copy_text(item.data(ROLE_FP)))
        menu.addAction("Copy line", lambda: copy_text(item.text()))
        menu.exec(event.globalPos())


class MainWindow(QMainWindow):
    def __init__(self, identity: Identity, trust_store: TrustStore):
        super().__init__()
        self.identity = identity
        self.trust_store = trust_store
        self.bridge = Bridge()
        self.network = P2PNetwork(identity, trust_store, self.bridge)

        self.config = load_config()
        self._active_file_id: Optional[str] = None
        self._speed = SpeedTracker()

        self.setWindowTitle("P2PFS — Encrypted P2P File Sharing")
        self.resize(1020, 780)
        icon_path = resource_path("p2p.ico")
        if Path(icon_path).is_file():
            self.setWindowIcon(QIcon(icon_path))

        self._build_ui()
        self._connect_signals()
        # let the window paint before any network work starts
        QTimer.singleShot(0, self.network.start)

        saved = self.config.get("server")
        if saved:
            self.server_edit.setText(saved)
            QTimer.singleShot(0, self._connect_server)

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        ibox = QGroupBox("Identity")
        il = QVBoxLayout(ibox)
        il.addWidget(QLabel(f"Username: <b>{self.identity.username}</b>"))
        il.addWidget(QLabel(f"Fingerprint: {self.identity.fingerprint}"))
        il.addWidget(QLabel(f"Your ID: <code>{self.network.endpoint_name}</code>"))
        self.public_ip_label = QLabel("Public IP: looking up…")
        il.addWidget(self.public_ip_label)
        root.addWidget(ibox)

        sbox = QGroupBox("Relay server")
        sl = QHBoxLayout(sbox)
        self.server_edit = QLineEdit()
        self.server_edit.setPlaceholderText("your-tunnel.at.ply.gg:12345")
        self.server_btn = QPushButton("Connect")
        self.server_btn.clicked.connect(self._connect_server)
        self.server_edit.returnPressed.connect(self._connect_server)
        self.server_status = QLabel("Not connected")
        sl.addWidget(QLabel("Address:"))
        sl.addWidget(self.server_edit, 2)
        sl.addWidget(self.server_btn)
        sl.addWidget(self.server_status, 1)
        root.addWidget(sbox)

        pbox = QGroupBox("Online peers")
        pl = QVBoxLayout(pbox)
        self.peer_list = PeerList()
        self.peer_list.itemDoubleClicked.connect(self._select_peer)
        pl.addWidget(self.peer_list)
        root.addWidget(pbox, 1)

        sendbox = QGroupBox("Send file")
        sendl = QHBoxLayout(sendbox)
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("peer ID (or double-click a peer above)")
        self.send_btn = QPushButton("Choose file && send…")
        self.send_btn.clicked.connect(self._send_clicked)
        sendl.addWidget(QLabel("Peer:"))
        sendl.addWidget(self.target_edit, 1)
        sendl.addWidget(self.send_btn)
        root.addWidget(sendbox)

        self.transfer_box = QGroupBox("Active transfer")
        tl = QVBoxLayout(self.transfer_box)
        self.transfer_name = QLabel("—")
        self.transfer_bar = QProgressBar()
        self.transfer_bar.setRange(0, 1000)
        self.transfer_bar.setValue(0)
        self.transfer_status = QLabel("Idle")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_clicked)
        statrow = QHBoxLayout()
        statrow.addWidget(self.transfer_status, 1)
        statrow.addWidget(self.cancel_btn)
        tl.addWidget(self.transfer_name)
        tl.addWidget(self.transfer_bar)
        tl.addLayout(statrow)
        self.transfer_box.setVisible(False)
        root.addWidget(self.transfer_box)

        lbox = QGroupBox("Console log")
        ll = QVBoxLayout(lbox)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self.log_view.setMaximumBlockCount(6000)
        ll.addWidget(self.log_view)
        root.addWidget(lbox, 2)

        self.setStatusBar(QStatusBar())
        self.status_label = QLabel("Starting…")
        self.statusBar().addWidget(self.status_label, 1)

        # hidden containers never get a Show event until used
        for label in self.findChildren(QLabel):
            label.setTextInteractionFlags(SELECTABLE)

    def _connect_signals(self) -> None:
        self.bridge.log.connect(self._log)
        self.bridge.public_ip.connect(self._on_ip)
        self.bridge.peers.connect(self._on_peers)
        self.bridge.incoming_offer.connect(self._on_offer)
        self.bridge.trust_request.connect(self._on_trust)
        self.bridge.transfer_started.connect(self._on_transfer_started)
        self.bridge.transfer_progress.connect(self._on_transfer_progress)
        self.bridge.transfer_retrying.connect(self._on_transfer_retrying)
        self.bridge.transfer_finished.connect(self._on_transfer_finished)
        self.bridge.error.connect(self._on_error)

    def _log(self, msg: str) -> None:
        logging.getLogger("p2pfs.gui").info(msg)
        self.log_view.appendPlainText(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def _on_ip(self, ip, port, nat):
        ep = f"{ip}:{port}" if port else ip
        self.public_ip_label.setText(f"Public IP: <b>{ep}</b> &nbsp; NAT: {nat}")
        self.status_label.setText("Ready")

    def _on_peers(self, peers):
        self.peer_list.clear()
        for p in peers:
            item = QListWidgetItem(
                f"{p['username']}  ({p['id']})  fp:{p['fingerprint'][:12]}…"
            )
            item.setData(ROLE_ID, p["id"])
            item.setData(ROLE_FP, p["fingerprint"])
            item.setToolTip(f"Fingerprint: {p['fingerprint']}")
            self.peer_list.addItem(item)
        if self.server_status.text() in ("Connecting…", "Reconnecting…"):
            self.server_status.setText("Connected")

    def _select_peer(self, item):
        self.target_edit.setText(item.data(ROLE_ID))

    def _connect_server(self):
        addr = self.server_edit.text().strip()
        if ":" not in addr:
            QMessageBox.warning(self, "Invalid address", "Use host:port")
            return
        host, port_s = addr.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            QMessageBox.warning(self, "Invalid port", "Port must be a number")
            return
        self.config["server"] = addr
        save_config(self.config)
        self.server_status.setText("Connecting…")
        self.network.connect_server(host, port)
        self._log(f"Connecting to relay server {addr}...")

    def _send_clicked(self):
        target = self.target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing peer", "Select or enter a peer ID.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Select file", str(Path.home()), "All files (*)"
        )
        if not path:
            return
        self._log(f"Queued send: {path} -> {target}")
        self.network.send_file(target, path)

    def _cancel_clicked(self):
        if self._active_file_id:
            self.network.cancel_transfer(self._active_file_id)
            self.cancel_btn.setEnabled(False)
            self.transfer_status.setText("Cancelling…")

    def _on_offer(self, offer):
        name = offer.get("name", "file")
        sender = offer.get("sender", "unknown")
        size = int(offer.get("size", 0))
        fp = offer.get("sender_fingerprint", "")[:24]
        box = QMessageBox(self)
        box.setWindowTitle("Incoming file")
        box.setTextInteractionFlags(SELECTABLE)
        box.setText(
            f"<b>{sender}</b> wants to send you a file:<br><br>"
            f"<b>{name}</b><br>"
            f"Size: {human_bytes(size)}<br>"
            f"Fingerprint: {fp}…"
        )
        accept = box.addButton("Accept && Save As…", QMessageBox.AcceptRole)
        box.addButton("Decline", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is not accept:
            self.network.answer(offer["req"], (False, None))
            return
        suggested = str(Path.home() / name)
        save, _ = QFileDialog.getSaveFileName(
            self, "Save incoming file as", suggested, "All files (*)"
        )
        if not save:
            self.network.answer(offer["req"], (False, None))
            return
        self.network.answer(offer["req"], (True, save))

    def _on_trust(self, remote):
        fp = sha256_hex(b64d(remote["ed_public"]))
        changed = remote.get("key_changed", False)
        box = QMessageBox(self)
        box.setWindowTitle("Peer key changed!" if changed else "Trust this peer?")
        box.setIcon(QMessageBox.Critical if changed else QMessageBox.Warning)
        box.setTextInteractionFlags(SELECTABLE)
        if changed:
            box.setText(
                f"<b>{remote['username']}</b> is presenting a DIFFERENT key than "
                f"the one you pinned.<br>This can mean an impersonation attempt.<br><br>"
                f"New fingerprint:<br><code>{fp}</code><br><br>"
                "Only continue if you verified this new fingerprint out-of-band."
            )
            trust = box.addButton("Replace pinned key && trust", QMessageBox.AcceptRole)
            deny = box.addButton("Deny", QMessageBox.RejectRole)
            box.setDefaultButton(deny)
        else:
            box.setText(
                f"First contact with <b>{remote['username']}</b>.<br><br>"
                f"Fingerprint:<br><code>{fp}</code><br><br>"
                "Only trust if you have verified this fingerprint out-of-band."
            )
            trust = box.addButton("Trust && pin", QMessageBox.AcceptRole)
            box.addButton("Deny", QMessageBox.RejectRole)
        box.exec()
        self.network.answer(remote["req"], box.clickedButton() is trust)

    def _on_transfer_started(self, file_id, name):
        if self._active_file_id == file_id:
            # same transfer resumed - don't reset the bar
            return
        self._active_file_id = file_id
        self._speed.reset()
        self.transfer_name.setText(f"<b>{name}</b>")
        self.transfer_bar.setValue(0)
        self.transfer_status.setText("Starting…")
        self.transfer_box.setVisible(True)
        self.cancel_btn.setEnabled(True)

    def _on_transfer_progress(self, file_id, done, total):
        if file_id != self._active_file_id:
            return
        done = int(done)
        total = int(total)
        self._speed.update(done)
        speed = self._speed.speed()

        # never pass raw bytes to QProgressBar.setValue (int32 overflow)
        fraction = (done / total) if total > 0 else 0.0
        self.transfer_bar.setValue(int(fraction * 1000))
        pct = fraction * 100.0

        eta = ""
        if speed > 0 and total > done:
            eta = f" • ETA {human_eta((total - done) / speed)}"
        spd = human_bytes(speed) + "/s" if speed > 0 else "—"
        self.transfer_status.setText(
            f"{human_bytes(done)} / {human_bytes(total)} "
            f"({pct:.1f}%) • {spd}{eta}"
        )

    def _on_transfer_retrying(self, file_id, attempt, reason):
        if file_id != self._active_file_id:
            return
        self.transfer_status.setText(
            f"⟳ Reconnecting (attempt {attempt}) — {reason}"
        )
        self.cancel_btn.setEnabled(True)

    def _on_transfer_finished(self, file_id, ok, detail):
        if file_id != self._active_file_id:
            return
        self.cancel_btn.setEnabled(False)
        if ok:
            self.transfer_status.setText(f"✓ Complete: {detail}")
            self.transfer_bar.setValue(1000)
            box = QMessageBox(self)
            box.setWindowTitle("Transfer complete")
            box.setIcon(QMessageBox.Information)
            box.setTextInteractionFlags(SELECTABLE)
            box.setText(f"Saved and verified:\n\n{detail}")
            box.exec()
        else:
            self.transfer_status.setText(f"✗ {detail}")
        self._active_file_id = None

    def _on_error(self, msg):
        self._log(f"ERROR: {msg}")
        if "Server connect failed" in msg or "control loop ended" in msg:
            self.server_status.setText("Reconnecting…")

    def closeEvent(self, event):
        self.network.stop()
        if self.network.server:
            self.network.server.close()
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    _setup_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("P2PFS")
    label_filter = SelectableLabels(app)
    app.installEventFilter(label_filter)

    icon_path = resource_path("p2p.ico")
    if Path(icon_path).is_file():
        app.setWindowIcon(QIcon(icon_path))

    if IDENTITY_FILE.exists():
        identity = Identity.load_or_create(IDENTITY_FILE, "")
    else:
        name, ok = QInputDialog.getText(None, "P2PFS username", "Choose a username:")
        if not ok or not name.strip():
            raise SystemExit("No username")
        identity = Identity.load_or_create(IDENTITY_FILE, name.strip())

    window = MainWindow(identity, TrustStore(TRUST_FILE))
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

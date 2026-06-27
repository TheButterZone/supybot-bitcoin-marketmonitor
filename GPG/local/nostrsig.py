import hashlib
import json
import re
import socket
import ssl
import os
import struct
import base64
import select
import time
from urllib.parse import urlparse

from ecdsa.curves import SECP256k1
from ecdsa.util import string_to_number
from ecdsa.ellipticcurve import Point


# =========================
# RELAY STATE / ANTI-SPAM
# =========================

RELAY_STATS = {}
RELAY_BACKOFF = {}

CONNECT_TIMEOUT = 2
READ_TIMEOUT = 2
MAX_RELAY_ATTEMPTS = 6


# =========================
# BECH32 CONSTANTS
# =========================

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_MAP = {c: i for i, c in enumerate(CHARSET)}
VALID_HRPS = {"npub", "note"}


# =========================
# BECH32 DECODER
# =========================

def decode_bech32_to_hex(bech32_str):
    s = bech32_str.strip()

    if re.match(r'^[0-9a-fA-F]{64}$', s):
        return s.lower()

    if s != s.lower() and s != s.upper():
        raise ValueError("Mixed-case Bech32 strings are invalid.")

    s = s.lower()

    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or len(s) > 90:
        raise ValueError("Invalid Bech32 formatting or length constraints.")

    hrp = s[:pos]
    data_part = s[pos + 1:]

    if hrp not in VALID_HRPS:
        raise ValueError("Unsupported HRP")

    if any(c not in CHARSET_MAP for c in data_part):
        raise ValueError("Invalid Bech32 characters")

    data = [CHARSET_MAP[c] for c in data_part]

    if len(data) != 58:
        raise ValueError("Invalid payload size")

    def polymod(values):
        g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            chk &= 0xffffffff
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= g[i]
        return chk

    hrp_expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

    if polymod(hrp_expanded + data) != 1:
        raise ValueError("Bad checksum")

    payload = data[:-6]

    acc = 0
    bits = 0
    out = []

    for v in payload:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xff)

    if bits >= 5 or ((acc << (8 - bits)) & 0xff):
        raise ValueError("Bad padding")

    hex_out = bytes(out).hex()
    if len(hex_out) != 64:
        raise ValueError("Bad key length")

    return hex_out


# =========================
# RELAY MANAGEMENT
# =========================

def relay_available(relay):
    return time.time() > RELAY_BACKOFF.get(relay, 0)


def mark_failure(relay):
    s = RELAY_STATS.setdefault(relay, {"ok": 0, "fail": 0, "latency": 0.0})
    s["fail"] += 1
    RELAY_BACKOFF[relay] = time.time() + min(60, 2 ** s["fail"])


def mark_success(relay, latency):
    s = RELAY_STATS.setdefault(relay, {"ok": 0, "fail": 0, "latency": 0.0})
    s["ok"] += 1
    s["latency"] += latency


def relay_score(relay):
    s = RELAY_STATS.get(relay)
    if not s:
        return 1.0
    if s["ok"] == 0:
        return 5.0 + s["fail"]
    return (s["latency"] / s["ok"]) + (s["fail"] * 2)


def sort_relays(relays):
    relays = list(set(relays))
    return sorted([r for r in relays if relay_available(r)], key=relay_score)


# =========================
# RFC-SAFE WEBSOCKET LAYER
# =========================

def ws_handshake(sock, host, path="/"):
    key = base64.b64encode(os.urandom(16)).decode()

    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )

    sock.sendall(req.encode())

    resp = sock.recv(4096)
    if b"101" not in resp:
        raise Exception("WebSocket handshake failed")


def ws_send(sock, data):
    payload = json.dumps(data).encode()
    n = len(payload)

    frame = bytearray([0x81])

    if n < 126:
        frame.append(0x80 | n)
    elif n < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack(">H", n))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack(">Q", n))

    mask = os.urandom(4)
    frame.extend(mask)
    frame.extend(payload[i] ^ mask[i % 4] for i in range(n))

    sock.sendall(frame)


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def ws_read(sock):
    try:
        hdr = _recv_exact(sock, 2)
        if not hdr:
            return None

        b1, b2 = hdr
        length = b2 & 127

        if length == 126:
            length = struct.unpack(">H", _recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", _recv_exact(sock, 8))[0]

        payload = _recv_exact(sock, length)
        if not payload:
            return None

        return json.loads(payload.decode(errors="ignore"))

    except:
        return None


# =========================
# FETCH EVENT (FIXED + SAFE)
# =========================

def fetch_event_by_id(event_id_hex):
    relays = sort_relays([
        "wss://relay.ditto.pub",
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net",
        "wss://relay.snort.social",
        "wss://relay.nostr.band"
    ])[:MAX_RELAY_ATTEMPTS]

    req = ["REQ", "gribble", {"ids": [event_id_hex]}]

    sockets = []
    relay_map = {}
    start_times = {}

    for relay in relays:
        try:
            u = urlparse(relay)
            host = u.hostname

            sock = socket.create_connection((host, 443), timeout=CONNECT_TIMEOUT)
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            sock.settimeout(READ_TIMEOUT)

            ws_handshake(sock, host, "/")
            ws_send(sock, req)

            sockets.append(sock)
            relay_map[sock] = relay
            start_times[sock] = time.time()

        except:
            mark_failure(relay)

    if not sockets:
        return None

    try:
        for _ in range(12):
            readable, _, _ = select.select(sockets, [], [], 2)

            for s in readable:
                msg = ws_read(s)
                relay = relay_map.get(s)

                if isinstance(msg, list):
                    if msg[0] == "EVENT":
                        mark_success(relay, time.time() - start_times[s])
                        return msg[2]

                    if msg[0] == "EOSE":
                        sockets.remove(s)
                        s.close()

            if not sockets:
                break

    finally:
        for s in sockets:
            try:
                s.close()
            except:
                pass

    return None


# =========================
# SIGNATURE VERIFICATION
# =========================

def verify_nostr_event_json(event_json):
    try:
        if not re.match(r'^[0-9a-fA-F]{64}$', event_json.get('id', '')):
            return False
        if not re.match(r'^[0-9a-fA-F]{64}$', event_json.get('pubkey', '')):
            return False
        if not re.match(r'^[0-9a-fA-F]{128}$', event_json.get('sig', '')):
            return False

        serialized = json.dumps([
            0,
            event_json['pubkey'],
            event_json['created_at'],
            event_json['kind'],
            event_json['tags'],
            event_json['content']
        ], separators=(',', ':'))

        if hashlib.sha256(serialized.encode()).hexdigest() != event_json['id']:
            return False

        curve = SECP256k1.curve
        generator = SECP256k1.generator
        order = SECP256k1.order
        field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

        px = int(event_json['pubkey'], 16)
        r = int(event_json['sig'][:64], 16)
        s = int(event_json['sig'][64:], 16)

        if px >= field or r >= field or s >= order or r == 0 or s == 0 or px == 0:
            return False

        y2 = (pow(px, 3, field) + 7) % field
        py = pow(y2, (field + 1) // 4, field)

        if pow(py, 2, field) != y2:
            return False

        if py % 2:
            py = field - py

        P = Point(curve, px, py)

        e = hashlib.sha256(
            b"BIP0340/challenge" +
            b"BIP0340/challenge" +
            bytes.fromhex(event_json['sig'][:64]) +
            bytes.fromhex(event_json['pubkey']) +
            bytes.fromhex(event_json['id'])
        ).digest()

        e = string_to_number(e) % order

        return (s * generator) == (Point(curve, r, py) + e * P)

    except:
        return False

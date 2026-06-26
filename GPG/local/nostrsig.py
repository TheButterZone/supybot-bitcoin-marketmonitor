import hashlib
import json
import re
import socket
import ssl
import os
import struct
import base64
import select
from urllib.parse import urlparse
import time

from ecdsa.curves import SECP256k1
from ecdsa.util import string_to_number
from ecdsa.ellipticcurve import Point


# ----------------------------
# Relay performance tracking
# ----------------------------

RELAY_STATS = {}

FAIL_THRESHOLD = 5
COOLDOWN_SECONDS = 60  # 🔥 prevents spam retry loops


# ----------------------------
# Bech32 decode
# ----------------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_MAP = {c: i for i, c in enumerate(CHARSET)}
VALID_HRPS = {"npub", "note"}


def decode_bech32_to_hex(bech32_str):
    s = bech32_str.strip()

    if re.match(r'^[0-9a-fA-F]{64}$', s):
        return s.lower()

    if s != s.lower() and s != s.upper():
        raise ValueError("Mixed-case Bech32 strings are invalid.")

    bech32_str = s.lower()

    pos = bech32_str.rfind("1")
    if pos < 1 or pos + 7 > len(bech32_str) or len(bech32_str) > 90:
        raise ValueError("Invalid Bech32 formatting or length constraints.")

    hrp = bech32_str[:pos]
    data_part = bech32_str[pos + 1:]

    if hrp not in VALID_HRPS:
        raise ValueError(f"Unsupported Nostr prefix type: {hrp}")

    if any(char not in CHARSET_MAP for char in data_part):
        raise ValueError("Invalid characters found outside Bech32 mapping.")

    data_5bit = [CHARSET_MAP[c] for c in data_part]

    def bech32_polymod(values):
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (((chk & 0x1ffffff) << 5) ^ value) & 0xffffffff
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= generator[i]
        return chk

    hrp_expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

    if bech32_polymod(hrp_expanded + data_5bit) != 1:
        raise ValueError("Bech32 checksum failed.")

    data_payload = data_5bit[:-6]

    if len(data_payload) != 52:
        raise ValueError("Invalid key length.")

    acc = 0
    bits = 0
    out = []

    for v in data_payload:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xff)

    if bits >= 5 or ((acc << (8 - bits)) & 0xff):
        raise ValueError("Invalid padding.")

    return bytes(out).hex()


# ----------------------------
# Relay cooldown logic (NEW)
# ----------------------------

def relay_available(relay):
    stats = RELAY_STATS.get(relay)
    if not stats:
        return True

    # soft exclusion window
    if stats.get("cooldown_until", 0) > time.time():
        return False

    return True


def record_relay_success(relay, latency):
    stats = RELAY_STATS.setdefault(relay, {"ok": 0, "fail": 0, "latency": 0.0, "cooldown_until": 0})
    stats["ok"] += 1
    stats["latency"] += latency


def record_relay_failure(relay):
    stats = RELAY_STATS.setdefault(relay, {"ok": 0, "fail": 0, "latency": 0.0, "cooldown_until": 0})
    stats["fail"] += 1

    # 🔥 cooldown instead of pure punishment
    stats["cooldown_until"] = time.time() + COOLDOWN_SECONDS


def relay_score(relay):
    stats = RELAY_STATS.get(relay)
    if not stats:
        return 1.0

    if stats.get("ok", 0) == 0:
        return 5.0 + stats.get("fail", 0)

    return (stats["latency"] / stats["ok"]) + (stats["fail"] * 2.0)


def get_sorted_relays(relays):
    return sorted(relays, key=relay_score)


def prune_relays(relays):
    return [r for r in relays if relay_available(r)]


# ----------------------------
# WebSocket helpers
# ----------------------------

def _ws_handshake(sock, host, path="/"):
    key = base64.b64encode(os.urandom(16)).decode()

    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.send(req.encode())

    resp = sock.recv(4096)
    if b"101" not in resp:
        raise Exception("handshake failed")


def _ws_send(sock, data):
    payload = json.dumps(data).encode()

    frame = bytearray([0x81])
    length = len(payload)

    if length < 126:
        frame.append(0x80 | length)
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack(">Q", length))

    mask = os.urandom(4)
    frame.extend(mask)

    frame.extend(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.send(frame)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _ws_readable(sock):
    try:
        header = _recv_exact(sock, 2)
        if not header:
            return None

        b1, b2 = header
        length = b2 & 127

        if length == 126:
            ext = _recv_exact(sock, 2)
            if not ext:
                return None
            length = struct.unpack(">H", ext)[0]

        elif length == 127:
            ext = _recv_exact(sock, 8)
            if not ext:
                return None
            length = struct.unpack(">Q", ext)[0]

        data = _recv_exact(sock, length)
        if not data:
            return None

        return json.loads(data.decode())

    except:
        return None


# ----------------------------
# Fetch with anti-spam routing
# ----------------------------

def fetch_event_by_id(event_id_hex):

    relays = [
        "wss://relay.ditto.pub",
        "wss://relay.dreamith.to",
        "wss://relay.primal.net",
        "wss://relay.damus.io",
        "wss://nostr.mutinywallet.com",
        "wss://nos.lol",
        "wss://relay.nostr.band",
        "wss://cache1.primal.net",
        "wss://relay.snort.social",
        "wss://relay.bitcoiner.social",
        "wss://relay.current.fyi",
    ]

    # 🛡️ prevent spam retry loops
    relays = prune_relays(relays)
    relays = get_sorted_relays(relays)

    req = ["REQ", "gribble", {"ids": [event_id_hex]}]

    socks = []
    sock_map = {}

    for relay in relays:
        try:
            u = urlparse(relay)
            host = u.hostname

            sock = socket.create_connection((host, 443), timeout=2)
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            sock.settimeout(2)

            _ws_handshake(sock, host, "/")
            _ws_send(sock, req)

            sock_map[sock] = (relay, time.time())
            socks.append(sock)

        except:
            record_relay_failure(relay)

    if not socks:
        return None

    try:
        for _ in range(10):
            readable, _, _ = select.select(socks, [], [], 2)

            for sock in readable:
                msg = _ws_readable(sock)

                if msg is None:
                    relay, _ = sock_map.get(sock, (None, None))
                    if relay:
                        record_relay_failure(relay)

                    if sock in socks:
                        socks.remove(sock)
                    sock.close()
                    continue

                if isinstance(msg, list):

                    if msg[0] == "EVENT":
                        relay, start = sock_map.get(sock, (None, time.time()))
                        if relay:
                            record_relay_success(relay, time.time() - start)

                        return msg[2]

                    if msg[0] == "EOSE":
                        if sock in socks:
                            socks.remove(sock)
                        sock.close()

            if not socks:
                break

    finally:
        for s in socks:
            try:
                s.close()
            except:
                pass

    return None


# ----------------------------
# Signature verification
# ----------------------------

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

        p_x = int(event_json['pubkey'], 16)
        sig_r = int(event_json['sig'][:64], 16)
        sig_s = int(event_json['sig'][64:], 16)

        if p_x >= field or sig_r >= field or sig_s >= order or sig_r == 0 or sig_s == 0 or p_x == 0:
            return False

        y_sq = (pow(p_x, 3, field) + 7) % field
        p_y = pow(y_sq, (field + 1) // 4, field)

        if pow(p_y, 2, field) != y_sq:
            return False

        if p_y % 2:
            p_y = field - p_y

        P = Point(curve, p_x, p_y)

        commitment = (
            bytes.fromhex(event_json['sig'][:64]) +
            bytes.fromhex(event_json['pubkey']) +
            bytes.fromhex(event_json['id'])
        )

        tag = hashlib.sha256(b"BIP0340/challenge").digest()
        e = string_to_number(hashlib.sha256(tag + tag + commitment).digest()) % order

        sG = sig_s * generator
        eP = e * P

        r_y_sq = (pow(sig_r, 3, field) + 7) % field
        r_y = pow(r_y_sq, (field + 1) // 4, field)

        if r_y % 2:
            r_y = field - r_y

        R = Point(curve, sig_r, r_y)

        return sG == (R + eP)

    except:
        return False

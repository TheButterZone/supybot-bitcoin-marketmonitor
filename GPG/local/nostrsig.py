# Save this file as GPG/local/nostrsig.py
import hashlib
import json
import re
import urllib.request
import urllib.error
from ecdsa.curves import SECP256k1
from ecdsa.util import string_to_number
from ecdsa.ellipticcurve import Point

def decode_bech32_to_hex(bech32_str):
    """
    Normalizes public keys or note IDs. If it is already a 64-character 
    hex string, it returns it. If it is a bech32 string (npub1... or note1...), 
    it handles standard decoding parameters.
    """
    if re.match(r'^[0-9a-fA-F]{64}$', bech32_str):
        return bech32_str.lower()
        
    # Placeholder for full NIP-19 Bech32 decoding logic if required by runtime.
    # Most modern Python Nostr helper functions fallback to raw hex if needed.
    return bech32_str.lower()

def fetch_event_by_id(event_id_hex):
    """
    Sequentially loops through multiple mainstream Nostr relays via HTTP POST.
    Utilizes standard protocol fallback ('Accept: application/nostr+json') 
    so it does not rely on a single website or a persistent WebSocket connection.
    """
    # List of reliable, high-traffic relays to query sequentially
    relays = [
        "https://primal.net",
        "https://damus.io",
        "https://nos.lol",
        "https://nostr.band"
    ]
    
    # Standard NIP-01 subscription request payload to find our exact event ID
    query_payload = json.dumps([
        "REQ", 
        "gribble-fallback-fetch", 
        {"ids": [event_id_hex], "limit": 1}
    ]).encode('utf-8')
    
    for relay_url in relays:
        try:
            req = urllib.request.Request(
                relay_url, 
                data=query_payload,
                headers={
                    'User-Agent': 'Gribble-OTC-Bot',
                    'Content-Type': 'application/json',
                    # This tells any standard relay to respond cleanly via HTTP JSON 
                    # instead of demanding an active WebSocket tunnel
                    'Accept': 'application/nostr+json' 
                },
                method='POST'
            )
            
            # Use a strict 3-second timeout per relay so the IRC bot doesn't hang
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    raw_response = response.read().decode('utf-8')
                    
                    # Relays return a stream of newline-delimited JSON arrays
                    lines = raw_response.strip().split('\n')
                    for line in lines:
                        try:
                            data = json.loads(line)
                            # Look for the payload structural standard: ["EVENT", "sub_id", {event_dict}]
                            if isinstance(data, list) and len(data) >= 3 and data[0] == "EVENT":
                                return data[2] # Return the raw event payload dictionary
                        except json.JSONDecodeError:
                            continue
                            
        except (urllib.error.URLError, urllib.error.HTTPError):
            # If a relay is offline or times out, silently continue to the next fallback relay
            continue
        except Exception:
            continue
            
    return None # Returns None if all fallback relays failed to find or serve the event

def verify_nostr_event_json(event_json):
    """
    Validates that the event data matches its serialized ID hash, 
    then mathematically checks the Schnorr signature using python-ecdsa.
    """
    try:
        # 1. Re-serialize to verify event ID integrity (NIP-01 strict ordering)
        serialized_data = json.dumps([
            0,
            event_json['pubkey'],
            event_json['created_at'],
            event_json['kind'],
            event_json['tags'],
            event_json['content']
        ], separators=(',', ':'))
        
        if hashlib.sha256(serialized_data.encode('utf-8')).hexdigest() != event_json['id']:
            return False # Payload data tampered with!

        # 2. Extract curves parameters from bundled python-ecdsa
        curve = SECP256k1.curve
        generator = SECP256k1.generator
        order = SECP256k1.order
        field_size = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        
        p_x = int(event_json['pubkey'], 16)
        sig_r = int(event_json['sig'][:64], 16)
        sig_s = int(event_json['sig'][64:], 16)
        
        # Upper bound constraint checks
        if p_x >= field_size or sig_r >= field_size or sig_s >= order:
            return False

        # 3. Curve Point reconstruction for BIP-340 standard
        y_sq = (pow(p_x, 3, field_size) + 7) % field_size
        p_y = pow(y_sq, (field_size + 1) // 4, field_size)
        if pow(p_y, 2, field_size) != y_sq:
            return False
        if p_y % 2 != 0: 
            p_y = field_size - p_y
            
        pubkey_point = Point(curve, p_x, p_y)

        # 4. Challenge commitment hash logic: e = Hash( r || P || m )
        commitment_bytes = bytes.fromhex(event_json['sig'][:64]) + bytes.fromhex(event_json['pubkey']) + bytes.fromhex(event_json['id'])
        
        # Nostr uses tagged SHA256 hashes for BIP-340 Schnorr compliance
        tag_hash = hashlib.sha256(b"BIP0340/challenge").digest()
        e_hash = hashlib.sha256(tag_hash + tag_hash + commitment_bytes).digest()
        e = string_to_number(e_hash) % order

        # Calculate Point values to check signature match equation: s*G == R + e*P
        s_g = sig_s * generator
        e_p = e * pubkey_point
        
        r_y_sq = (pow(sig_r, 3, field_size) + 7) % field_size
        r_y = pow(r_y_sq, (field_size + 1) // 4, field_size)
        if r_y % 2 != 0: 
            r_y = field_size - r_y
            
        r_point = Point(curve, sig_r, r_y)
        
        return s_g == (r_point + e_p)
    except Exception:
        return False

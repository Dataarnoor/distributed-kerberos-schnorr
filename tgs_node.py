"""
tgs_node.py
Ticket Granting Server (TGS) node for Kerberos multi-signature system.

Usage:
    python tgs_node.py <node_id>      # node_id in {1, 2, 3}
"""

import sys
import json
import os
import socket
import time
import threading

from crypto_utils import (
    schnorr_sign,
    schnorr_verify,
    verify_multi_signatures,
    aes_encrypt,
    aes_decrypt,
    canonical_message,
    send_message,
    recv_message,
    bytes_to_hex,
    hex_to_bytes,
    hex_to_int,
    int_to_hex,
)

KEYS_DIR = "keys"
HOST = "127.0.0.1"
PORT_MAP = {1: 5011, 2: 5012, 3: 5013}
SERVICE_TICKET_LIFETIME = 600
TIMESTAMP_TOLERANCE = 300
CURRENT_KEY_VERSION = 1


def load_config(node_id: int) -> dict:
    auth_id = f"TGS{node_id}"
    priv_path = os.path.join(KEYS_DIR, f"tgs{node_id}_private.json")
    with open(priv_path) as f:
        priv = json.load(f)
    pub_path = os.path.join(KEYS_DIR, "public_keys.json")
    with open(pub_path) as f:
        pub = json.load(f)
    shared_path = os.path.join(KEYS_DIR, "shared_keys.json")
    with open(shared_path) as f:
        shared = json.load(f)
    as_public_keys = {
        aid: hex_to_int(info["public_key"])
        for aid, info in pub.items()
        if aid.startswith("AS")
    }
    return {
        "authority_id": auth_id,
        "private_key": hex_to_int(priv["private_key"]),
        "public_key": hex_to_int(priv["public_key"]),
        "key_version": priv["key_version"],
        "as_public_keys": as_public_keys,
        "tgt_key": hex_to_bytes(shared["tgt_encryption_key"]),
        "service_keys": {k: hex_to_bytes(v) for k, v in shared["service_keys"].items()},
    }


def normalise_payload(payload: dict) -> dict:
    """
    Normalise a ticket payload by round-tripping through JSON so that
    float timestamps have identical representation on client and server.
    """
    return json.loads(json.dumps(payload))


def validate_tgt(tgt: dict, cfg: dict) -> tuple:
    auth_id = cfg["authority_id"]

    if "payload" not in tgt or "signatures" not in tgt or "encrypted_tgt" not in tgt:
        return False, "Malformed TGT: missing required fields", None

    try:
        enc_tgt = hex_to_bytes(tgt["encrypted_tgt"])
        decrypted_bytes = aes_decrypt(cfg["tgt_key"], enc_tgt)
        authoritative_payload = json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        return False, f"TGT decryption failed: {e}", None

    if canonical_message(tgt["payload"]) != canonical_message(authoritative_payload):
        return False, "TGT payload tampered (does not match encrypted version)", None

    payload = authoritative_payload

    if payload.get("key_version", 0) != CURRENT_KEY_VERSION:
        return False, f"Outdated key version: {payload.get('key_version')}", None

    issue_ts = payload.get("issue_timestamp", 0)
    lifetime = payload.get("lifetime", 0)
    if time.time() > issue_ts + lifetime:
        return False, "TGT has expired", None

    m = canonical_message(payload)
    sigs = []
    for sig in tgt["signatures"]:
        sigs.append({
            "authority_id": sig["authority_id"],
            "R": hex_to_int(sig["R"]),
            "s": hex_to_int(sig["s"]),
        })

    if not verify_multi_signatures(m, sigs, cfg["as_public_keys"], threshold=2):
        return False, "TGT does not have enough valid AS signatures (need >= 2)", None

    print(f"  [{auth_id}] TGT validated for '{payload.get('client_id')}'")
    return True, "OK", payload


def handle_tgs_request(request: dict, cfg: dict) -> dict:
    auth_id = cfg["authority_id"]

    for field in ("tgt", "service_id", "svc_proposal", "authenticator"):
        if field not in request:
            return {"type": "TGS_ERR", "error": f"Missing field: {field}"}

    tgt = request["tgt"]
    service_id = request["service_id"]
    svc_proposal = request["svc_proposal"]

    ok, err, tgt_payload = validate_tgt(tgt, cfg)
    if not ok:
        return {"type": "TGS_ERR", "error": err}

    client_id = tgt_payload["client_id"]
    tgt_session_key = hex_to_bytes(tgt_payload["session_key"])

    try:
        auth_bytes = hex_to_bytes(request["authenticator"])
        auth_data = json.loads(aes_decrypt(tgt_session_key, auth_bytes).decode())
        now = time.time()
        if abs(auth_data.get("timestamp", 0) - now) > TIMESTAMP_TOLERANCE:
            return {"type": "TGS_ERR", "error": "Authenticator timestamp invalid"}
        if auth_data.get("client_id") != client_id:
            return {"type": "TGS_ERR", "error": "Authenticator client_id mismatch"}
    except Exception as e:
        return {"type": "TGS_ERR", "error": f"Authenticator decryption failed: {e}"}

    if svc_proposal.get("client_id") != client_id:
        return {"type": "TGS_ERR", "error": "Service ticket client_id mismatch"}
    if svc_proposal.get("service_id") != service_id:
        return {"type": "TGS_ERR", "error": "Service ticket service_id mismatch"}
    if "service_session_key" not in svc_proposal or len(svc_proposal["service_session_key"]) != 64:
        return {"type": "TGS_ERR", "error": "Invalid service session key"}

    # Normalise payload so canonical_message produces identical bytes to client
    svc_proposal = normalise_payload(svc_proposal)
    m = canonical_message(svc_proposal)
    R, s = schnorr_sign(m, cfg["private_key"], auth_id)

    if service_id in cfg["service_keys"]:
        enc_svc_ticket = aes_encrypt(cfg["service_keys"][service_id], m)
        enc_svc_ticket_hex = bytes_to_hex(enc_svc_ticket)
    else:
        enc_svc_ticket_hex = None

    print(f"  [{auth_id}] Signed service ticket for '{client_id}' -> '{service_id}'")

    return {
        "type": "TGS_REP",
        "authority_id": auth_id,
        "key_version": cfg["key_version"],
        "signature": {
            "R": int_to_hex(R),
            "s": int_to_hex(s),
            "authority_id": auth_id,
        },
        "encrypted_service_ticket": enc_svc_ticket_hex,
    }


def handle_client(conn, addr, cfg: dict):
    try:
        request = recv_message(conn)
        if request is None:
            return
        if request.get("type") != "TGS_REQ":
            send_message(conn, {"type": "ERR", "error": "Unknown message type"})
            return
        response = handle_tgs_request(request, cfg)
        send_message(conn, response)
    except Exception as e:
        print(f"  [{cfg['authority_id']}] Error: {e}")
        try:
            send_message(conn, {"type": "TGS_ERR", "error": str(e)})
        except Exception:
            pass
    finally:
        conn.close()


def run_server(node_id: int):
    cfg = load_config(node_id)
    auth_id = cfg["authority_id"]
    port = PORT_MAP[node_id]

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(10)

    print(f"[{auth_id}] Listening on {HOST}:{port}")
    print(f"[{auth_id}] Public key: {int_to_hex(cfg['public_key'])[:32]}...")

    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, cfg), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print(f"\n[{auth_id}] Shutting down")
            break
        except Exception as e:
            print(f"[{auth_id}] Accept error: {e}")

    srv.close()


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("1", "2", "3"):
        print("Usage: python tgs_node.py <1|2|3>")
        sys.exit(1)
    run_server(int(sys.argv[1]))
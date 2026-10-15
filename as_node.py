"""
as_node.py
Authentication Server (AS) node for Kerberos multi-signature system.
"""

import sys
import json
import os
import socket
import time
import threading
import traceback

from crypto_utils import (
    schnorr_sign,
    aes_encrypt,
    aes_decrypt,
    canonical_message,
    send_message,
    recv_message,
    sha256_hex,
    bytes_to_hex,
    hex_to_bytes,
    hex_to_int,
    int_to_hex,
    secure_random_bytes,
)

KEYS_DIR = "keys"
HOST = "127.0.0.1"
PORT_MAP = {1: 5001, 2: 5002, 3: 5003}
TICKET_LIFETIME = 3600
TIMESTAMP_TOLERANCE = 300


def load_config(node_id: int) -> dict:
    auth_id = f"AS{node_id}"
    priv_path = os.path.join(KEYS_DIR, f"as{node_id}_private.json")
    with open(priv_path) as f:
        priv = json.load(f)
    users_path = os.path.join(KEYS_DIR, "users.json")
    with open(users_path) as f:
        users = json.load(f)
    shared_path = os.path.join(KEYS_DIR, "shared_keys.json")
    with open(shared_path) as f:
        shared = json.load(f)
    return {
        "authority_id": auth_id,
        "private_key": hex_to_int(priv["private_key"]),
        "public_key": hex_to_int(priv["public_key"]),
        "key_version": priv["key_version"],
        "users": users,
        "tgt_key": hex_to_bytes(shared["tgt_encryption_key"]),
    }


def verify_client_auth(client_id: str, auth_token: str, timestamp: float, users: dict) -> bool:
    if client_id not in users:
        return False
    stored_hash = users[client_id]["password_hash"]
    ts_str = str(int(timestamp))
    expected = sha256_hex((stored_hash + ts_str + client_id).encode())
    return expected == auth_token


def normalise_payload(payload: dict) -> dict:
    return json.loads(json.dumps(payload))


def handle_as_request(request: dict, cfg: dict) -> dict:
    auth_id = cfg["authority_id"]

    for field in ("client_id", "timestamp", "auth_token", "tgt_proposal"):
        if field not in request:
            return {"type": "AS_ERR", "error": f"Missing field: {field}"}

    client_id = request["client_id"]
    timestamp = request["timestamp"]
    auth_token = request["auth_token"]
    tgt_proposal = request["tgt_proposal"]

    now = time.time()
    if abs(now - timestamp) > TIMESTAMP_TOLERANCE:
        return {"type": "AS_ERR", "error": "Timestamp too old (replay protection)"}

    if not verify_client_auth(client_id, auth_token, timestamp, cfg["users"]):
        return {"type": "AS_ERR", "error": "Authentication failed: invalid credentials"}

    if tgt_proposal.get("client_id") != client_id:
        return {"type": "AS_ERR", "error": "TGT client_id mismatch"}
    if tgt_proposal.get("service") != "TGS":
        return {"type": "AS_ERR", "error": "TGT service must be TGS"}
    if abs(tgt_proposal.get("issue_timestamp", 0) - now) > TIMESTAMP_TOLERANCE:
        return {"type": "AS_ERR", "error": "TGT timestamp invalid"}
    if "session_key" not in tgt_proposal or len(tgt_proposal["session_key"]) != 64:
        return {"type": "AS_ERR", "error": "Invalid session key in TGT proposal"}

    tgt_proposal = normalise_payload(tgt_proposal)
    m = canonical_message(tgt_proposal)
    R, s = schnorr_sign(m, cfg["private_key"], auth_id)

    encrypted_tgt = aes_encrypt(cfg["tgt_key"], m)

    user_aes_key = hex_to_bytes(cfg["users"][client_id]["aes_key"])
    confirmation = {
        "session_key": tgt_proposal["session_key"],
        "timestamp": now,
        "authority_id": auth_id,
    }
    enc_conf = aes_encrypt(user_aes_key, json.dumps(confirmation).encode())

    print(f"  [{auth_id}] Signed TGT for '{client_id}' | R={int_to_hex(R)[:16]}...")

    return {
        "type": "AS_REP",
        "authority_id": auth_id,
        "key_version": cfg["key_version"],
        "signature": {
            "R": int_to_hex(R),
            "s": int_to_hex(s),
            "authority_id": auth_id,
        },
        "encrypted_tgt": bytes_to_hex(encrypted_tgt),
        "encrypted_confirmation": bytes_to_hex(enc_conf),
    }


def handle_client(conn, addr, cfg: dict):
    print(f"  [{cfg['authority_id']}] Got connection from {addr}")
    try:
        request = recv_message(conn)
        if request is None:
            return
        if request.get("type") != "AS_REQ":
            send_message(conn, {"type": "ERR", "error": "Unknown message type"})
            return
        response = handle_as_request(request, cfg)
        send_message(conn, response)
    except Exception as e:
        traceback.print_exc()
        try:
            send_message(conn, {"type": "AS_ERR", "error": str(e)})
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
        print("Usage: python as_node.py <1|2|3>")
        sys.exit(1)
    run_server(int(sys.argv[1]))
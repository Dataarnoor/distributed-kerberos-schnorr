"""
service_server.py
Service Server for Kerberos multi-signature system.

Usage:
    python service_server.py <service_id>    # e.g., service1 or service2

Each service server:
  1. Loads its service-specific symmetric key
  2. Loads the TGS public key registry
  3. Listens on its assigned port
  4. Handles SVC_REQ from clients:
     - Decrypts the service ticket (AES verification)
     - Verifies at least 2 TGS Schnorr signatures on the service ticket payload
     - Rejects tickets with invalid signatures
     - Rejects tickets signed with outdated key version
     - Grants access to the service
"""

import sys
import json
import os
import socket
import time
import threading

from crypto_utils import (
    verify_multi_signatures,
    aes_decrypt,
    canonical_message,
    send_message,
    recv_message,
    hex_to_bytes,
    hex_to_int,
    int_to_hex,
)

KEYS_DIR = "keys"
HOST = "127.0.0.1"
TIMESTAMP_TOLERANCE = 300
CURRENT_KEY_VERSION = 1


def load_config(service_id: str) -> dict:
    """Load service key and TGS public keys."""
    shared_path = os.path.join(KEYS_DIR, "shared_keys.json")
    with open(shared_path) as f:
        shared = json.load(f)

    if service_id not in shared["service_keys"]:
        raise ValueError(f"Unknown service: {service_id}")

    pub_path = os.path.join(KEYS_DIR, "public_keys.json")
    with open(pub_path) as f:
        pub = json.load(f)

    tgs_public_keys = {
        aid: hex_to_int(info["public_key"])
        for aid, info in pub.items()
        if aid.startswith("TGS")
    }

    svc_path = os.path.join(KEYS_DIR, "services.json")
    with open(svc_path) as f:
        svc_cfg = json.load(f)

    return {
        "service_id": service_id,
        "service_key": hex_to_bytes(shared["service_keys"][service_id]),
        "tgs_public_keys": tgs_public_keys,
        "port": svc_cfg[service_id]["port"],
    }


def validate_service_ticket(ticket: dict, cfg: dict) -> tuple:
    """
    Validate a service ticket.
    Returns (ok, error_msg, payload).

    Checks:
      1. Decrypt encrypted_service_ticket (AES verification)
      2. Verify payload matches decrypted version (tamper check)
      3. Verify key version is current (rejects outdated key version)
      4. Check ticket has not expired
      5. Verify at least 2 TGS Schnorr signatures (threshold: 2-of-3)
    """
    service_id = cfg["service_id"]

    if "payload" not in ticket or "signatures" not in ticket:
        return False, "Malformed ticket: missing payload or signatures", None

    # -- Decrypt service ticket using service's own key ---------
    if "encrypted_service_ticket" not in ticket:
        return False, "Missing encrypted_service_ticket", None
    try:
        enc = hex_to_bytes(ticket["encrypted_service_ticket"])
        decrypted_bytes = aes_decrypt(cfg["service_key"], enc)
        authoritative_payload = json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        return False, f"Service ticket decryption failed (AES invalid): {e}", None

    # -- Verify payload integrity -------------------------------
    if canonical_message(ticket["payload"]) != canonical_message(authoritative_payload):
        return False, "Service ticket payload tampered", None

    payload = authoritative_payload

    # -- Check service_id --------------------------------------
    if payload.get("service_id") != service_id:
        return False, f"Ticket not for this service (got {payload.get('service_id')})", None

    # -- Check key version (reject outdated) -------------------
    kv = payload.get("key_version", 0)
    if kv != CURRENT_KEY_VERSION:
        return False, f"Outdated key version {kv} (current: {CURRENT_KEY_VERSION})", None

    # -- Check expiry ------------------------------------------
    issue_ts = payload.get("issue_timestamp", 0)
    lifetime = payload.get("lifetime", 0)
    if time.time() > issue_ts + lifetime:
        return False, "Service ticket expired", None

    # -- Verify at least 2 TGS Schnorr signatures -------------
    m = canonical_message(payload)
    sigs = []
    for sig in ticket["signatures"]:
        sigs.append({
            "authority_id": sig["authority_id"],
            "R": hex_to_int(sig["R"]),
            "s": hex_to_int(sig["s"]),
        })

    if not verify_multi_signatures(m, sigs, cfg["tgs_public_keys"], threshold=2):
        valid_count = 0
        for sig in sigs:
            aid = sig["authority_id"]
            if aid in cfg["tgs_public_keys"]:
                from crypto_utils import schnorr_verify
                if schnorr_verify(m, sig["R"], sig["s"], cfg["tgs_public_keys"][aid], aid):
                    valid_count += 1
        return False, f"Insufficient valid TGS signatures: {valid_count} (need >= 2)", None

    print(f"  [{service_id}] Ticket validated for '{payload.get('client_id')}'")
    return True, "OK", payload


def handle_svc_request(request: dict, cfg: dict) -> dict:
    """
    Process a SVC_REQ and return a SVC_REP.

    Expected request fields:
      service_ticket : dict -- assembled service ticket from Phase 2
      authenticator  : str  -- AES-encrypted timestamp with service_session_key
    """
    service_id = cfg["service_id"]

    for field in ("service_ticket", "authenticator"):
        if field not in request:
            return {"type": "SVC_ERR", "error": f"Missing field: {field}"}

    svc_ticket = request["service_ticket"]

    # -- Validate service ticket -------------------------------
    ok, err, payload = validate_service_ticket(svc_ticket, cfg)
    if not ok:
        print(f"  [{service_id}] REJECTED: {err}")
        return {"type": "SVC_ERR", "error": err}

    client_id = payload["client_id"]
    svc_session_key = hex_to_bytes(payload["service_session_key"])

    # -- Verify authenticator (proves client has service session key) -
    try:
        auth_enc = hex_to_bytes(request["authenticator"])
        auth_data = json.loads(aes_decrypt(svc_session_key, auth_enc).decode())
        now = time.time()
        if abs(auth_data.get("timestamp", 0) - now) > TIMESTAMP_TOLERANCE:
            return {"type": "SVC_ERR", "error": "Authenticator timestamp invalid"}
        if auth_data.get("client_id") != client_id:
            return {"type": "SVC_ERR", "error": "Authenticator client_id mismatch"}
    except Exception as e:
        return {"type": "SVC_ERR", "error": f"Authenticator decryption failed: {e}"}

    # -- Grant access ------------------------------------------
    print(f"  [{service_id}] ACCESS GRANTED to '{client_id}'")

    # Encrypt service response with service session key
    from crypto_utils import aes_encrypt
    resp_data = {
        "status": "ACCESS_GRANTED",
        "client_id": client_id,
        "service_id": service_id,
        "message": f"Welcome {client_id}! You have successfully accessed {service_id}.",
        "timestamp": time.time(),
    }
    enc_resp = aes_encrypt(svc_session_key,
                            json.dumps(resp_data).encode())
    from crypto_utils import bytes_to_hex
    return {
        "type": "SVC_REP",
        "status": "ACCESS_GRANTED",
        "client_id": client_id,
        "encrypted_response": bytes_to_hex(enc_resp),
    }


def handle_client(conn, addr, cfg: dict):
    """Handle a single client connection."""
    try:
        request = recv_message(conn)
        if request is None:
            return

        if request.get("type") != "SVC_REQ":
            send_message(conn, {"type": "ERR", "error": "Unknown message type"})
            return

        response = handle_svc_request(request, cfg)
        send_message(conn, response)

    except Exception as e:
        print(f"  [{cfg['service_id']}] Error: {e}")
        try:
            send_message(conn, {"type": "SVC_ERR", "error": str(e)})
        except Exception:
            pass
    finally:
        conn.close()


def run_server(service_id: str):
    cfg = load_config(service_id)
    port = cfg["port"]

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(10)

    print(f"[{service_id}] Listening on {HOST}:{port}")

    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, cfg), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print(f"\n[{service_id}] Shutting down")
            break
        except Exception as e:
            print(f"[{service_id}] Accept error: {e}")

    srv.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python service_server.py <service_id>")
        print("  service_id: service1 | service2")
        sys.exit(1)
    run_server(sys.argv[1])

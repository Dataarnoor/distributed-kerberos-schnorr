"""
client.py
Kerberos client implementing full 3-phase multi-signature authentication.

Usage:
    python client.py <username> <password> <service_id>

    Example:
        python client.py alice alice_password service1

Three phases:
  Phase 1 -- Distributed AS Exchange:
    Contact all 3 AS nodes. Collect >=2 valid Schnorr signatures on the TGT.

  Phase 2 -- Distributed TGS Exchange:
    Present TGT to all 3 TGS nodes. Collect >=2 valid Schnorr signatures
    on the service ticket.

  Phase 3 -- Service Authentication:
    Present service ticket (with >=2 TGS signatures) to service server.
    Verify the response.
"""

import sys
import json
import os
import socket
import time
import threading

from crypto_utils import (
    schnorr_verify,
    verify_multi_signatures,
    aes_encrypt,
    aes_decrypt,
    canonical_message,
    send_message,
    recv_message,
    derive_key_from_password,
    sha256_hex,
    secure_random_bytes,
    bytes_to_hex,
    hex_to_bytes,
    hex_to_int,
    int_to_hex,
    create_tgt_payload,
    create_service_ticket_payload,
)

KEYS_DIR = "keys"
HOST = "127.0.0.1"
AS_PORTS  = {1: 5001, 2: 5002, 3: 5003}
TGS_PORTS = {1: 5011, 2: 5012, 3: 5013}
SVC_PORTS = {"service1": 5021, "service2": 5022}

TGT_LIFETIME = 3600
SVC_TICKET_LIFETIME = 600
KEY_VERSION = 1
TIMEOUT = 10


def load_public_keys():
    with open(os.path.join(KEYS_DIR, "public_keys.json")) as f:
        raw = json.load(f)
    return {aid: hex_to_int(info["public_key"]) for aid, info in raw.items()}


def connect_to(host: str, port: int):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        return s
    except Exception as e:
        print(f"    [client] Cannot connect to {host}:{port} -- {e}")
        return None


def build_auth_token(username: str, password: str, timestamp: float) -> str:
    pwd_hash = sha256_hex(password.encode())
    ts_str = str(int(timestamp))
    return sha256_hex((pwd_hash + ts_str + username).encode())


def normalise_payload(payload: dict) -> dict:
    """
    Normalise a ticket payload by round-tripping through JSON so that
    float timestamps have identical representation on client and server.
    """
    return json.loads(json.dumps(payload))


# --------------------------------------------------------------
# Phase 1: Distributed AS Exchange
# --------------------------------------------------------------

def phase1_get_tgt(username: str, password: str, public_keys: dict) -> dict:
    print("\n=== Phase 1: AS Exchange ===")

    session_key = bytes_to_hex(secure_random_bytes(32))
    now = time.time()

    tgt_payload = create_tgt_payload(username, now, TGT_LIFETIME, session_key, KEY_VERSION)
    # Normalise so canonical_message produces identical bytes to what server will sign
    tgt_payload = normalise_payload(tgt_payload)
    m = canonical_message(tgt_payload)

    timestamp = now
    auth_token = build_auth_token(username, password, timestamp)

    request = {
        "type": "AS_REQ",
        "client_id": username,
        "timestamp": timestamp,
        "auth_token": auth_token,
        "tgt_proposal": tgt_payload,
    }

    signatures = []
    encrypted_tgt_hex = None
    contacted = 0

    for node_id, port in AS_PORTS.items():
        print(f"  [client] Contacting AS{node_id} on port {port}...")
        sock = connect_to(HOST, port)
        if sock is None:
            print(f"  [client] AS{node_id} offline -- skipping")
            continue
        contacted += 1

        try:
            send_message(sock, request)
            response = recv_message(sock)
        except Exception as e:
            print(f"  [client] AS{node_id} communication error: {e}")
            continue
        finally:
            sock.close()

        if response is None or response.get("type") == "AS_ERR":
            print(f"  [client] AS{node_id} error: {response.get('error','unknown')}")
            continue

        auth_id = response.get("authority_id")
        sig = response.get("signature", {})
        R = sig.get("R")
        s = sig.get("s")

        if not (auth_id and R and s):
            print(f"  [client] AS{node_id} returned incomplete response")
            continue

        R_int = hex_to_int(R)
        s_int = hex_to_int(s)
        if auth_id in public_keys:
            if schnorr_verify(m, R_int, s_int, public_keys[auth_id], auth_id):
                print(f"  [client] AS{node_id} signature VALID OK")
                signatures.append({"authority_id": auth_id, "R": R, "s": s})
                if encrypted_tgt_hex is None:
                    encrypted_tgt_hex = response.get("encrypted_tgt")
            else:
                print(f"  [client] AS{node_id} signature INVALID -- discarding")
        else:
            print(f"  [client] Unknown authority: {auth_id}")

    if len(signatures) < 2:
        raise RuntimeError(
            f"Phase 1 failed: only {len(signatures)} valid AS signatures collected (need >= 2). "
            f"Contacted {contacted} AS nodes."
        )

    print(f"  [client] TGT assembled with {len(signatures)} AS signatures OK")

    tgt = {
        "payload": tgt_payload,
        "encrypted_tgt": encrypted_tgt_hex,
        "signatures": signatures[:3],
    }
    return tgt, session_key


# --------------------------------------------------------------
# Phase 2: Distributed TGS Exchange
# --------------------------------------------------------------

def phase2_get_service_ticket(tgt: dict, tgt_session_key_hex: str,
                               service_id: str, username: str,
                               public_keys: dict) -> dict:
    print(f"\n=== Phase 2: TGS Exchange (requesting '{service_id}') ===")

    tgt_session_key = hex_to_bytes(tgt_session_key_hex)
    now = time.time()

    svc_session_key = bytes_to_hex(secure_random_bytes(32))

    svc_payload = create_service_ticket_payload(
        username, service_id, now, SVC_TICKET_LIFETIME, svc_session_key, KEY_VERSION
    )
    # Normalise so canonical_message produces identical bytes to what TGS will sign
    svc_payload = normalise_payload(svc_payload)
    m = canonical_message(svc_payload)

    auth_data = {"client_id": username, "timestamp": now}
    authenticator = bytes_to_hex(aes_encrypt(tgt_session_key, json.dumps(auth_data).encode()))

    request = {
        "type": "TGS_REQ",
        "tgt": tgt,
        "service_id": service_id,
        "svc_proposal": svc_payload,
        "authenticator": authenticator,
    }

    signatures = []
    encrypted_svc_ticket_hex = None
    contacted = 0

    for node_id, port in TGS_PORTS.items():
        print(f"  [client] Contacting TGS{node_id} on port {port}...")
        sock = connect_to(HOST, port)
        if sock is None:
            print(f"  [client] TGS{node_id} offline -- skipping")
            continue
        contacted += 1

        try:
            send_message(sock, request)
            response = recv_message(sock)
        except Exception as e:
            print(f"  [client] TGS{node_id} communication error: {e}")
            continue
        finally:
            sock.close()

        if response is None or response.get("type") == "TGS_ERR":
            print(f"  [client] TGS{node_id} error: {response.get('error','unknown')}")
            continue

        auth_id = response.get("authority_id")
        sig = response.get("signature", {})
        R = sig.get("R")
        s = sig.get("s")

        if not (auth_id and R and s):
            print(f"  [client] TGS{node_id} returned incomplete response")
            continue

        R_int = hex_to_int(R)
        s_int = hex_to_int(s)
        if auth_id in public_keys:
            if schnorr_verify(m, R_int, s_int, public_keys[auth_id], auth_id):
                print(f"  [client] TGS{node_id} signature VALID OK")
                signatures.append({"authority_id": auth_id, "R": R, "s": s})
                if encrypted_svc_ticket_hex is None:
                    encrypted_svc_ticket_hex = response.get("encrypted_service_ticket")
            else:
                print(f"  [client] TGS{node_id} signature INVALID -- discarding")
        else:
            print(f"  [client] Unknown authority: {auth_id}")

    if len(signatures) < 2:
        raise RuntimeError(
            f"Phase 2 failed: only {len(signatures)} valid TGS signatures (need >= 2). "
            f"Contacted {contacted} TGS nodes."
        )

    print(f"  [client] Service ticket assembled with {len(signatures)} TGS signatures OK")

    service_ticket = {
        "payload": svc_payload,
        "encrypted_service_ticket": encrypted_svc_ticket_hex,
        "signatures": signatures,
    }
    return service_ticket, svc_session_key


# --------------------------------------------------------------
# Phase 3: Service Authentication
# --------------------------------------------------------------

def phase3_access_service(service_ticket: dict, svc_session_key_hex: str,
                           service_id: str, username: str) -> bool:
    print(f"\n=== Phase 3: Service Authentication ({service_id}) ===")

    svc_session_key = hex_to_bytes(svc_session_key_hex)
    now = time.time()

    auth_data = {"client_id": username, "timestamp": now}
    authenticator = bytes_to_hex(aes_encrypt(svc_session_key, json.dumps(auth_data).encode()))

    request = {
        "type": "SVC_REQ",
        "service_ticket": service_ticket,
        "authenticator": authenticator,
    }

    port = SVC_PORTS.get(service_id)
    if port is None:
        raise ValueError(f"Unknown service: {service_id}")

    print(f"  [client] Contacting {service_id} on port {port}...")
    sock = connect_to(HOST, port)
    if sock is None:
        raise RuntimeError(f"Cannot connect to {service_id}")

    try:
        send_message(sock, request)
        response = recv_message(sock)
    finally:
        sock.close()

    if response is None:
        raise RuntimeError("No response from service server")

    if response.get("type") == "SVC_ERR":
        print(f"  [client] Service REJECTED: {response.get('error')}")
        return False

    if response.get("type") == "SVC_REP" and response.get("status") == "ACCESS_GRANTED":
        try:
            enc = hex_to_bytes(response["encrypted_response"])
            resp_data = json.loads(aes_decrypt(svc_session_key, enc).decode())
            print(f"\n  +========================================+")
            print(f"  |  {resp_data.get('message', 'Access granted'):<38} |")
            print(f"  +========================================+")
        except Exception as e:
            print(f"  [client] Could not decrypt service response: {e}")
        return True

    print(f"  [client] Unexpected response: {response}")
    return False


# --------------------------------------------------------------
# Main Client Flow
# --------------------------------------------------------------

def run_client(username: str, password: str, service_id: str):
    print(f"\n{'='*55}")
    print(f"  Kerberos Multi-Signature Client")
    print(f"  User: {username}  |  Service: {service_id}")
    print(f"{'='*55}")

    t_start = time.time()
    public_keys = load_public_keys()

    t1 = time.time()
    tgt, session_key = phase1_get_tgt(username, password, public_keys)
    t1_elapsed = time.time() - t1
    print(f"  [timing] Phase 1 completed in {t1_elapsed:.3f}s")

    t2 = time.time()
    svc_ticket, svc_key = phase2_get_service_ticket(
        tgt, session_key, service_id, username, public_keys
    )
    t2_elapsed = time.time() - t2
    print(f"  [timing] Phase 2 completed in {t2_elapsed:.3f}s")

    t3 = time.time()
    success = phase3_access_service(svc_ticket, svc_key, service_id, username)
    t3_elapsed = time.time() - t3
    print(f"  [timing] Phase 3 completed in {t3_elapsed:.3f}s")

    total = time.time() - t_start
    print(f"\n  Total authentication time: {total:.3f}s")
    print(f"  Result: {'SUCCESS' if success else 'FAILED'}")
    return success


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client.py <username> <password> <service_id>")
        print("  Examples:")
        print("    python client.py alice alice_password service1")
        print("    python client.py bob bob_password service2")
        sys.exit(1)
    run_client(sys.argv[1], sys.argv[2], sys.argv[3])
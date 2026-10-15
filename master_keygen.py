"""
master_keygen.py
One-time key generation for all Kerberos authorities.

Run this FIRST before starting any server or client.

Generates:
  - Schnorr key pairs for AS1, AS2, AS3, TGS1, TGS2, TGS3
  - Shared symmetric keys for TGT and service ticket encryption
  - Sample user database (alice, bob)
  - Public key registry (used by clients and service servers)

Output directory: keys/
"""

import os
import json
import time

from crypto_utils import (
    schnorr_keygen,
    derive_key_from_password,
    secure_random_bytes,
    int_to_hex,
    bytes_to_hex,
    sha256_hex,
)

KEYS_DIR = "keys"

AUTHORITIES = [
    {"id": "AS1",  "type": "AS",  "port": 5001},
    {"id": "AS2",  "type": "AS",  "port": 5002},
    {"id": "AS3",  "type": "AS",  "port": 5003},
    {"id": "TGS1", "type": "TGS", "port": 5011},
    {"id": "TGS2", "type": "TGS", "port": 5012},
    {"id": "TGS3", "type": "TGS", "port": 5013},
]

SERVICES = [
    {"id": "service1", "port": 5021},
    {"id": "service2", "port": 5022},
]

USERS = [
    {"username": "alice",  "password": "alice_password"},
    {"username": "bob",    "password": "bob_password"},
    {"username": "charlie","password": "charlie_password"},
]

KEY_VERSION = 1


def generate_all_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    print("[keygen] Generating Schnorr key pairs for all authorities...")

    public_keys = {}

    for auth in AUTHORITIES:
        auth_id = auth["id"]
        x, y = schnorr_keygen()

        private_data = {
            "authority_id": auth_id,
            "authority_type": auth["type"],
            "port": auth["port"],
            "private_key": int_to_hex(x),
            "public_key": int_to_hex(y),
            "key_version": KEY_VERSION,
            "generated_at": time.time(),
        }

        fname = os.path.join(KEYS_DIR, f"{auth_id.lower()}_private.json")
        with open(fname, "w") as f:
            json.dump(private_data, f, indent=2)
        print(f"  [keygen] {auth_id}: private key saved to {fname}")

        public_keys[auth_id] = {
            "public_key": int_to_hex(y),
            "key_version": KEY_VERSION,
            "port": auth["port"],
            "type": auth["type"],
        }

    # Save public key registry (accessible by all nodes, clients, services)
    pub_path = os.path.join(KEYS_DIR, "public_keys.json")
    with open(pub_path, "w") as f:
        json.dump(public_keys, f, indent=2)
    print(f"\n[keygen] Public key registry saved to {pub_path}")

    # -------------------------------------------------------
    # Generate shared symmetric keys
    # -------------------------------------------------------
    print("\n[keygen] Generating shared symmetric keys...")

    # TGT encryption key: known to all AS nodes and all TGS nodes
    tgt_key = secure_random_bytes(32)

    # Service ticket encryption keys (one per service)
    service_keys = {}
    for svc in SERVICES:
        service_keys[svc["id"]] = bytes_to_hex(secure_random_bytes(32))

    shared = {
        "tgt_encryption_key": bytes_to_hex(tgt_key),
        "service_keys": service_keys,
        "key_version": KEY_VERSION,
    }
    shared_path = os.path.join(KEYS_DIR, "shared_keys.json")
    with open(shared_path, "w") as f:
        json.dump(shared, f, indent=2)
    print(f"[keygen] Shared symmetric keys saved to {shared_path}")

    # -------------------------------------------------------
    # Generate service configuration
    # -------------------------------------------------------
    svc_cfg = {}
    for svc in SERVICES:
        svc_cfg[svc["id"]] = {"port": svc["port"]}
    svc_path = os.path.join(KEYS_DIR, "services.json")
    with open(svc_path, "w") as f:
        json.dump(svc_cfg, f, indent=2)
    print(f"[keygen] Service config saved to {svc_path}")

    # -------------------------------------------------------
    # Generate user database
    # -------------------------------------------------------
    print("\n[keygen] Generating user database...")
    users_db = {}
    for user in USERS:
        uname = user["username"]
        pwd = user["password"]
        # Derive AES key from password
        key_bytes, salt = derive_key_from_password(pwd)
        # Store password verifier (hash of password with salt)
        verifier = sha256_hex((pwd + bytes_to_hex(salt)).encode())
        users_db[uname] = {
            "password_hash": sha256_hex(pwd.encode()),  # simple hash for fast lookup
            "aes_key": bytes_to_hex(key_bytes),
            "salt": bytes_to_hex(salt),
            "verifier": verifier,
        }
        print(f"  [keygen] User '{uname}' registered")

    users_path = os.path.join(KEYS_DIR, "users.json")
    with open(users_path, "w") as f:
        json.dump(users_db, f, indent=2)
    print(f"[keygen] User database saved to {users_path}")

    print("\n[keygen] === Key generation complete ===")
    print("[keygen] Directory listing:")
    for fn in sorted(os.listdir(KEYS_DIR)):
        fpath = os.path.join(KEYS_DIR, fn)
        print(f"  {fpath}")


if __name__ == "__main__":
    generate_all_keys()

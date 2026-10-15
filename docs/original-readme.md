# Kerberos Under Partial Compromise using Schnorr Multi-Signatures

**CS5.470 — System and Network Security, Lab Assignment 3**

---

## Overview

This project implements a Kerberos-inspired authentication system that remains secure even when one of three authentication authorities is fully compromised. Security is achieved through a **2-of-3 Schnorr multi-signature scheme**: a ticket is valid only when at least two independent authorities have signed it.

---

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                        CLIENT                             │
│   Phase 1: contact AS1+AS2+AS3 → collect ≥2 AS sigs      │
│   Phase 2: contact TGS1+TGS2+TGS3 → collect ≥2 TGS sigs │
│   Phase 3: present service ticket → get service access    │
└───────────────────────────────────────────────────────────┘
         ↕              ↕              ↕
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │  AS1     │  │  AS2     │  │  AS3     │
   │ port 5001│  │ port 5002│  │ port 5003│
   └──────────┘  └──────────┘  └──────────┘
         ↕              ↕              ↕
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │  TGS1    │  │  TGS2    │  │  TGS3    │
   │ port 5011│  │ port 5012│  │ port 5013│
   └──────────┘  └──────────┘  └──────────┘
         ↕
   ┌──────────┐  ┌──────────┐
   │ Service1 │  │ Service2 │
   │ port 5021│  │ port 5022│
   └──────────┘  └──────────┘
```

### Ports

| Component   | Port |
|-------------|------|
| AS1         | 5001 |
| AS2         | 5002 |
| AS3         | 5003 |
| TGS1        | 5011 |
| TGS2        | 5012 |
| TGS3        | 5013 |
| service1    | 5021 |
| service2    | 5022 |

---

## File Structure

```
.
├── crypto_utils.py      # Core cryptographic primitives (Schnorr, AES-256, PKCS#7)
├── master_keygen.py     # One-time key generation for all authorities
├── as_node.py           # Authentication Server node
├── tgs_node.py          # Ticket Granting Server node
├── service_server.py    # Service Server
├── client.py            # Kerberos client (full 3-phase flow)
├── attacks.py           # Mandatory attack scenario demonstrations
├── run_demo.py          # Demo orchestrator (starts all servers + runs client + attacks)
├── keys/                # Generated key files (created by master_keygen.py)
│   ├── as1_private.json
│   ├── as2_private.json
│   ├── as3_private.json
│   ├── tgs1_private.json
│   ├── tgs2_private.json
│   ├── tgs3_private.json
│   ├── public_keys.json
│   ├── shared_keys.json
│   ├── services.json
│   └── users.json
├── README.md
└── SECURITY.md
```

---

## Cryptographic Primitives

All cryptographic primitives are implemented **from scratch** in `crypto_utils.py`:

| Primitive | Implementation |
|-----------|---------------|
| Modular exponentiation | Manual square-and-multiply (`mod_pow`) |
| Schnorr key generation | Manual: `x ← Z_q`, `y = g^x mod p` |
| Schnorr signing | Manual: `R=g^k mod p`, `e=H(m‖R‖ID)`, `s=k+ex mod q` |
| Schnorr verification | Manual: `g^s ≡ R·y^e mod p` |
| AES-256-CBC | Manual: S-box, MixColumns, ShiftRows, key expansion |
| PKCS#7 padding | Manual implementation |
| SHA-256 | Python `hashlib` standard library |
| Secure RNG | Python `os.urandom()` |

**No asymmetric cryptographic libraries are used.**

### Schnorr Group Parameters (RFC 5114, Section 2.1)
- **p**: 1024-bit prime
- **q**: 160-bit prime subgroup order (q | p−1)
- **g**: generator of order q in Z_p*

---

## Quick Start

### Step 1: Generate All Keys (run once)

```bash
python master_keygen.py
```

This creates the `keys/` directory with all key files.

### Step 2: Run Full Demo (all-in-one)

```bash
python run_demo.py
```

This starts all servers, runs the client demo, then runs all attack scenarios.

### Step 3: Manual Mode (separate terminals)

**Terminal 1–3 (AS nodes):**
```bash
python as_node.py 1
python as_node.py 2
python as_node.py 3
```

**Terminal 4–6 (TGS nodes):**
```bash
python tgs_node.py 1
python tgs_node.py 2
python tgs_node.py 3
```

**Terminal 7–8 (Service servers):**
```bash
python service_server.py service1
python service_server.py service2
```

**Terminal 9 (Client):**
```bash
python client.py alice alice_password service1
python client.py bob bob_password service2
```

**Terminal 10 (Attacks):**
```bash
python attacks.py
```

---

## Protocol Flow

### Phase 1: Distributed AS Exchange

1. Client generates a fresh session key `K_c_tgs` and proposes a TGT payload
2. Client contacts **all 3 AS nodes** in parallel
3. Each AS:
   - Verifies client credentials via `auth_token = SHA256(pwd_hash ‖ ts ‖ client_id)`
   - Validates the proposed TGT payload
   - Signs with its own Schnorr key: `(R_i, s_i) = SchnorrSign(m, x_i, auth_id_i)`
4. Client collects responses, verifies each signature
5. Client assembles TGT with **≥2 valid AS signatures**

### Phase 2: Distributed TGS Exchange

1. Client proposes a service ticket payload with fresh service session key `K_c_svc`
2. Client presents TGT + authenticator to **all 3 TGS nodes**
3. Each TGS:
   - Decrypts TGT, verifies **≥2 AS signatures** (threshold check)
   - Verifies the authenticator (proves client holds `K_c_tgs`)
   - Signs service ticket: `(R_j, s_j) = SchnorrSign(svc_m, x_j, auth_id_j)`
4. Client assembles service ticket with **≥2 valid TGS signatures**

### Phase 3: Service Authentication

1. Client presents service ticket + authenticator (encrypted with `K_c_svc`)
2. Service server:
   - Decrypts service ticket using its own key (AES integrity check)
   - Verifies **≥2 TGS Schnorr signatures**
   - Checks key version
   - Verifies authenticator
3. Service returns encrypted response confirming access

---

## Attack Scenarios (`attacks.py`)

| # | Attack | Outcome |
|---|--------|---------|
| 1 | Single malicious AS forges ticket | **BLOCKED** — 1 sig < threshold of 2 |
| 2 | Client modifies TGT payload | **BLOCKED** — Schnorr sigs bind to exact message |
| 3 | Replay of old partial signature | **BLOCKED** — challenge includes message hash |
| 4 | Leakage of AS1 private key | **BLOCKED** — cannot forge AS2/AS3 without DLP break |
| 5 | Authority offline (AS1 down) | **RESILIENT** — AS2+AS3 satisfy 2-of-3 threshold |
| 6 | Single-signature ticket at service | **BLOCKED** — service requires ≥2 TGS sigs |
| B | Nonce reuse → key recovery | **DEMONSTRATED** — shows why fresh nonce is critical |
| P | Performance benchmark | **MEASURED** — real Schnorr sign/verify timing, per-phase overhead |

---

## Sample Users

| Username | Password |
|----------|----------|
| alice | alice_password |
| bob | bob_password |
| charlie | charlie_password |

---

## Performance

Measured on this system (pure Python, RFC 5114 1024-bit group, 30-run average via `attacks.py`):

| Operation | Time |
|-----------|------|
| Schnorr sign | ~0.6 ms |
| Schnorr verify | ~1.1 ms |
| Phase 1 crypto (3 AS) | ~5 ms |
| Phase 2 crypto (3 TGS) | ~5 ms |
| Total crypto overhead | ~10 ms |

This is ~3x the overhead of classical single-authority Kerberos. In production (C/OpenSSL), each op is <0.1 ms and network latency dominates. Run `python attacks.py` to reproduce these numbers on your machine.

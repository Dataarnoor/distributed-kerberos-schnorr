# Distributed Kerberos with Schnorr Multi-Signatures

A Kerberos-inspired authentication prototype using eight local server processes and a 2-of-3 Schnorr signature policy for authentication and service tickets. It demonstrates ticket validation when one signing authority is compromised or unavailable.

Developed as part of System and Network Security coursework at IIIT Hyderabad. Cryptographic arithmetic, Schnorr signatures, AES-256-CBC, and PKCS#7 padding are implemented in Python; hashing and secure randomness use the standard library.

## Highlights

- Three Authentication Servers (AS), three Ticket Granting Servers (TGS), and two service servers.
- Each ticket requires valid signatures from at least two distinct authorities.
- Three-phase client flow: obtain a TGT, obtain a service ticket, authenticate to a service.
- Demonstrations of single-authority forgery, payload tampering, old-signature substitution, leaked signing keys, authority unavailability, and insufficient service-ticket signatures.
- A deliberately reused Schnorr nonce demonstration recovers the signing key and explains why fresh nonces matter.
- Standalone signing/verification benchmarks and a complete local socket demo.

The 2-of-3 policy verifies separate Schnorr signatures under independent keys. It does not implement secret sharing or a jointly generated threshold signature.

## Architecture

```text
                       Client
                          |
           +--------------+--------------+
           |              |              |
          AS1            AS2            AS3
         :5001          :5002          :5003
           +--------------+--------------+
                          |
               TGT with >=2 AS signatures
                          |
           +--------------+--------------+
           |              |              |
          TGS1           TGS2           TGS3
         :5011          :5012          :5013
           +--------------+--------------+
                          |
            Ticket with >=2 TGS signatures
                          |
                 +--------+--------+
                 |                 |
             Service 1         Service 2
               :5021             :5022
```

All servers bind to `127.0.0.1`. The demo runs all eight server processes on one computer.

## Quick start

Requires Python 3.9+; there are no third-party Python dependencies.

```bash
git clone https://github.com/Dataarnoor/distributed-kerberos-schnorr.git
cd distributed-kerberos-schnorr
python3 run_demo.py
```

The orchestrator generates keys when absent, starts the servers, runs standalone attack demonstrations and benchmarks, authenticates sample clients, and stops the servers. Ports 5001-5003, 5011-5013, and 5021-5022 must be available.

Run just the standalone attack demonstrations and benchmark:

```bash
python3 attacks.py
```

## Manual demo

Generate local keys once:

```bash
python3 master_keygen.py
```

Run each of the following commands in a separate terminal from the repository directory:

```bash
python3 as_node.py 1
python3 as_node.py 2
python3 as_node.py 3
python3 tgs_node.py 1
python3 tgs_node.py 2
python3 tgs_node.py 3
python3 service_server.py service1
python3 service_server.py service2
```

Then run a client:

```bash
python3 client.py alice alice_password service1
python3 client.py bob bob_password service2
```

`alice`, `bob`, and `charlie` use the intentionally public demo passwords `alice_password`, `bob_password`, and `charlie_password`. The generated `keys/` directory contains private keys, symmetric keys, and demo user records; Git excludes the whole directory. Regenerate local demo keys with `master_keygen.py` only when the servers are stopped.

## Source map

| File | Responsibility |
| --- | --- |
| `crypto_utils.py` | Modular arithmetic, Schnorr signatures, AES-256-CBC, padding, serialization |
| `master_keygen.py` | Authority keys, shared keys, service configuration, demo users |
| `as_node.py` | Client authentication and AS signatures |
| `tgs_node.py` | TGT validation and service-ticket signatures |
| `service_server.py` | Service-ticket and authenticator validation |
| `client.py` | Full three-phase authentication flow |
| `attacks.py` | Standalone attack demonstrations and performance benchmark |
| `run_demo.py` | Local server and client orchestration |

## Performance and scope

The original coursework documentation reports approximately 10-11 ms of combined AS/TGS cryptographic overhead on the original machine. Run `attacks.py` to measure this implementation on your machine; end-to-end authentication also includes socket and process overhead.

The demonstrations illustrate the signature policy and selected protocol checks, rather than establishing production security. This is a custom educational protocol with a 1024-bit Schnorr group, handwritten cryptography, demo credential storage, and timestamp freshness checks. AES-CBC padding validation alone does not establish ciphertext authenticity, and timestamp checks alone do not prevent replay within the allowed freshness window. The nonce-reuse example demonstrates key recovery; it does not implement a recovery defense.

See the [original coursework security analysis](SECURITY.md) and [original README](docs/original-readme.md) for the submitted design and recorded results. Those documents retain the original analysis; the scope and limitations above apply to this repository.

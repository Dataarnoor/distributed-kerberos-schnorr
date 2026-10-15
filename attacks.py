"""
attacks.py
Mandatory attack scenario demonstrations for the Kerberos multi-signature system.

All 6 attacks are simulated locally using the cryptographic primitives directly.
No servers need to be running (attacks demonstrate crypto-level properties).

Attacks demonstrated:
  1. Single malicious authority issuing forged ticket
  2. Modified ticket payload (tamper attack)
  3. Replay of old partial signature
  4. Leakage of one authority's private signing key
  5. Authority offline scenario (system resilience)
  6. Ticket containing only one valid signature
"""

import json
import time
import os
import copy

from crypto_utils import (
    schnorr_keygen,
    schnorr_sign,
    schnorr_verify,
    verify_multi_signatures,
    aes_encrypt,
    aes_decrypt,
    canonical_message,
    secure_random_bytes,
    bytes_to_hex,
    hex_to_bytes,
    create_tgt_payload,
    create_service_ticket_payload,
    int_to_hex,
    sha256_hex,
)


SEPARATOR = "-" * 60


def print_header(title: str):
    print(f"\n{'='*60}")
    print(f"  ATTACK: {title}")
    print(f"{'='*60}")


def print_result(blocked: bool, description: str):
    status = "[BLOCKED] BLOCKED" if blocked else "[BREACH] SECURITY BREACH"
    print(f"\n  Result: {status}")
    print(f"  {description}")


# --------------------------------------------------------------
# Setup: Generate 3 AS key pairs and 3 TGS key pairs
# --------------------------------------------------------------

def setup_keys():
    """Generate fresh key pairs for all authorities (simulated)."""
    print("\n[setup] Generating Schnorr key pairs for simulation...")
    as_keys  = {}  # {auth_id: (x, y)}
    tgs_keys = {}

    for i in range(1, 4):
        x, y = schnorr_keygen()
        as_keys[f"AS{i}"] = (x, y)
        print(f"  AS{i}: pub={int_to_hex(y)[:20]}...")

    for i in range(1, 4):
        x, y = schnorr_keygen()
        tgs_keys[f"TGS{i}"] = (x, y)
        print(f"  TGS{i}: pub={int_to_hex(y)[:20]}...")

    as_pub  = {aid: keys[1] for aid, keys in as_keys.items()}
    tgs_pub = {aid: keys[1] for aid, keys in tgs_keys.items()}
    return as_keys, tgs_keys, as_pub, tgs_pub


def make_legit_tgt(username: str, as_keys: dict, as_pub: dict) -> tuple:
    """Create a legitimate TGT signed by 2 valid AS nodes."""
    session_key = bytes_to_hex(secure_random_bytes(32))
    payload = create_tgt_payload(username, time.time(), 3600, session_key)
    m = canonical_message(payload)

    signatures = []
    for auth_id in ["AS1", "AS2"]:
        x, y = as_keys[auth_id]
        R, s = schnorr_sign(m, x, auth_id)
        signatures.append({"authority_id": auth_id, "R": R, "s": s})

    tgt = {"payload": payload, "signatures": signatures, "session_key": session_key}
    return tgt, session_key


def make_legit_svc_ticket(username: str, service_id: str,
                           tgs_keys: dict, tgs_pub: dict) -> tuple:
    """Create a legitimate service ticket signed by 2 valid TGS nodes."""
    svc_key = bytes_to_hex(secure_random_bytes(32))
    payload = create_service_ticket_payload(username, service_id, time.time(), 600, svc_key)
    m = canonical_message(payload)

    signatures = []
    for auth_id in ["TGS1", "TGS2"]:
        x, y = tgs_keys[auth_id]
        R, s = schnorr_sign(m, x, auth_id)
        signatures.append({"authority_id": auth_id, "R": R, "s": s})

    ticket = {"payload": payload, "signatures": signatures, "svc_key": svc_key}
    return ticket, svc_key


# --------------------------------------------------------------
# Attack 1: Single Malicious Authority Issues Forged Ticket
# --------------------------------------------------------------

def attack1_single_malicious_authority(as_keys: dict, as_pub: dict):
    print_header("Single Malicious Authority Issues Forged Ticket")
    print("""
  Scenario: AS1 is fully compromised. The attacker uses AS1's private key
  to forge a TGT claiming to be user 'admin' (who does not exist as a
  legitimate user). AS1 provides only its own signature.
""")

    # Forged TGT: only signed by compromised AS1
    forged_payload = create_tgt_payload("admin", time.time(), 3600,
                                         bytes_to_hex(secure_random_bytes(32)))
    m = canonical_message(forged_payload)

    # Attacker has full control of AS1
    x1, y1 = as_keys["AS1"]
    R1, s1 = schnorr_sign(m, x1, "AS1")
    forged_signatures = [{"authority_id": "AS1", "R": R1, "s": s1}]

    print(f"  Forged ticket signed by: ['AS1'] (1 signature)")
    print(f"  Required threshold: 2 signatures")

    # Verification at TGS / Service
    is_valid = verify_multi_signatures(m, forged_signatures, as_pub, threshold=2)

    print_result(
        not is_valid,
        "Forged ticket rejected: 1 valid signature < threshold of 2. "
        "AS2 and AS3 never co-signed this ticket, so the forged ticket "
        "is cryptographically invalid."
    )
    assert not is_valid, "SECURITY BREACH: Single-authority forged ticket accepted!"
    return True


# --------------------------------------------------------------
# Attack 2: Modified Ticket Payload
# --------------------------------------------------------------

def attack2_modified_payload(as_keys: dict, as_pub: dict):
    print_header("Modified Ticket Payload (Tamper Attack)")
    print("""
  Scenario: Alice legitimately obtains a TGT. Then she (or a MitM) modifies
  the payload -- changing 'client_id' from 'alice' to 'admin' to escalate
  privilege. The existing valid signatures are kept but the payload has changed.
""")

    # Legitimate TGT for alice
    tgt, _ = make_legit_tgt("alice", as_keys, as_pub)
    m_original = canonical_message(tgt["payload"])

    # Verify original is valid
    sigs = [{"authority_id": s["authority_id"], "R": s["R"], "s": s["s"]}
            for s in tgt["signatures"]]
    assert verify_multi_signatures(m_original, sigs, as_pub, threshold=2), \
        "Setup error: original TGT should be valid"
    print(f"  Original TGT valid: OK (client_id='alice')")

    # Attack: modify payload
    tampered_payload = copy.deepcopy(tgt["payload"])
    tampered_payload["client_id"] = "admin"
    m_tampered = canonical_message(tampered_payload)

    print(f"  Tampered TGT: client_id changed to 'admin'")
    print(f"  Original message hash: {sha256_hex(m_original)[:32]}...")
    print(f"  Tampered message hash: {sha256_hex(m_tampered)[:32]}...")

    # The OLD signatures are still present but sign the ORIGINAL message
    is_valid = verify_multi_signatures(m_tampered, sigs, as_pub, threshold=2)

    print_result(
        not is_valid,
        "Tampered ticket rejected: the Schnorr signatures bind to the exact "
        "canonical message bytes. Any change to the payload produces a different "
        "hash, causing signature verification to fail."
    )
    assert not is_valid, "SECURITY BREACH: Tampered ticket accepted!"
    return True


# --------------------------------------------------------------
# Attack 3: Replay of Old Partial Signature
# --------------------------------------------------------------

def attack3_signature_replay(as_keys: dict, as_pub: dict):
    print_header("Replay of Old Partial Signature")
    print("""
  Scenario: An attacker captured a valid (R1, s1) signature from a previous
  TGT request for user 'alice'. They try to replay this old signature on a
  NEW ticket (different session key, different timestamp) to get a free
  second signature without interacting with AS1 again.
""")

    # First ticket -- capture AS1's signature
    old_session_key = bytes_to_hex(secure_random_bytes(32))
    old_payload = create_tgt_payload("alice", time.time() - 7200, 3600, old_session_key)
    m_old = canonical_message(old_payload)
    x1, y1 = as_keys["AS1"]
    R1_old, s1_old = schnorr_sign(m_old, x1, "AS1")
    print(f"  Old signature captured: R={int_to_hex(R1_old)[:20]}...")

    # New ticket -- attacker creates with a different session key/timestamp
    new_session_key = bytes_to_hex(secure_random_bytes(32))
    new_payload = create_tgt_payload("alice", time.time(), 3600, new_session_key)
    m_new = canonical_message(new_payload)

    # AS2 honestly signs the new payload
    x2, y2 = as_keys["AS2"]
    R2_new, s2_new = schnorr_sign(m_new, x2, "AS2")

    # Attacker uses OLD (R1, s1) replayed on the NEW ticket
    replayed_signatures = [
        {"authority_id": "AS1", "R": R1_old, "s": s1_old},  # REPLAYED old sig
        {"authority_id": "AS2", "R": R2_new, "s": s2_new},  # honest sig
    ]

    print(f"  New ticket created with different payload")
    print(f"  Attacker replays old AS1 signature on new payload")

    # Verify AS1's signature on new payload using old (R1, s1)
    as1_valid = schnorr_verify(m_new, R1_old, s1_old, y1, "AS1")
    as2_valid = schnorr_verify(m_new, R2_new, s2_new, y2, "AS2")
    is_valid = verify_multi_signatures(m_new, replayed_signatures, as_pub, threshold=2)

    print(f"  AS1 replayed signature valid on new message: {as1_valid}")
    print(f"  AS2 honest signature valid: {as2_valid}")

    print_result(
        not as1_valid,
        "Replay attack blocked: the Schnorr challenge e = H(m || R || ID) "
        "binds the signature to the specific message m. An old signature "
        "generated over a different message m' cannot verify under m."
    )
    assert not as1_valid, "SECURITY BREACH: Replayed signature verified!"
    return True


# --------------------------------------------------------------
# Attack 4: Leakage of One Authority's Private Key
# --------------------------------------------------------------

def attack4_key_leakage(as_keys: dict, as_pub: dict):
    print_header("Leakage of One Authority's Private Key")
    print("""
  Scenario: AS1's private key x1 is leaked (e.g., memory dump, insider threat).
  The attacker now has x1 and tries to forge a TGT for 'root' with only
  the compromised AS1 key. Can they produce a valid 2-of-3 ticket?
""")

    leaked_x1 = as_keys["AS1"][0]
    print(f"  Leaked AS1 private key: {int_to_hex(leaked_x1)[:20]}...")

    # Attacker forges AS1 signature
    forged_payload = create_tgt_payload("root", time.time(), 3600,
                                         bytes_to_hex(secure_random_bytes(32)))
    m = canonical_message(forged_payload)
    R1_forged, s1_forged = schnorr_sign(m, leaked_x1, "AS1")

    # Verify attacker's forged AS1 signature IS valid (key is real)
    as1_sig_valid = schnorr_verify(m, R1_forged, s1_forged, as_pub["AS1"], "AS1")
    print(f"  Forged AS1 signature valid (expected: True): {as1_sig_valid}")

    # Attacker needs a second valid signature but cannot forge AS2 or AS3
    # without their private keys (DLP assumption)
    forged_signatures_single = [{"authority_id": "AS1", "R": R1_forged, "s": s1_forged}]
    is_valid_single = verify_multi_signatures(m, forged_signatures_single, as_pub, threshold=2)

    print(f"\n  Attacker has x1 (AS1), cannot break DLP to get x2 or x3.")
    print(f"  Ticket with only AS1's forged sig valid: {is_valid_single}")

    # Attacker cannot solve DLP to get x2 from y2 = g^x2 mod p.
    # Best they can do: generate a fresh random key pair and sign with it.
    # But the verifier checks against the REAL AS2 public key -- mismatch -> fail.
    x_fake, y_fake = schnorr_keygen()          # random key, NOT the real x2
    R2_fake, s2_fake = schnorr_sign(m, x_fake, "AS2")   # signed under wrong key
    forged_signatures_two = [
        {"authority_id": "AS1", "R": R1_forged, "s": s1_forged},
        {"authority_id": "AS2", "R": R2_fake,   "s": s2_fake},
    ]
    # Verifier uses REAL AS2 public key y2, not y_fake
    as2_random_valid = schnorr_verify(m, R2_fake, s2_fake, as_pub["AS2"], "AS2")
    is_valid_two = verify_multi_signatures(m, forged_signatures_two, as_pub, threshold=2)

    print(f"  Attacker signs with a random key (cannot compute x2 = DLP of y2)")
    print(f"  Fake AS2 sig verified against real AS2 public key: {as2_random_valid}")
    print(f"  Two-signature ticket (real AS1 forged + fake AS2) valid: {is_valid_two}")

    print_result(
        not is_valid_two,
        "Key leakage partially contained: attacker forges AS1 sig (has x1) "
        "but any AS2 signature produced under a different private key fails "
        "verification against AS2's real public key. Computing x2 from "
        "y2 = g^x2 mod p is the Discrete Logarithm Problem -- infeasible "
        "in a 1024-bit group. The 2-of-3 threshold holds."
    )
    assert not is_valid_two, "SECURITY BREACH: Key leakage allows full ticket forgery!"
    return True


# --------------------------------------------------------------
# Attack 5: Authority Offline (Resilience Test)
# --------------------------------------------------------------

def attack5_authority_offline(as_keys: dict, as_pub: dict):
    print_header("Authority Offline Scenario")
    print("""
  Scenario: AS1 crashes / becomes unreachable. The client can only contact
  AS2 and AS3. Does the system still work with 2 out of 3 authorities?
""")

    # Simulate AS1 being offline: only AS2 and AS3 respond
    session_key = bytes_to_hex(secure_random_bytes(32))
    payload = create_tgt_payload("alice", time.time(), 3600, session_key)
    m = canonical_message(payload)

    available_authorities = ["AS2", "AS3"]  # AS1 is offline
    print(f"  AS1 offline. Available: {available_authorities}")

    signatures = []
    for auth_id in available_authorities:
        x, y = as_keys[auth_id]
        R, s = schnorr_sign(m, x, auth_id)
        signatures.append({"authority_id": auth_id, "R": R, "s": s})

    is_valid = verify_multi_signatures(m, signatures, as_pub, threshold=2)
    valid_count = sum(
        1 for sig in signatures
        if schnorr_verify(m, sig["R"], sig["s"],
                          as_pub[sig["authority_id"]], sig["authority_id"])
    )

    print(f"  Valid signatures collected: {valid_count}")
    print(f"  System operational: {is_valid}")

    print_result(
        is_valid,
        "System remains operational with AS1 offline. Two remaining honest "
        "authorities (AS2, AS3) satisfy the 2-of-3 threshold. The Kerberos "
        "service is not disrupted by a single authority failure."
    )
    assert is_valid, "SYSTEM FAILURE: Should work with 2-of-3 authorities!"
    return True


# --------------------------------------------------------------
# Attack 6: Ticket with Only One Valid Signature
# --------------------------------------------------------------

def attack6_single_signature_ticket(tgs_keys: dict, tgs_pub: dict):
    print_header("Ticket with Only One Valid TGS Signature")
    print("""
  Scenario: A compromised TGS1 issues a service ticket and tries to pass it
  off as valid. The ticket contains only TGS1's valid signature (TGS2 and
  TGS3 did not sign it). The service server checks the multi-signature.
""")

    svc_key = bytes_to_hex(secure_random_bytes(32))
    payload = create_service_ticket_payload("alice", "service1", time.time(), 600, svc_key)
    m = canonical_message(payload)

    # Only TGS1 (compromised) signs
    x1, y1 = tgs_keys["TGS1"]
    R1, s1 = schnorr_sign(m, x1, "TGS1")
    single_sig_ticket = [{"authority_id": "TGS1", "R": R1, "s": s1}]

    print(f"  Ticket signed by: ['TGS1'] only (1 signature)")
    print(f"  Service server threshold: 2 valid TGS signatures")

    # Service server verification
    is_valid = verify_multi_signatures(m, single_sig_ticket, tgs_pub, threshold=2)
    tgs1_sig_valid = schnorr_verify(m, R1, s1, y1, "TGS1")

    print(f"  TGS1 signature itself is valid: {tgs1_sig_valid}")
    print(f"  Ticket passes threshold check: {is_valid}")

    print_result(
        not is_valid,
        "Single-signature ticket rejected at service server: 1 valid signature "
        "< threshold of 2. The service correctly requires co-signing from at "
        "least 2 independent TGS nodes."
    )
    assert not is_valid, "SECURITY BREACH: Single-signature ticket accepted by service!"
    return True


# --------------------------------------------------------------
# Bonus: Nonce Reuse Attack (private key recovery demonstration)
# --------------------------------------------------------------

def attack_bonus_nonce_reuse(as_keys: dict, as_pub: dict):
    print_header("BONUS: Nonce Reuse -> Private Key Recovery")
    print("""
  Scenario: AS1 accidentally reuses the same nonce k for two different
  messages m1 and m2. An adversary observing both (R, s1) and (R, s2)
  can recover x1 (the private key) from the two signatures.

  Math: s1 = k + e1*x   ->  s2 = k + e2*x
        s1 - s2 = (e1 - e2)*x  ->  x = (s1 - s2) / (e1 - e2)  mod q
""")
    from crypto_utils import Q, G, P, mod_pow, mod_inverse, sha256_int, secure_random_int

    x1, y1 = as_keys["AS1"]
    auth_id = "AS1"

    # REUSED nonce
    k_reused = secure_random_int(Q)
    R = mod_pow(G, k_reused, P)
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, 'big')

    m1 = b"TGT for alice at t=100"
    m2 = b"TGT for bob at t=200"

    # Sign m1 with reused k
    e1 = sha256_int(m1 + R_bytes + auth_id.encode()) % Q
    s1 = (k_reused + e1 * x1) % Q

    # Sign m2 with SAME reused k
    e2 = sha256_int(m2 + R_bytes + auth_id.encode()) % Q
    s2 = (k_reused + e2 * x1) % Q

    print(f"  Attacker observes: same R in both signatures (nonce reused!)")
    print(f"  Recovering private key via: x = (s1 - s2) * (e1 - e2)^(-1) mod q")

    # Recovery: x = (s1 - s2) * modular_inverse(e1 - e2, q) mod q
    s_diff = (s1 - s2) % Q
    e_diff = (e1 - e2) % Q
    if e_diff == 0:
        print("  (e1 == e2 in this run, skipping recovery -- try again)")
        return True

    x_recovered = (s_diff * mod_inverse(e_diff, Q)) % Q
    recovery_success = (x_recovered == x1)

    print(f"  Original private key: {int_to_hex(x1)[:20]}...")
    print(f"  Recovered key:        {int_to_hex(x_recovered)[:20]}...")
    print(f"  Key recovery successful: {recovery_success}")

    print_result(
        recovery_success,
        "NONCE REUSE IS CATASTROPHIC: Reusing k in two Schnorr signatures "
        "allows full private key recovery with simple arithmetic. Our "
        "implementation always generates a fresh k via os.urandom()."
    )
    return True


# --------------------------------------------------------------
# Performance Benchmark
# --------------------------------------------------------------

def run_performance_benchmark():
    print_header("Performance Benchmark: Schnorr Operations (1024-bit group)")
    print("""
  Measuring actual wall-clock time for Schnorr sign and verify
  on a 1024-bit group with 160-bit subgroup (RFC 5114 params).
""")
    N = 30
    x, y = schnorr_keygen()
    m = b"benchmark test message"

    # Warm up
    for _ in range(3):
        R, s = schnorr_sign(m, x, "AS1")
        schnorr_verify(m, R, s, y, "AS1")

    # Time signing
    t0 = time.time()
    sigs = []
    for _ in range(N):
        R, s = schnorr_sign(m, x, "AS1")
        sigs.append((R, s))
    sign_ms = (time.time() - t0) / N * 1000

    # Time verification
    t0 = time.time()
    for R, s in sigs:
        schnorr_verify(m, R, s, y, "AS1")
    verify_ms = (time.time() - t0) / N * 1000

    print(f"  Schnorr sign   (per op, avg {N} runs): {sign_ms:.1f} ms")
    print(f"  Schnorr verify (per op, avg {N} runs): {verify_ms:.1f} ms")
    print(f"")
    print(f"  Protocol overhead estimate (pure Python, loopback network):")
    print(f"    Phase 1 - 3 AS nodes: ~{3*sign_ms:.0f} ms sign + ~{3*verify_ms:.0f} ms verify = ~{3*(sign_ms+verify_ms):.0f} ms crypto")
    print(f"    Phase 2 - 3 TGS nodes: ~{3*sign_ms:.0f} ms sign + ~{3*verify_ms:.0f} ms verify = ~{3*(sign_ms+verify_ms):.0f} ms crypto")
    print(f"    Total crypto overhead: ~{6*(sign_ms+verify_ms):.0f} ms")
    print(f"")
    print(f"  Classical Kerberos: 1 sign + 1 verify per phase")
    print(f"  This system:        3 sign + 3 verify per phase (3x overhead)")
    print(f"  Security gain: tolerates 1 fully compromised authority")


# --------------------------------------------------------------
# Main
# --------------------------------------------------------------

def run_all_attacks():
    print("\n" + "#"*60)
    print("  Kerberos Multi-Signature -- Attack Scenario Demonstrations")
    print("#"*60)

    as_keys, tgs_keys, as_pub, tgs_pub = setup_keys()

    results = {}

    for name, fn, args in [
        ("Attack 1: Single Malicious Authority",
         attack1_single_malicious_authority, (as_keys, as_pub)),
        ("Attack 2: Modified Payload",
         attack2_modified_payload, (as_keys, as_pub)),
        ("Attack 3: Signature Replay",
         attack3_signature_replay, (as_keys, as_pub)),
        ("Attack 4: Key Leakage",
         attack4_key_leakage, (as_keys, as_pub)),
        ("Attack 5: Authority Offline",
         attack5_authority_offline, (as_keys, as_pub)),
        ("Attack 6: Single-Signature Ticket",
         attack6_single_signature_ticket, (tgs_keys, tgs_pub)),
        ("Bonus: Nonce Reuse",
         attack_bonus_nonce_reuse, (as_keys, as_pub)),
        ("Performance Benchmark",
         lambda *_: (run_performance_benchmark(), True)[1], ()),
    ]:
        try:
            ok = fn(*args)
            results[name] = "PASS" if ok else "FAIL"
        except AssertionError as e:
            results[name] = f"BREACH: {e}"
        except Exception as e:
            results[name] = f"ERROR: {e}"
            import traceback
            traceback.print_exc()

    print(f"\n{'='*60}")
    print("  Attack Scenario Summary")
    print(f"{'='*60}")
    for name, result in results.items():
        icon = "[BLOCKED]" if result == "PASS" else "[BREACH]"
        print(f"  {icon} {name}: {result}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    run_all_attacks()

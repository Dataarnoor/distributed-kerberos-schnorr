"""
run_demo.py
Demo orchestrator -- starts all servers, runs the full Kerberos demo,
then runs all attack scenarios.

Usage:
    python run_demo.py
"""

import subprocess
import sys
import time
import os
import socket

PYTHON = sys.executable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(SCRIPT_DIR, "keys")
WAIT_READY = 5  # seconds to wait for servers to bind


def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(host: str, port: int, label: str, retries: int = 20) -> bool:
    for i in range(retries):
        if check_port(host, port):
            print(f"  [demo] {label} ready on port {port}")
            return True
        time.sleep(0.3)
    print(f"  [demo] WARNING: {label} did not come up on port {port}")
    return False


def run_keygen():
    if os.path.isdir(KEYS_DIR) and os.path.exists(os.path.join(KEYS_DIR, "public_keys.json")):
        print("[demo] Keys already exist -- skipping keygen")
        return
    print("[demo] Running master_keygen.py ...")
    subprocess.run([PYTHON, "master_keygen.py"], check=True, cwd=SCRIPT_DIR)


def start_servers():
    processes = []

    configs = [
        (["as_node.py",        "1"], 5001, "AS1"),
        (["as_node.py",        "2"], 5002, "AS2"),
        (["as_node.py",        "3"], 5003, "AS3"),
        (["tgs_node.py",       "1"], 5011, "TGS1"),
        (["tgs_node.py",       "2"], 5012, "TGS2"),
        (["tgs_node.py",       "3"], 5013, "TGS3"),
        (["service_server.py", "service1"], 5021, "Service1"),
        (["service_server.py", "service2"], 5022, "Service2"),
    ]

    print("[demo] Starting all server processes ...")
    for args, port, label in configs:
        p = subprocess.Popen(
            [PYTHON] + args,
            cwd=SCRIPT_DIR,
        )
        processes.append((p, label, port))
        print(f"  [demo] Launched {label} (pid={p.pid})")
        time.sleep(0.3)

    print(f"\n[demo] Waiting {WAIT_READY}s for servers to initialize ...")
    time.sleep(WAIT_READY)

    all_ready = True
    for p, label, port in processes:
        if not wait_for_port("127.0.0.1", port, label):
            all_ready = False

    return [p for p, _, _ in processes], all_ready


def stop_servers(processes):
    print("\n[demo] Stopping all server processes ...")
    for p in processes:
        try:
            p.terminate()
        except Exception:
            pass
    for p in processes:
        try:
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    print("[demo] All servers stopped.")


def main():
    print("+======================================================+")
    print("|  Kerberos Under Partial Compromise                    |")
    print("|  Schnorr Multi-Signature Demo                         |")
    print("+======================================================+")

    # Step 1: Generate keys
    run_keygen()

    # Step 2: Start all servers
    processes, all_ready = start_servers()

    if not all_ready:
        print("\n[demo] WARNING: Some servers did not start. Continuing anyway...")

    try:
        # Step 3: Run attacks (standalone, no servers needed)
        print("\n" + "="*55)
        print("  [demo] Running attack scenario demonstrations ...")
        print("="*55)
        subprocess.run([PYTHON, "attacks.py"], check=True, cwd=SCRIPT_DIR)

        # Step 4: Run full client demo
        print("\n" + "="*55)
        print("  [demo] Running full Kerberos client flow ...")
        print("="*55)

        for user, pwd, svc in [
            ("alice", "alice_password", "service1"),
            ("bob",   "bob_password",   "service2"),
        ]:
            print(f"\n  [demo] --- Client: {user} -> {svc} ---")
            result = subprocess.run(
                [PYTHON, "client.py", user, pwd, svc],
                check=False,
                cwd=SCRIPT_DIR,
            )
            if result.returncode != 0:
                print(f"  [demo] Client returned non-zero exit code")

        # Step 5: Performance analysis
        print("\n" + "="*55)
        print("  [demo] Performance Analysis Summary")
        print("="*55)
        print("""
  Schnorr Operations (1024-bit group, 160-bit subgroup):
    - Key generation:        O(log q) modular multiplications
    - Signing (per auth):    2 modular exponentiations + hash
    - Verification:          2 modular exponentiations + hash
    - Multi-sig (2-of-3):    up to 6 modular exponentiations

  Protocol Overhead vs Classical Kerberos:
    - Phase 1 (AS):          3x round-trips instead of 1
    - Phase 2 (TGS):         3x round-trips instead of 1
    - Ticket size:           larger (2-3 signatures included)
    - Verification:          2-3 Schnorr verifications per ticket

  Security Gain:
    - Classical Kerberos:    1 compromised AS -> full system compromise
    - This system:           1 compromised AS -> no security impact
    - Requires 2+ compromised authorities to forge tickets
        """)

    finally:
        stop_servers(processes)

    print("\n[demo] Demo complete.")


if __name__ == "__main__":
    main()
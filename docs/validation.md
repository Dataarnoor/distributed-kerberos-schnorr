# Validation

Checked on 16 October 2026 with Python 3.13.9 on Linux.

Commands: `python3 attacks.py` and `python3 run_demo.py`.

- All six standalone attack/policy demonstrations reported PASS.
- The deliberate nonce-reuse key recovery demonstration reported PASS.
- The performance benchmark completed.
- All three AS nodes, three TGS nodes, and two service servers became ready on loopback ports.
- Alice authenticated to service1 and Bob authenticated to service2; both clients reported SUCCESS.
- The orchestrator completed and stopped its server processes.

The first full-demo attempt could not open sockets inside the execution sandbox. The full demo was subsequently rerun with local socket access and passed. Standalone attack checks do not require sockets.

All Python files parsed successfully. Source files match the original project copy. The generated `keys/` directory and bytecode are excluded from Git. These checks validate the supplied demonstrations, not production security.

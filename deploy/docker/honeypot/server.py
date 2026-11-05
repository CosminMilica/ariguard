"""A deliberately-vulnerable honeypot server (F11 discovery).

It is a decoy: only an attacker has a reason to touch it, so every command it runs is attack
behavior by definition. Each injected command is executed under ``strace -ff`` so the full syscall
sequence of the attack is written to a shared volume; a capture sidecar parses those into
attack-labeled traces and POSTs them to the console, where the rule-generation loop mines them for
new kill-chains. Run ONLY on an isolated cluster.
"""

import os
import subprocess
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

# The 16 syscalls AriGuard hooks; strace captures exactly these so traces match the rule ABI.
HOOKS = (
    "openat,connect,execve,execveat,setns,unshare,mount,fsmount,move_mount,"
    "ptrace,dup2,dup3,memfd_create,init_module,finit_module,bpf"
)
TRACES = os.environ.get("TRACE_DIR", "/traces")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path != "/exec":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"honeypot\n")
            return
        cmd = urllib.parse.parse_qs(q.query).get("cmd", [""])[0]
        out = b"ok\n"
        if cmd:
            # command injection by design: run it under strace so the attack's syscalls are captured.
            try:
                # -f (follow, single file) keeps the whole session time-ordered across processes,
                # so a cross-process chain (unshare in one child, mount in the next) stays together.
                sess = f"{TRACES}/sess-{int(time.time() * 1000)}"
                r = subprocess.run(
                    ["strace", "-f", "-qq", "-e", f"trace={HOOKS}", "-o", sess, "sh", "-c", cmd],
                    capture_output=True, timeout=15,
                )
                out = r.stdout or b"ok\n"
            except Exception as e:  # noqa: BLE001 — honeypot, never crash on a bad payload
                out = str(e).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(out)


if __name__ == "__main__":
    print(f"honeypot on :8080, traces -> {TRACES}", flush=True)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

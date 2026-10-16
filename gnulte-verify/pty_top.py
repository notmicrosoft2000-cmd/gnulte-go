#!/usr/bin/env python3
"""PTY render-check for gnulte-top (v16.11).

Only a real terminal proves the live full-screen view paints and that 'q'
reaches the loop. In the sandbox the AF_PACKET counter is unavailable, so the
rates are all zero; the view must still render, show the measuring/empty state,
and exit cleanly on q.
"""
import os
import pty
import re
import select
import signal
import subprocess
import sys
import time

BIN = sys.argv[1] if len(sys.argv) > 1 else "/tmp/opencode/gnulte-top"
ANSI = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[()][A-Z0-9]|\x1b[=>]|\r")


def strip(b: bytes) -> str:
    return ANSI.sub(b"", b).decode("utf-8", "replace")


def run(args, send_after, keys):
    master, slave = pty.openpty()
    env = dict(os.environ, GNULTE_AS_ROOT="1", TERM="xterm-256color")
    p = subprocess.Popen([BIN, *args], stdin=slave, stdout=slave, stderr=slave,
                         env=env, close_fds=True)
    os.close(slave)
    buf = b""
    deadline = time.time() + send_after
    sent = False
    end = time.time() + send_after + 4
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.2)
        if master in r:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        if not sent and time.time() >= deadline:
            os.write(master, keys)
            sent = True
        if p.poll() is not None:
            break
    if p.poll() is None:
        p.send_signal(signal.SIGKILL)
        p.wait()
        return strip(buf), -9
    return strip(buf), p.returncode


def main():
    text, code = run(["-i", "1"], 2.6, b"q")
    ok = True
    if "GNULTE TOP" not in text:
        print("FAIL: title not rendered"); ok = False
    # Either the first frame's measuring state or the first sampled frame.
    if "measuring" not in text and "no host traffic" not in text:
        print("FAIL: neither the measuring nor the empty-traffic state rendered"); ok = False
    if code != 0:
        print(f"FAIL: exit code {code}, want 0 on q"); ok = False
    if ok:
        print("PASS: gnulte-top rendered the live view and quit cleanly on q")
    else:
        print("--- captured output ---")
        print(text[-2000:])
        sys.exit(1)


if __name__ == "__main__":
    main()

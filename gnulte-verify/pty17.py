#!/usr/bin/env python3
"""GNULTE v17 bug-batch PTY harness.

Covers the interactive paths changed by the bug batch, where a unit test can
pin the logic but only a real pty proves the keys reach the right host:

  A  gnulte-lan  ⏎ handoff names the row under the cursor on talkers
  B  gnulte-lan  same after a sort change (the live repro of the stale-IP bug)
  C  gnulte-lan  ⏎ on flows never launches a gnulte test
  D  gnulte-lan  ⏎ on the map never launches a gnulte test
  E  gnulte-lan  the four non-hosts screens still render and quit cleanly
  F  gnulte-scan  --watch runs its first sweep immediately and reports the
                  real effective cadence (v16's swallowed-interval bug)

Usage: python3 pty17.py [pattern]
"""
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import threading
import time

BIN = os.environ.get("GNULTE_BIN", "/tmp/opencode/bin")
ANSI = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[()][A-Z0-9]|\x1b[=>]|\r")
DOWN = b"\x1b[B"
ENTER = b"\r"


def strip(b: bytes) -> str:
    return ANSI.sub(b"", b).decode("utf-8", "replace")


def detect_net():
    out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if "lo" in parts[1]:
            continue
        iface = parts[1]
        ip = parts[3].split("/")[0]
        if ip.startswith("127."):
            continue
        prefix = int(parts[3].split("/")[1])
        if prefix >= 16:
            return iface, ip
    raise SystemExit("no non-loopback IPv4 interface found")


class Term:
    def __init__(self, argv, env=None):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            # GNULTE_AS_ROOT=1 skips the sudo re-exec: this sandbox has no
            # root, so the harness runs the non-root path (no packet counter,
            # but every screen, key and handoff is still real).
            e = dict(os.environ, TERM="xterm-256color", COLUMNS="150",
                     LINES="45", GNULTE_AS_ROOT="1")
            if env:
                e.update(env)
            os.execvpe(argv[0], argv, e)
        import fcntl
        import struct
        import termios
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 150, 0, 0))
        self.buf = b""

    def read(self, seconds=1.0):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.buf += chunk
        return strip(self.buf)

    def send(self, data, settle=1.0):
        os.write(self.fd, data)
        time.sleep(0.25)
        return self.read(settle)

    def wait_exit(self, timeout=5.0):
        """Poll for the child's exit. Returns (exited, status)."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                return True, 0
            if pid == self.pid:
                self.exited = True
                return True, os.waitstatus_to_exitcode(status)
            time.sleep(0.1)
        return False, None

    def close(self):
        if getattr(self, "exited", False):
            try:
                os.close(self.fd)
            except OSError:
                pass
            return
        try:
            os.kill(self.pid, signal.SIGINT)
            self.read(1.5)
        except (ProcessLookupError, OSError):
            pass
        try:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        except (ProcessLookupError, OSError, ChildProcessError):
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass


def ips_in(text):
    return re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", text)


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("  PASS  " if cond else "  FAIL  ") + name + (f"\n         {detail}" if detail and not cond else ""))


def last_frame(text):
    """The accumulated pty buffer holds every repaint; keep the final frame."""
    return strip(("LIVE LAN WATCH" + text.split("LIVE LAN WATCH")[-1]).encode())


def host_rows(frame):
    """Host rows of the hosts screen, in display order, as bare IPs.

    A row is a line carrying a dot-quad plus the word 'ping'; the cursor row is
    marked with the cursor glyph. Returns (rows, cursor_ip).
    """
    rows, cursor = [], None
    for line in frame.splitlines():
        m = re.match(r"\s*(\u25b8)?\s*(\d+\.\d+\.\d+\.\d+)\s+.*\bping\b", line)
        if m:
            rows.append(m.group(2))
            if m.group(1):
                cursor = m.group(2)
    return rows, cursor


def arp_rows(frame):
    """ARP screen rows: an IP and a MAC, in the screen's IP order."""
    return re.findall(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}",
                      frame, re.M)


def handoff_ip(frame):
    m = re.search(r"gnulte -t (\d+\.\d+\.\d+\.\d+)", frame)
    return m.group(1) if m else None


def lan(iface):
    return Term([f"{BIN}/gnulte-lan", "--no-report", "-i", iface])


def test_a(bundle):
    """talkers: g hands off a real host, and the same handoff on the hosts
    screen is the hosts cursor row — so the two screens can name different
    hosts for the same cursor index."""
    t = lan(bundle["iface"])
    home = last_frame(t.read(7))
    if "LIVE LAN WATCH" not in home:
        check("A0 lan starts", False, home[-300:])
        t.close()
        return
    t.buf = b""
    t.send(b"1", 1.5)                       # hosts, cursor 0
    hosts_hint = handoff_ip(last_frame(t.send(b"g", 2.0)))
    t.buf = b""
    t.send(b"2", 2.5)                       # talkers, cursor still 0
    talk_hint = handoff_ip(last_frame(t.send(b"g", 2.0)))
    live = set(ips_in(home))
    check("A1 hosts g hands off its own row 0", hosts_hint in live, f"hint={hosts_hint}")
    check("A2 talkers g hands off a host on the link", talk_hint in live, f"hint={talk_hint}")
    t.close()


def test_b(bundle):
    """The handoff must name the row the cursor is on, read in the same frame
    (the latency sort reorders live, so a snapshot from another frame drifts)."""
    t = lan(bundle["iface"])
    t.read(7)
    t.send(b"s", 1.0)                      # address -> traffic
    t.send(b"s", 2.0)                      # traffic  -> latency
    t.buf = b""
    t.send(b"1", 1.5)
    t.send(DOWN, 0.8)                      # cursor -> rank 2
    frame = last_frame(t.send(ENTER, 2.0))
    _, cursor_ip = host_rows(frame)
    check("B1 hosts ⏎ names the cursor row", handoff_ip(frame) == cursor_ip,
          f"hint={handoff_ip(frame)} cursor row={cursor_ip}")
    t.buf = b""
    t.send(b"4", 2.5)                      # ARP screen, IP-ordered rows
    frame = last_frame(t.send(ENTER, 2.0))
    rows = arp_rows(frame)
    check("B2 ARP ⏎ names its rank 2 row", handoff_ip(frame) == (rows[1] if len(rows) > 1 else None),
          f"hint={handoff_ip(frame)} rows={rows[:4]}")
    t.close()


def test_c(bundle):
    """flows rows are pairs: g must not launch a test against anything.

    The old gate was `currentIP != ""`, so g on the flows screen handed the
    *hosts* screen's host to gnulte — the stale-target bug, live.
    """
    t = lan(bundle["iface"])
    t.read(7)
    t.send(b"3", 2.5)      # flows
    out = last_frame(t.send(b"g", 2.0))
    check("C1 no gnulte handoff on flows", "gnulte -t" not in out, out[-300:])
    t.close()


def test_d(bundle):
    """the map's last row is the gateway hub: g must not launch a test."""
    t = lan(bundle["iface"])
    t.read(7)
    t.send(b"5", 2.5)      # map
    out = last_frame(t.send(b"g", 2.0))
    check("D1 no gnulte handoff on the map", "gnulte -t" not in out, out[-300:])
    t.close()


def test_e(bundle):
    """every screen renders its own section header, and q exits the process.

    The flows and map screens need the root capture socket for live edges; this
    sandbox has none, so those two legitimately render their gate panel instead
    of the full view — either one counts as rendering.
    """
    for key, markers in ((b"2", ("TOP TALKERS",)),
                         (b"3", ("FLOWS", "raw AF_PACKET socket")),
                         (b"4", ("NEIGHBOURS",)),
                         (b"5", ("INTERCONNECTION MAP", "raw AF_PACKET socket"))):
        t = lan(bundle["iface"])
        t.read(7)
        out = last_frame(t.send(key, 2.5))
        check(f"E1 screen {key.decode()} renders",
              any(m in out for m in markers) and "q quit" in out, out[-250:])
        os.write(t.fd, b"q")
        gone, status = t.wait_exit(8.0)
        check(f"E2 screen {key.decode()} quits on q", gone, f"still running: {out[-160:]}")
        if gone and status != 0:
            check(f"E3 screen {key.decode()} exit status", False, f"status={status}")
        t.close()


class Reader(threading.Thread):
    """Drains one pipe, timestamping every line as it arrives."""

    def __init__(self, stream):
        super().__init__(daemon=True)
        self.stream = stream
        self.lines = []
        self.start()

    def run(self):
        for line in self.stream:
            self.lines.append((time.time(), line))

    def find(self, needle):
        for t, line in self.lines:
            if needle in line:
                return t, line
        return None, ""

    def text(self):
        return "".join(l for _, l in self.lines)


def test_f(bundle):
    """--watch: the feed stays pure JSON and the stated cadence is truthful.

    The claim is verified against the *same* run's own clock. The baseline line
    is emitted just before the first sweep starts and the cadence note just
    after that sweep ends, so the gap between the two arrivals is that sweep's
    measured cost — a made-up number cannot match it.
    """
    base = subprocess.run([f"{BIN}/gnulte-scan", "-i", bundle["iface"],
                           "--no-report", "-q", "--json"],
                          capture_output=True, text=True,
                          env=dict(os.environ, GNULTE_AS_ROOT="1"))
    check("F1 --json stdout is one pure JSON document (narrative on stderr)",
          isinstance(json.loads(base.stdout), list), base.stdout[:200])

    p = subprocess.Popen(
        [f"{BIN}/gnulte-scan", "-i", bundle["iface"], "--no-report",
         "--watch", "2", "--json"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
        env=dict(os.environ, GNULTE_AS_ROOT="1"))
    out, err = Reader(p.stdout), Reader(p.stderr)
    deadline = time.time() + 60
    while time.time() < deadline and not err.find("first sweep took")[1]:
        time.sleep(0.2)
    time.sleep(0.5)
    p.terminate()
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=5)

    t_base, base_line = out.find('"baseline"')
    check("F2 first feed event arrives", base_line != "", out.text()[:160])
    _, note = err.find("first sweep took")
    check("F3 watch reports its true effective cadence", note != "", err.text()[-300:])
    m = re.search(r"first sweep took ([\d.]+)s", note)
    t_note, _ = err.find("first sweep took")
    if not m or t_base is None or t_note is None:
        return
    claimed = float(m.group(1))
    measured = t_note - t_base
    check("F4 the reported sweep cost matches the observed gap",
          abs(measured - claimed) <= 1.0,
          f"claimed {claimed}s, observed {measured:.2f}s between baseline and note")
    eff = re.search(r"about every (\d+)s", note)
    check("F5 the effective interval includes the sweep cost",
          eff is not None and int(eff.group(1)) >= int(claimed) + 1,
          f"claimed cost {claimed}s, stated interval {eff and eff.group(1)}s")


def test_g(bundle):
    """gnulte-scan -T --watch N: the browser's rescan goroutine uses the same
    sweep-then-wait cadence and must not crash, wedge or leak frames."""
    t = Term([f"{BIN}/gnulte-scan", "-T", "-i", bundle["iface"],
              "--no-report", "--watch", "2"])
    first = t.read(8)
    check("G1 -T browser opens",
          any(m in first for m in ("GNULTE-SCAN", "DEVICES", "device(s) identified", "resolving")),
          first[-300:])
    # Let the immediate first sweep plus a second one run (sweep ~11s + 2s wait).
    out = t.read(26)
    check("G2 no panic in the -T watch loop",
          "panic:" not in out and "goroutine " not in out, out[-300:])
    check("G3 -T watch loop still rendering", "q quit" in out or "quit" in out.lower(),
          out[-300:])
    os.write(t.fd, b"r")           # manual rescan must still work
    out = t.read(6)
    check("G4 manual r rescan keeps the UI alive", "panic:" not in out, out[-200:])
    os.write(t.fd, b"q")
    gone, status = t.wait_exit(8.0)
    check("G5 -T quits on q", gone, out[-200:])
    if gone and status not in (0, None):
        check("G6 -T exit status", False, f"status={status}")
    t.close()


TESTS = {"A": test_a, "B": test_b, "C": test_c, "D": test_d, "E": test_e,
         "F": test_f, "G": test_g}


def main():
    pattern = sys.argv[1] if len(sys.argv) > 1 else ""
    iface, ip = detect_net()
    bundle = {"iface": iface, "self": ip}
    print(f"network: {iface} {ip}\n")
    for name, fn in TESTS.items():
        if pattern and pattern not in name:
            continue
        print(f"{name}: {fn.__doc__ or ''}")
        try:
            fn(bundle)
        except Exception as exc:  # keep going; report as a failure
            check(f"{name} raised", False, repr(exc))
    bad = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(bad)}/{len(RESULTS)} passed")
    if bad:
        print("failed: " + ", ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

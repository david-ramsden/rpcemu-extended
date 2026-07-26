#!/usr/bin/env python3
"""
Boot a machine headlessly and check that RISC OS actually reaches a desktop.

Everything else in CI stops at "the binary starts and parses its arguments".
This drives a real boot instead: it starts the emulator with --headless, waits
for the built-in VNC server to accept a connection, captures the framebuffer
over RFB, and checks the result looks like a booted machine rather than a blank
or frozen screen. That exercises the CPU, memory, VIDC, ROM loading and the VNC
server end to end, on whichever platform the job runs.

The RFB handling mirrors tools/mcp/rpcemu_mcp.py (RFB 3.3, security None, Raw
encoding, 32bpp true colour) so there is one protocol implementation to reason
about, not two.

Usage:
  vnc_smoke.py --binary <path> [--machine Default] [--port 5900]
               [--boot-timeout 180] [--save shot.png]

Exit status is 0 when the machine booted and the screen looked plausible, and 1
otherwise, with the reason on stderr.
"""

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zlib


class SmokeError(Exception):
    pass


# ---------------------------------------------------------------------------
# RFB client (subset of tools/mcp/rpcemu_mcp.py)
# ---------------------------------------------------------------------------


def _recvn(s: socket.socket, n: int, what: str) -> bytes:
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise SmokeError(f"VNC connection closed during {what}")
        b += c
    return b


def vnc_capture(host: str, port: int) -> tuple[int, int, bytearray]:
    """Connect, grab one framebuffer update, return (width, height, RGBX bytes)."""
    s = socket.create_connection((host, port), timeout=15)
    s.settimeout(30)
    try:
        _recvn(s, 12, "handshake")  # server "RFB 003.00x\n"
        s.sendall(b"RFB 003.003\n")
        (sec,) = struct.unpack(">I", _recvn(s, 4, "handshake"))
        if sec == 0:
            (n,) = struct.unpack(">I", _recvn(s, 4, "handshake"))
            raise SmokeError("VNC rejected us: " + _recvn(s, n, "handshake").decode("latin-1"))
        if sec != 1:
            raise SmokeError(f"VNC wants authentication (security type {sec}); the test config must have no password")

        s.sendall(b"\x01")  # ClientInit, shared
        w, h = struct.unpack(">HH", _recvn(s, 4, "server init"))
        _recvn(s, 16, "pixel format")
        (nl,) = struct.unpack(">I", _recvn(s, 4, "desktop name"))
        _recvn(s, nl, "desktop name")

        if w == 0 or h == 0:
            raise SmokeError(f"VNC reported a {w}x{h} framebuffer")

        # 32bpp true colour, little-endian, shifts 0/8/16 so pixels arrive as
        # [R, G, B, x] - the order the PNG encoder below expects.
        spf = (
            struct.pack(">BBBB", 0, 0, 0, 0)
            + struct.pack(">BBBB", 32, 24, 0, 1)
            + struct.pack(">HHH", 255, 255, 255)
            + struct.pack(">BBB", 0, 8, 16)
            + b"\x00\x00\x00"
        )
        s.sendall(spf)
        s.sendall(struct.pack(">BBH", 2, 0, 1) + struct.pack(">i", 0))  # SetEncodings: Raw
        s.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, w, h))  # FramebufferUpdateRequest

        mt = _recvn(s, 1, "message type")[0]
        while mt != 0:  # skip anything that is not a FramebufferUpdate
            if mt == 1:
                _recvn(s, 5, "colour map")
            elif mt == 3:
                _recvn(s, 7, "cut text")
            else:
                raise SmokeError(f"unexpected VNC message type {mt}")
            mt = _recvn(s, 1, "message type")[0]

        _recvn(s, 1, "padding")
        (nrect,) = struct.unpack(">H", _recvn(s, 2, "rect count"))
        fb = bytearray(w * h * 4)
        for _ in range(nrect):
            x, y, rw, rh, enc = struct.unpack(">HHHHi", _recvn(s, 12, "rect header"))
            if enc != 0:
                raise SmokeError(f"VNC used encoding {enc}; only Raw is handled")
            data = _recvn(s, rw * rh * 4, "rect data")
            for row in range(rh):
                src = row * rw * 4
                dst = ((y + row) * w + x) * 4
                fb[dst : dst + rw * 4] = data[src : src + rw * 4]
        return w, h, fb
    finally:
        s.close()


def encode_png(w: int, h: int, fb: bytearray) -> bytes:
    """Minimal RGB PNG, so a failing run can upload what it saw."""
    raw = bytearray()
    for y in range(h):
        raw.append(0)  # filter: none
        row = fb[y * w * 4 : (y + 1) * w * 4]
        for x in range(w):
            raw += row[x * 4 : x * 4 + 3]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + chunk(b"IEND", b"")
    )


# ---------------------------------------------------------------------------
# Screen plausibility
# ---------------------------------------------------------------------------


def describe_screen(w: int, h: int, fb: bytearray) -> tuple[bool, str]:
    """
    Decide whether this looks like a booted desktop.

    Deliberately loose: asserting on exact pixels would break on any cosmetic
    change to RISC OS, the ROM or the mode. A booted desktop has a background,
    an icon bar and window furniture, so it has many distinct colours spread
    over the screen. A machine that never got going gives a uniform screen (all
    black, or one flat colour).
    """
    step = max(1, (w * h) // 20000)  # sample ~20k pixels, enough to judge
    colours: dict[tuple[int, int, int], int] = {}
    total = 0
    for i in range(0, w * h, step):
        px = (fb[i * 4], fb[i * 4 + 1], fb[i * 4 + 2])
        colours[px] = colours.get(px, 0) + 1
        total += 1

    if total == 0:
        return False, "no pixels sampled"

    distinct = len(colours)
    top_px, top_n = max(colours.items(), key=lambda kv: kv[1])
    dominant = top_n / total

    summary = (
        f"{w}x{h}, {distinct} distinct colours in {total} sampled pixels, "
        f"most common {top_px} covering {dominant:.1%}"
    )

    if distinct < 8:
        return False, f"screen looks blank or unrendered ({summary})"
    if dominant > 0.995:
        return False, f"screen is essentially one colour ({summary})"
    return True, summary


# ---------------------------------------------------------------------------
# Driving the emulator
# ---------------------------------------------------------------------------


def make_test_config(src_cfg: str, dst_cfg: str, port: int) -> None:
    """
    Copy the machine config with the VNC server switched on.

    The shipped Default.cfg has vnc_enabled=0, and headless mode refuses to
    start without it. The tracked config is left alone: CI should not depend on
    mutating a file that is also a user-facing default.
    """
    with open(src_cfg, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    def set_key(t: str, key: str, value: str) -> str:
        pat = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
        if pat.search(t):
            return pat.sub(f"{key}={value}", t)
        return t.rstrip("\n") + f"\n{key}={value}\n"

    text = set_key(text, "vnc_enabled", "1")
    text = set_key(text, "vnc_port", str(port))
    text = set_key(text, "vnc_password", "")

    with open(dst_cfg, "w", encoding="utf-8") as f:
        f.write(text)


def wait_for_port(host: str, port: int, proc: subprocess.Popen, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SmokeError(f"the emulator exited early with status {proc.returncode}")
        try:
            with socket.create_connection((host, port), timeout=2):
                return
        except OSError:
            time.sleep(1)
    raise SmokeError(f"the VNC server did not accept a connection within {timeout:.0f}s")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, help="emulator to run")
    ap.add_argument("--machine", default="Default", help="machine config name")
    ap.add_argument("--port", type=int, default=5900, help="VNC port to use")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--boot-timeout", type=float, default=180.0,
                    help="seconds to wait for the VNC server to come up")
    ap.add_argument("--settle", type=float, default=25.0,
                    help="seconds to let RISC OS finish drawing after VNC accepts")
    ap.add_argument("--save", help="write the captured screen here as a PNG")
    args = ap.parse_args()

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        print(f"error: no such binary: {binary}", file=sys.stderr)
        return 1

    # Run from the release directory so configs/, roms/ and machines/ resolve
    # the way they do for a user running the staged build.
    workdir = os.path.dirname(binary)
    configs = os.path.join(workdir, "configs")
    src_cfg = os.path.join(configs, f"{args.machine}.cfg")
    if not os.path.isfile(src_cfg):
        print(f"error: no config at {src_cfg}", file=sys.stderr)
        return 1

    test_name = f"{args.machine}-vncsmoke"
    test_cfg = os.path.join(configs, f"{test_name}.cfg")
    make_test_config(src_cfg, test_cfg, args.port)

    # The machine directory is keyed by the config's "name" field, so the test
    # machine gets its own - seeded from the real one so it has the same CMOS
    # and HostFS starting point.
    machines = os.path.join(workdir, "machines")
    src_machine = os.path.join(machines, args.machine)
    dst_machine = os.path.join(machines, test_name)
    if os.path.isdir(src_machine) and not os.path.isdir(dst_machine):
        shutil.copytree(src_machine, dst_machine)

    env = dict(os.environ)
    env["RPCEMU_NO_GUI_MESSAGES"] = "1"

    log = tempfile.NamedTemporaryFile(prefix="vnc-smoke-", suffix=".log", delete=False)
    print(f"==> starting {binary} --headless --machine {test_name}", flush=True)
    proc = subprocess.Popen(
        [binary, "--headless", "--machine", test_name],
        cwd=workdir, env=env, stdout=log, stderr=subprocess.STDOUT,
    )

    rc = 1
    try:
        wait_for_port(args.host, args.port, proc, args.boot_timeout)
        print(f"==> VNC accepted on {args.host}:{args.port}; "
              f"letting RISC OS settle for {args.settle:.0f}s", flush=True)
        # The server accepts as soon as it is listening, which is well before
        # the desktop is drawn. Give the guest time to get there.
        time.sleep(args.settle)

        w, h, fb = vnc_capture(args.host, args.port)
        if args.save:
            with open(args.save, "wb") as f:
                f.write(encode_png(w, h, fb))
            print(f"==> wrote {args.save}", flush=True)

        ok, summary = describe_screen(w, h, fb)
        if ok:
            print(f"PASS: {summary}", flush=True)
            rc = 0
        else:
            print(f"FAIL: {summary}", file=sys.stderr, flush=True)
    except SmokeError as e:
        print(f"FAIL: {e}", file=sys.stderr, flush=True)
    except OSError as e:
        print(f"FAIL: {e}", file=sys.stderr, flush=True)
    finally:
        if proc.poll() is None:
            proc.terminate()  # SIGTERM: headless saves CMOS and discs on this
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        log.close()
        with open(log.name, "r", encoding="utf-8", errors="replace") as f:
            output = f.read().strip()
        if output:
            print("--- emulator output ---", flush=True)
            print(output, flush=True)
        os.unlink(log.name)

    return rc


if __name__ == "__main__":
    sys.exit(main())

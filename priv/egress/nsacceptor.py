#!/usr/bin/env python3
"""The listener that lives inside one sandbox's network namespace (005 T060a3).

Started from the host with `nsenter -t <holder> -n -U --preserve-credentials`,
because a socket's network namespace is fixed at the moment of the syscall by
the namespace of the calling process -- the BEAM never enters the sandbox's
netns, so no option to `:gen_tcp.listen/2` could put a listener there.

⚠️ THIS PROCESS HOLDS NO POLICY. It reads the true destination the tenant asked
for and asks the platform for a verdict over an AF_UNIX socket. Giving it a copy
of the allowlist would work, pass every check, and place the policy one process
away from the tenant -- inside the blast radius the acceptor exists to bound.
Measured: AF_UNIX crosses the netns boundary, and the tenant cannot see the path
at all (ENOENT, not EACCES) because `bwrap` never binds it into its mount view.
See `egress-path-measurements.md`.

⚠️ EVERY ERROR PATH CLOSES THE CONNECTION. This is the one component in the
subsystem where the natural bug goes the unsafe way: code that forwards when
something unexpected happened is a boundary that stops enforcing exactly when
it is malfunctioning. There is no path here where a failure yields more
reachability than a success -- no retry, no fallback destination, no "allow on
timeout".
"""
import errno
import os
import socket
import struct
import sys
import threading

# SO_ORIGINAL_DST. `socket.SOL_IP` is the correct option level; an earlier probe
# used 80 for both level and option and raised OSError [Errno 95], which reads
# exactly like a kernel that does not support the call.
SO_ORIGINAL_DST = 80

CONNECT_TIMEOUT = 5.0
VERDICT_TIMEOUT = 5.0
IDLE_TIMEOUT = 120.0
BUF = 65536


def original_destination(conn):
    """The address the tenant actually asked for, recovered from the redirect.

    Returns None when it cannot be read. ⚠️ None must never be treated as
    "allow": a connection whose destination is unknown cannot be checked
    against an allowlist, so it is refused.
    """
    try:
        raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    except OSError:
        return None
    port, = struct.unpack_from("!H", raw, 2)
    host = socket.inet_ntoa(raw[4:8])
    return host, port


def ask_platform(verdict_path, source_key, host, port):
    """Ask the BEAM whether this sandbox may reach this destination.

    ⚠️ Any failure to obtain a verdict is a refusal. A platform that cannot be
    reached, answers late, or answers something unrecognised must not widen the
    boundary -- "fail open on error" here would make an unreachable supervisor
    indistinguishable from a permissive allowlist.
    """
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(VERDICT_TIMEOUT)
        s.connect(verdict_path)
        s.sendall(("%s %s %d\n" % (source_key, host, port)).encode())
        answer = s.recv(64).decode(errors="replace").strip()
        s.close()
    except OSError:
        return False
    return answer == "PERMIT"


def splice(a, b):
    """Carry bytes one way until either side ends, then shut the pair down.

    A half-duplex relay forwards the request and drops the response, which from
    inside the sandbox reads as a slow destination rather than a broken proxy --
    and passes every denial check. Both directions run; either ending tears down
    both.
    """
    try:
        while True:
            data = a.recv(BUF)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (a, b):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(conn, verdict_path, source_key):
    dest = original_destination(conn)
    if dest is None:
        conn.close()
        return
    host, port = dest

    if not ask_platform(verdict_path, source_key, host, port):
        conn.close()
        return

    try:
        upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except OSError:
        conn.close()
        return

    conn.settimeout(IDLE_TIMEOUT)
    upstream.settimeout(IDLE_TIMEOUT)
    threading.Thread(target=splice, args=(conn, upstream), daemon=True).start()
    threading.Thread(target=splice, args=(upstream, conn), daemon=True).start()


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("usage: nsacceptor.py <port> <verdict-socket> <source-key>\n")
        return 2
    port = int(sys.argv[1])
    verdict_path = sys.argv[2]
    source_key = sys.argv[3]

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # ⚠️ Binds 0.0.0.0, not 127.0.0.1. A `redirect` rewrites the destination to a
    # local address, but the packet arrives on the namespace's own interface
    # rather than on loopback -- measured `peer=('172.19.0.4', 48160)`. A
    # loopback-only bind misses every connection while looking correct.
    #
    # This is safe *because of* where it binds: the namespace holds exactly one
    # tenant and nothing else can route to it, so 0.0.0.0 here is narrower than
    # 127.0.0.1 on the host.
    srv.bind(("0.0.0.0", port))
    srv.listen(128)
    sys.stdout.write("ACCEPTOR listening %d\n" % port)
    sys.stdout.flush()

    while True:
        try:
            conn, _peer = srv.accept()
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            return 1
        # ⚠️ The peer address is deliberately unused. This acceptor serves ONE
        # namespace and nothing else can reach it, so the sandbox's identity is
        # the acceptor's own existence. Reading identity off the connection
        # would consult a value the tenant partly controls to answer a question
        # already answered by connecting at all.
        threading.Thread(
            target=handle, args=(conn, verdict_path, source_key), daemon=True
        ).start()


if __name__ == "__main__":
    sys.exit(main())

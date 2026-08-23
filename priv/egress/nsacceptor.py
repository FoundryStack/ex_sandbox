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

⚠️ IT ALSO CARRIES DNS, AND FOR THE SAME REASON IT CARRIES TCP (029 T015).
A socket's network namespace is fixed by the namespace of the calling process,
so a UDP listener the sandbox can reach has to be created from in here. It
holds no resolver either: it relays the query bytes to the platform over a
second AF_UNIX socket and writes back whatever the platform answers. The
platform is what resolves, what applies FR-015 to the answers, and what records
the name->address binding the verdict later consults -- see
`ExSandbox.Egress.Resolver`.

⚠️ A DNS RELAY FAILURE IS SILENCE, NEVER A SYNTHESISED ANSWER. Answering from
here would mean inventing a name-to-address mapping the platform never made and
never recorded, and a tenant acting on it would connect to an address no
allowlist entry can match. A dropped datagram is what an unavailable resolver
looks like on the wire, and the client retries.
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

# Must match `ExSandbox.Egress.Netns.acceptor_mark/0`. ⚠️ If these drift, the
# acceptor's upstream stops being exempt and it re-enters its own redirect --
# a loop whose only symptom is permitted destinations timing out.
ACCEPTOR_MARK = 42
SO_MARK = 36  # SOL_SOCKET option; not exposed as socket.SO_MARK on all builds

CONNECT_TIMEOUT = 5.0
VERDICT_TIMEOUT = 5.0
IDLE_TIMEOUT = 120.0
BUF = 65536

# A DNS message over UDP without EDNS0 is at most 512 bytes; the platform's
# responses are re-encoded by `:inet_dns` and stay within it. Read more than
# that so an oversized query is seen and dropped rather than silently truncated
# into something that decodes as a *different* question.
DNS_BUF = 4096
RESOLVER_TIMEOUT = 6.0


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
        upstream = socket.socket()
        # ⚠️ SO_MARK, without which this connect is caught by the very redirect
        # this process serves and the acceptor talks to itself. `Netns` installs
        # `meta mark <ACCEPTOR_MARK> return` ahead of the redirect to skip it.
        #
        # Measured: without the mark the acceptor sees its own upstream as a new
        # connection (ORIGINAL_DST=127.0.0.1:9100, its own destination) and
        # loops. The symptom is a PERMITTED destination timing out -- which
        # reads as an unreachable network, not as a broken boundary, and leaves
        # every denial check passing.
        upstream.setsockopt(socket.SOL_SOCKET, SO_MARK, ACCEPTOR_MARK)
        upstream.settimeout(CONNECT_TIMEOUT)
        upstream.connect((host, port))
    except OSError:
        conn.close()
        return

    conn.settimeout(IDLE_TIMEOUT)
    upstream.settimeout(IDLE_TIMEOUT)
    threading.Thread(target=splice, args=(conn, upstream), daemon=True).start()
    threading.Thread(target=splice, args=(upstream, conn), daemon=True).start()


def ask_resolver(resolver_path, source_key, query):
    """Hand one DNS query to the platform and return its answer bytes.

    Returns None on any failure. ⚠️ None means "send nothing back", never
    "answer something" -- see the module docstring.

    The frame is `"<source-key>\n" <> <query bytes>`, length-prefixed, and the
    source key is the one this process was STARTED with. It is never read off
    the datagram: this listener serves one namespace, so the sandbox's identity
    is its own existence, exactly as for the TCP side.
    """
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(RESOLVER_TIMEOUT)
        s.connect(resolver_path)
        frame = source_key.encode() + b"\n" + query
        s.sendall(struct.pack("!I", len(frame)) + frame)
        head = recv_exactly(s, 4)
        if head is None:
            s.close()
            return None
        body = recv_exactly(s, struct.unpack("!I", head)[0])
        s.close()
        return body
    except OSError:
        return None


def recv_exactly(sock, count):
    """Read exactly `count` bytes, or None if the peer stops first."""
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve_dns(udp, resolver_path, source_key):
    """Answer DNS for this namespace, one datagram at a time.

    ⚠️ Serialised rather than threaded per datagram. A resolver is a
    request/response service with a client that retries on silence, and a
    thread per datagram is an unbounded fan-out driven by tenant code -- the
    tenant would choose how many host-side connections the platform opens.
    """
    while True:
        try:
            query, peer = udp.recvfrom(DNS_BUF)
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            return
        answer = ask_resolver(resolver_path, source_key, query)
        if answer is None:
            continue
        try:
            udp.sendto(answer, peer)
        except OSError:
            continue


def main():
    if len(sys.argv) != 7:
        sys.stderr.write(
            "usage: nsacceptor.py <port> <verdict-socket> <source-key> "
            "<resolver-socket> <resolver-address> <resolver-port>\n"
        )
        return 2
    port = int(sys.argv[1])
    verdict_path = sys.argv[2]
    source_key = sys.argv[3]
    resolver_path = sys.argv[4]
    resolver_address = sys.argv[5]
    resolver_port = int(sys.argv[6])

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

    # ⚠️ Bound BEFORE the readiness line, so a host that cannot serve DNS to
    # this sandbox refuses the launch instead of producing one whose every
    # hostname allowlist entry silently denies. `await_acceptor/2` treats an
    # exit before that line as a refusal, and `police_or_terminate/3` then
    # terminates the tenant.
    #
    # ⚠️ Bound to the resolver address EXACTLY, not `0.0.0.0`. The nft exemption
    # names one destination address, and a wildcard bind here would accept
    # datagrams the rule never permitted -- making the listener wider than the
    # rule and hiding a mistake in the rule.
    #
    # ⚠️ Port 0 means the plan carries NO resolver, i.e. this sandbox is meant
    # to have no name resolution at all. It is an explicit configuration, not a
    # fallback -- a resolver that was configured and could not be read raises at
    # plan-build time and never reaches this process.
    if resolver_port:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            udp.bind((resolver_address, resolver_port))
        except OSError as exc:
            sys.stderr.write(
                "RESOLVER bind failed on %s:%d (%s)\n"
                % (resolver_address, resolver_port, exc)
            )
            sys.stderr.flush()
            return 1

        threading.Thread(
            target=serve_dns, args=(udp, resolver_path, source_key), daemon=True
        ).start()
        sys.stdout.write("RESOLVER listening %s:%d\n" % (resolver_address, resolver_port))
    else:
        sys.stdout.write("RESOLVER disabled\n")
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

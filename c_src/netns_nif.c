/*
 * Sockets that live in a sandbox's network namespace, owned by this BEAM.
 *
 * WHY THIS EXISTS
 *
 * The enforcement point for egress has to be a socket inside the sandbox's
 * network namespace. An `nft` `redirect` is DNAT to the local machine *as that
 * namespace sees it*, so it can only ever land on a socket in that namespace.
 * The BEAM runs in the host namespace and no option to `:gen_tcp.listen/2`
 * changes a socket's namespace -- which is why this project shipped a separate
 * helper process entered via `nsenter`, and why `ExSandbox.Egress.Pool`'s own
 * listener was dead code that nothing redirected to.
 *
 * `setns(2)` with `CLONE_NEWNET` affects only the calling *thread*. So a socket
 * can be created in another namespace without moving the process: enter on a
 * dedicated pthread, create and bind there, and hand the descriptor back. The
 * BEAM then adopts it with `{:fd, Fd}` and the socket behaves like any other,
 * while living in a namespace the emulator never joined.
 *
 * Measured, in `ex-sandbox-isolation` with a namespace `probe1`:
 *
 *     listener adopted from netns fd    {:ok, {{0, 0, 0, 0}, 9200}}
 *     connect from the HOST namespace   {:error, :econnrefused}
 *     connect from INSIDE probe1        received "OUTBOUND-FROM-NETNS"
 *     SO_ORIGINAL_DST on the accepted   {:raw, 0, 80, <<2, 0, ...>>}
 *
 * The `econnrefused` is the load-bearing half: the port does not exist in the
 * host namespace, so the socket demonstrably is not here.
 *
 * WHY EVERY JOB GETS ITS OWN THREAD
 *
 * A scheduler thread that entered a namespace and did not leave would run every
 * unrelated process scheduled onto it in that namespace afterwards. There is no
 * "leave" -- only `setns` back, which needs a descriptor for the original
 * namespace and is one missed error path away from a scheduler permanently
 * misplaced. A thread created for one job and joined immediately cannot leak
 * the namespace, because it does not outlive it.
 *
 * Dirty I/O rather than a normal scheduler: `open` and `setns` are blocking
 * filesystem-ish calls, and a NIF that blocks a normal scheduler stalls every
 * process on it.
 */

#define _GNU_SOURCE
#include <erl_nif.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct job {
  char path[512];
  /* listen: the port to bind. socket: the SO_MARK value. */
  int n;
  int fd;
  int err;
  const char *stage;
};

static int enter_netns(struct job *j) {
  int nsfd = open(j->path, O_RDONLY | O_CLOEXEC);
  if (nsfd < 0) { j->err = errno; j->stage = "open"; return -1; }
  if (setns(nsfd, CLONE_NEWNET) != 0) { j->err = errno; j->stage = "setns"; close(nsfd); return -1; }
  close(nsfd);
  return 0;
}

static void *listen_worker(void *p) {
  struct job *j = p;
  j->fd = -1;
  if (enter_netns(j) != 0) return NULL;

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) { j->err = errno; j->stage = "socket"; return NULL; }

  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons((unsigned short) j->n);
  /* INADDR_ANY, not loopback. The redirect rewrites the destination to the
   * namespace's own primary address rather than to 127.0.0.1, so a listener
   * bound to loopback is never reached. Measured: peer=('172.19.0.4', 48160). */
  sa.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(s, (struct sockaddr *) &sa, sizeof sa) != 0) { j->err = errno; j->stage = "bind"; close(s); return NULL; }
  if (listen(s, 128) != 0) { j->err = errno; j->stage = "listen"; close(s); return NULL; }

  j->fd = s;
  return NULL;
}

/*
 * An outbound socket in the namespace, carrying SO_MARK before it is connected.
 *
 * WHY THE MARK IS SET AND READ BACK **HERE**, IN C
 *
 * The namespace's `nat output` hook redirects all outbound TCP to the acceptor,
 * so the acceptor's own upstream connect is caught by the redirect it exists to
 * serve and it talks to itself. `Netns.redirect_commands/2` installs
 * `meta mark 42 return` ahead of the redirect as the exemption.
 *
 * Setting that mark from Elixir FAILS OPEN. Measured with CAP_NET_ADMIN and
 * CAP_NET_RAW dropped: `:gen_tcp.connect` returns `:ok`, `:inet.setopts`
 * returns `:ok`, and reading the option back yields `<<0, 0, 0, 0>>`. `:inet`
 * swallows the kernel's EPERM. CPython raised OSError on the same call, which
 * is the only reason the helper failed closed.
 *
 * The symptom of a lost mark is a PERMITTED destination timing out. That reads
 * as an unreachable network, not as a broken enforcement point, and every
 * denial check still passes -- which is exactly how it survived before.
 *
 * So the value is written, read back, and compared before the descriptor is
 * allowed to leave this function. Same capability drop, through this path:
 *
 *     {:error, :setsockopt_mark, 1}      (EPERM, and no fd)
 *
 * The caller cannot obtain an unmarked socket, because there is no return path
 * that produces one.
 */
static void *socket_worker(void *p) {
  struct job *j = p;
  j->fd = -1;
  if (enter_netns(j) != 0) return NULL;

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) { j->err = errno; j->stage = "socket"; return NULL; }

  int mark = j->n;
  if (setsockopt(s, SOL_SOCKET, SO_MARK, &mark, sizeof mark) != 0) {
    j->err = errno; j->stage = "setsockopt_mark"; close(s); return NULL;
  }

  int got = -1;
  socklen_t len = sizeof got;
  if (getsockopt(s, SOL_SOCKET, SO_MARK, &got, &len) != 0) {
    j->err = errno; j->stage = "getsockopt_mark"; close(s); return NULL;
  }
  if (got != mark) {
    j->err = got; j->stage = "mark_readback_mismatch"; close(s); return NULL;
  }

  j->fd = s;
  return NULL;
}

/*
 * A bound UDP socket in the namespace, for the DNS leg.
 *
 * INADDR_ANY on the resolver's port rather than the resolver's address: the
 * redirect DNATs the tenant's port 53 traffic to that address:port, and the
 * namespace holds exactly one tenant with nothing else able to route to it, so
 * binding all addresses there is narrower than binding loopback on the host.
 * Same reasoning as the TCP listener above, and the same measurement behind it.
 */
static void *udp_worker(void *p) {
  struct job *j = p;
  j->fd = -1;
  if (enter_netns(j) != 0) return NULL;

  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) { j->err = errno; j->stage = "socket"; return NULL; }

  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons((unsigned short) j->n);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(s, (struct sockaddr *) &sa, sizeof sa) != 0) { j->err = errno; j->stage = "bind"; close(s); return NULL; }

  j->fd = s;
  return NULL;
}

static ERL_NIF_TERM run(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[], void *(*fn)(void *)) {
  ErlNifBinary path;
  int n;

  if (argc != 2 || !enif_inspect_binary(env, argv[0], &path) || !enif_get_int(env, argv[1], &n))
    return enif_make_badarg(env);
  if (path.size >= sizeof(((struct job *) 0)->path))
    return enif_make_badarg(env);

  struct job j;
  memset(&j, 0, sizeof j);
  memcpy(j.path, path.data, path.size);
  j.path[path.size] = 0;
  j.n = n;

  pthread_t t;
  if (pthread_create(&t, NULL, fn, &j) != 0)
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, "thread_create"));
  pthread_join(t, NULL);

  if (j.fd < 0)
    return enif_make_tuple3(env,
      enif_make_atom(env, "error"),
      enif_make_atom(env, j.stage ? j.stage : "unknown"),
      enif_make_int(env, j.err));

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_int(env, j.fd));
}

static ERL_NIF_TERM netns_listen(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  return run(env, argc, argv, listen_worker);
}

static ERL_NIF_TERM netns_socket(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  return run(env, argc, argv, socket_worker);
}

static ERL_NIF_TERM netns_udp(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  return run(env, argc, argv, udp_worker);
}

static ErlNifFunc funcs[] = {
  {"netns_listen", 2, netns_listen, ERL_NIF_DIRTY_JOB_IO_BOUND},
  {"netns_socket", 2, netns_socket, ERL_NIF_DIRTY_JOB_IO_BOUND},
  {"netns_udp", 2, netns_udp, ERL_NIF_DIRTY_JOB_IO_BOUND}
};

ERL_NIF_INIT(Elixir.ExSandbox.Egress.NetnsSocket, funcs, NULL, NULL, NULL, NULL)

# Changelog

## 1.2.0 — 2026-08-29

### A mechanism can report where a sandbox is reachable

`ExSandbox.Mechanism` gains `address/1`, an **optional** callback returning
`{:ok, String.t() | nil}`. Every existing mechanism keeps compiling, and a consumer that derives
the required callback set from `behaviour_info(:callbacks) -- behaviour_info(:optional_callbacks)`
sees no change.

`{:ok, nil}` is the ordinary answer for a sandbox that is not reachable — it names no port, it is
not running, or the mechanism cannot publish one. It is deliberately not an error: a caller that
had to rescue in order to render a stopped sandbox would eventually render something else.

`ExSandbox.Mechanism.Beam` returns `nil`. It has a `"peer:<id>"` handle and that handle is not an
address; returning it would put a broken frame in front of a person instead of a clear absence.

### `ExSandbox.Sandbox` gains `service_port`, and it decides the container's network posture

`service_port` is the port an application inside the sandbox listens on. It is **not** opaque: a
mechanism reads it and acts on it.

* `service_port: nil` — `ExSandbox.Mechanism.Docker` passes `--network none`, exactly as before.
  A host that never sets the field keeps the posture it has today.
* `service_port: <port>` — the container joins the default bridge and that port is published to
  `127.0.0.1` on an **ephemeral** host port the daemon allocates. `address/1` reads back what was
  allocated, so two concurrent provisions cannot be handed the same host port.

⚠️ **What the second posture gives up, stated rather than implied.** A bridge network means
outbound access, so the deny-by-default posture does not hold for a sandbox that names a port:
code inside can install dependencies at runtime and can reach the internet, and
`ExSandbox.Egress`'s allowlist does not apply to it. What still constrains it is unchanged —
filesystem and process confinement, and the memory and CPU caps applied at create time. Inbound
is narrower than deny-all suggests rather than wider: one port, bound to loopback, reachable from
the host running the platform and from no other machine.

## 1.1.0 — 2026-08-29

### ⚠️ On Linux, egress now needs a C compiler at build time instead of `python3` at runtime

`Mix.Tasks.Compile.NetnsNif` builds `c_src/netns_nif.c` into `priv/netns_nif.so` in the
consumer's own tree. It is skipped off Linux, and a missing compiler is a **warning, not a build
failure** — but on a Linux host without one, `ExSandbox.Egress.NetnsSocket.available?/0` is false,
the `network_restriction` capability is not constructed, and `ExSandbox.Mechanism.Beam` refuses to
launch any sandbox that requires it. The refusal names itself; it does not fail open.

CI installs `gcc` where it used to install `python3`. A deployment that pinned the runtime image's
package list should make the same swap.

### The in-namespace acceptor is no longer a separate process

The enforcement point for egress has to be a socket inside the sandbox's network namespace: an
`nft` `redirect` is DNAT to the local machine *as that namespace sees it*, so it can only reach a
socket there. The BEAM runs in the host namespace and no option to `:gen_tcp.listen/2` changes a
socket's namespace, so the listener was a Python helper entered with `nsenter`.

The third premise is true and irrelevant, which is what was missed. `setns(2)` with `CLONE_NEWNET`
affects only the calling **thread**, so the socket can be created in the sandbox's namespace on a
thread of its own and the descriptor adopted with `{:fd, Fd}`. Measured in the isolation image:

    listener adopted from the namespace fd   {:ok, {{0, 0, 0, 0}, 9200}}
    connect from the HOST namespace          {:error, :econnrefused}
    connect from INSIDE the namespace        received its bytes
    SO_ORIGINAL_DST on the accepted socket   readable

The `econnrefused` is the load-bearing half: that port does not exist in the host namespace, so
the socket demonstrably is not there.

Because the acceptor is now a process on this node, `ExSandbox.Egress.Decision.decide/3` is an
ordinary function call. Everything that existed only to bridge the process boundary is gone rather
than simplified: the `AF_UNIX` verdict socket and its wire format, a second `AF_UNIX` socket and
length-prefixed frame for DNS, the sandbox's identity passed on `argv`, a readiness line parsed
off stdout, and the `chmod` widening whose absence silently dropped every datagram. Net −713 lines.

All private modules — none appeared in `priv/boundary.md`, so the package contract is unchanged.

### `ExSandbox.Egress.Pool` is now `ExSandbox.Egress.Decision`, and holds no socket

The pool supervised a listener on `127.0.0.1` in the **host** namespace, which the paragraph above
explains can never receive a redirected connection. Its own moduledoc said so, and named the
condition for removing it: *"If this comment outlives the tests that justify it, the listener
should go."*

⚠️ It did, in the way that matters most. The two test files justifying the listener were driving
**that** copy of the accept-decide-relay path, while `ExSandbox.Egress.Acceptor` — the copy every
tenant connection actually reaches — had two tests. Correct tests over unreachable code: the same
defect species as the unsupervised pool and the unreferenced `Binding`, with the polarity
reversed. Both files now stand over the acceptor, which is a coverage increase rather than a move.

Deleted: the listener, the accept loop, `port/1`, `handle_connection/3`, `relay/2`, and the entry
in the application supervision tree. `decide/3` remains, and is still the single implementation of
the allowlist question. The module was renamed because a module with one function and no socket
should not be called a pool. All private — nothing here appears in `priv/boundary.md`.

⚠️ Three supervision tests went with the listener: that it was a supervised child, that it started
after the registry, and that it bound a real port. All three were true and none meant anything —
they described a socket nothing could reach. What they were really asking is now answered at
launch rather than at boot, and a new test pins that an acceptor which cannot enter its namespace
binds **nothing** rather than falling back to the host.

### A socket-ownership race in the acceptor, found by moving those tests

`accept_loop/1` started the per-connection handler and *then* transferred socket ownership to it.
`:gen_tcp.recv/3` on a passive socket is refused for any process that is not the controlling one,
so a handler that won the race tore the connection down before a byte moved. From inside the
sandbox that is a **permitted** destination behaving exactly like a denied one, leaving a single
`:einval` deep in the relay as its only trace.

The handler now waits to be told it owns the socket. The pool never hit this because it
transferred ownership to the relay task rather than to the handler; the bug arrived with the
acceptor and would not have been visible without repointing the tests onto it.

### `SO_MARK` on the relay's upstream socket was failing open

The acceptor's own upstream connect is caught by the redirect it exists to serve, so it needs
`meta mark 42 return` to exempt itself. `ExSandbox.Egress.Relay` set that mark with
`raw: {1, 36, _}` on `:gen_tcp.connect/4`. Measured with `CAP_NET_ADMIN` and `CAP_NET_RAW` dropped:
the connect returns `:ok`, `:inet.setopts/2` returns `:ok`, and reading the option back yields
`<<0, 0, 0, 0>>`. `:inet` swallows the kernel's `EPERM`. The Python helper failed closed only
because CPython raised `OSError` on the same call.

⚠️ The symptom of a lost mark is a **permitted** destination timing out, which reads as an
unreachable network rather than as a broken enforcement point — and every denial check still
passes, because denial is unaffected.

The mark is now written, read back, and compared inside the NIF before any descriptor is returned:
`{:error, :setsockopt_mark, 1}` under the same capability drop, and no fd. An unmarked upstream is
unrepresentable rather than merely unlikely. The test that guarded this previously asserted the
*presence of the option that was the bug*, so it passed in exactly the configuration where the
mark was silently dropped.

### The citations in this library's comments now resolve, and a test keeps them resolving

This codebase's convention is that a claim about behaviour names the thing that measured it, so
comments cite probe scripts and contract documents by filename. The extraction from the Axonn
umbrella brought the code and not that tree, which left 78 backticked names pointing at nothing --
including `contracts/egress.md`, cited in the opening line of most `ExSandbox.Egress` moduledocs
and therefore on the published page for each of them.

[docs/provenance.md](docs/provenance.md) now says where each family of names went and, for the
umbrella ones, states plainly that nothing here reads them at build or run time. It ships in the
package and is linked from the docs.

`test/documentation_pointers_test.exs` enforces it: a backticked filename must resolve in the tree
or be declared absent, and a declared absence must be explained in that document. Written because
renaming `ExSandbox.Egress.Pool` left three stale pointers that compile warnings and
`mix docs --warnings-as-errors` both passed over -- one of them a present-tense claim that a
renamed-away test file covers the decision.

### A renamed module leaves the same wreckage, and ExDoc does not catch it

Renaming `ExSandbox.Egress.Pool` also left six present-tense claims that live code calls the
pool's decide function, in two library modules, the census baseline and three test files. ExDoc
autolinks a **fully qualified** module in backticks and fails the build when it cannot resolve one,
which is why the rename's qualified references were caught at the time. An unqualified alias is not
autolinked, so every one of these passed `mix docs --warnings-as-errors`.

All six corrected. `test/documentation_pointers_test.exs` now also bans the unqualified form. A
removed module is written with the qualifier it had, so `Egress.Pool.relay/2` reads as history and
an unqualified mention is always a pointer at something gone. This paragraph is subject to the same
rule, which is how the rule was found to apply to prose about the rule.

### `ExSandbox.Capability.satisfied?/1` documented a role it does not have

Its docstring said "this is what an entry point calls before starting a sandbox". This library's
entry points do not call it. `ExSandbox.provision/2` and `ExSandbox.start/2` gate on a private
`ensure_capable/2` built on `missing/1`, because a refusal has to name which capability was absent.
The function is unchanged and still public; only the docstring was wrong, and a reader following it
looked for the gate in the wrong place.

Also removed: `ExSandbox.Conformance.Execution.long_line_bytes/0`, a `@doc false` accessor for a
module attribute that nothing read.

### Two conformance checks credited a refusal that distinguished nothing

`reaching another sandbox over the network is refused` passed against any mechanism whose published
address had nothing listening on it. A refusal at a dead port is what a mechanism with **no**
boundary produces, so the green tick reported an enforcement point that had never refused anything.
`test/conformance_network_meta_test.exs` required that pass, which is a test pinning the defect the
check exists to catch (`029` T034d).

Both checks now probe the address from the platform before crediting a refusal, and report the
third outcome when nothing answers there.

⚠️ **The control runs after the attempt, not before it, and the order is the whole of it.** Gating
first was measured here and is a real weakening. `OpenNetworkMechanism` declares an address and a
`connect` that reports success for every destination, and probing liveness first short-circuits
before `connect` is ever called, so a mechanism that declared a boundary and let everything through
is filed as `unavailable` instead of as the breach it is.

The same latent fault was measured in `every published handle of another sandbox is refused from
inside`, which had gated first since it was written. A mechanism crossing a dead handle reported the
third outcome rather than a violation. Reordered, and a new meta-test pins it: a crossing is a
breach at a live handle and a dead one alike, and only a refusal has to prove it distinguished
something.

⚠️ Neither change moves the census. `ExSandbox.Mechanism.Beam` publishes `"peer:" <> id` rather than
a dialable tuple, so both checks already reported the third outcome against it and still do.

### One guarantee is now demonstrated less well, and the census records it

`ExSandbox.Mechanism.Beam` published the verdict socket's path as `context.policy_handle`, and
`FR-011b` demonstrated "a tenant cannot widen its own allowlist" by attempting to write it from
inside a sandbox. There is no socket any more, and no filesystem artefact of any kind carries the
allowlist — it lives in `ExSandbox.Egress.Registry`, in this BEAM's memory, which a tenant has no
route to.

The guarantee is stronger and the evidence for it weaker. `docker/census-baseline.txt` was raised
from 8 to 9 with the reason recorded there, because a ceiling that moves without one is how a
suite reports fewer guarantees every release and stays green the whole way.

## 1.0.1 — 2026-08-28

### `boundary.md` moved to `priv/`, so the documented lookup resolves

1.0.0 shipped `docs/boundary.md` and told consumers to read it with
`Application.app_dir(:ex_sandbox, "docs/boundary.md")`. That call cannot work. Mix links exactly
`ebin` and `priv` into an application's build directory, so a file shipped under any other
top-level directory is present in the tarball and absent from `app_dir/2` -- and `app_dir/2` is
the only path a consumer has at runtime.

Found the first time a consumer actually made the call: `File.exists?` on the documented path
returned false against an installed 1.0.0, while `tar tzf` on the same release listed the file.
A packaging check that stops at "is it in the tarball" cannot see this, because the tarball was
never the thing that was wrong.

The file is now `priv/boundary.md`. Its content is unchanged.

**If you read the 1.0.0 path, update the call:**

```elixir
# before -- returns a path that does not exist
Application.app_dir(:ex_sandbox, "docs/boundary.md")

# after
Application.app_dir(:ex_sandbox, "priv/boundary.md")
```

Nothing else changed: no module, function, behaviour or configuration key differs from 1.0.0.

## 1.0.0 — 2026-08-28

### Extracted from the Axonn umbrella; first public release

This library was an application inside a larger umbrella project. It is now its own repository and
its own Hex package, with its own lockfile, config, CI and isolation harness. The extraction
preserved history (`git subtree split`, 143 commits) rather than re-creating the tree.

What changed for a consumer, as opposed to for the umbrella:

- **`storage_root` now defaults to `/var/lib/ex_sandbox/sandboxes`**, was `/var/lib/axonn/sandboxes`.
  ⚠️ For an existing deployment this is a data migration, not a cosmetic rename — sandbox storage
  moves. Set `config :ex_sandbox, :beam, storage_root: "/var/lib/axonn/sandboxes"` to keep the old
  path.
- **The verdict socket's default prefix is `ex-sandbox-`**, was `axonn-`.
- The dependency tree is `:telemetry` and nothing else, enforced by
  `test/dependency_tree_test.exs`, and the Elixir floor is `~> 1.14` rather than the platform's
  version.
- The conformance suite's credentials group reports `capability_unavailable` here rather than
  passing, because this package has no data store to probe (`012-FR-001`). A consumer with a
  database instantiates the same suite with its own probe. The identifiers are explained in
  [docs/requirement-ids.md](docs/requirement-ids.md).

No public function, callback, struct field or telemetry event changed in the move.

### `ExSandbox.Mechanism` gained an optional callback, and the gate changed shape

`c:ExSandbox.Mechanism.constructed_capabilities/0` declares the capabilities a
mechanism **builds for whatever it runs** — the opposite claim from
`c:ExSandbox.Mechanism.required_capabilities/0`, which says what it needs from
the host. `ExSandbox`'s private `ensure_capable/2` now subtracts the second list from the
first and asks the host probe only about the remainder.

⚠️ **This is a change to a refusal, which is why it is a major version.** The
callback is optional and a mechanism that omits it is gated exactly as before,
so nothing in the tree breaks — but a mechanism that declares one is now
admitted on a host where it was previously refused, and a gate that admits more
than it used to is a behavioural change to the thing this library exists to do.
It is stated here rather than in the additive column.

The claim is **not verified by the behaviour**. `ExSandbox.Conformance` is what
establishes it, by observing a breach being stopped; until a mechanism is run
through the suite, what backs its list is whatever tests accompany it.

### `ExSandbox.Mechanism.Docker`

A mechanism backed by a container runtime, for hosts whose own kernel cannot
construct the confinement `ExSandbox.Mechanism.Beam` requires — every macOS
host, where all five gating capabilities report unavailable and `Beam` is
therefore refused before it is reached.

It declares `:resource_limits`, `:filesystem_confinement` and
`:network_restriction` as constructed, each backed by an observed breach in
`test/mechanism/`. It deliberately claims neither
`:disk_quota` — MEASURED accepted-and-ignored on overlayfs — nor
`:privilege_separation`; both omissions are stated reductions and are documented
on the module.

### `ExSandbox.Sandbox` gained `workspace_path`

An absolute host directory the sandbox's contents live in, supplied by the host
and made reachable from inside by whatever means the mechanism has. Additive:
`nil` means "no workspace", which a mechanism must read as *mount nothing*
rather than as *mount somewhere sensible*.

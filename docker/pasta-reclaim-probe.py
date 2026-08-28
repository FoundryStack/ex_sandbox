#!/usr/bin/env python3
"""Does `pasta` survive `destroy/1`, and does its namespace go with it?

`destroy/1` terminates the peer, releases the binding, and kills the acceptor.
It does **not** kill `pasta`. Whether that leaks is an empirical question:
`bwrap --die-with-parent` might take the tenant down and pasta might exit when
its spawned command does -- or pasta might linger holding a namespace open,
which is exactly what the acceptor was measured to do (and why `destroy/1`
kills it explicitly).

⚠️ Reports INCONCLUSIVE rather than a verdict if the launch never happens.
A probe that cannot provision has measured nothing about reclamation, and
scoring "no pasta process found" as "reclaimed cleanly" would be a false pass
of precisely the shape this feature keeps producing.
"""
import os, re, subprocess, sys, time

def say(m): print(f"\n=== {m} ===", flush=True)

def pasta_procs():
    """(pid, netns) for every live pasta, by /proc rather than ps output."""
    out = []
    for p in sorted(os.listdir("/proc")):
        if not p.isdigit():
            continue
        try:
            cmd = open(f"/proc/{p}/cmdline").read()
        except OSError:
            continue
        if "pasta" not in cmd:
            continue
        try:
            ns = os.readlink(f"/proc/{p}/ns/net")
        except OSError:
            ns = "?"
        out.append((int(p), ns))
    return out

ELIXIR = r'''
sandbox = struct!(ExSandbox.Sandbox,
  id: "reclaim-probe-#{System.unique_integer([:positive])}",
  owner_ref: "o", template_ref: "t",
  cpu_limit: 500, memory_limit_mb: 128, disk_quota_mb: 256,
  context: %{network_allowlist: [{"1.1.1.1", 443}]})

case ExSandbox.provision(ExSandbox.Mechanism.Beam, sandbox) do
  {:ok, s} ->
    IO.puts("PROVISIONED")
    Process.sleep(3_000)
    IO.puts("BEFORE-DESTROY")
    :ok = ExSandbox.Mechanism.Beam.destroy(s)
    IO.puts("DESTROYED")
    Process.sleep(3_000)
    IO.puts("SETTLED")

  other ->
    IO.puts("PROVISION-FAILED #{inspect(other)}")
end
'''

say("0. baseline: pasta processes before anything is provisioned")
before = pasta_procs()
for pid, ns in before:
    print(f"  pid={pid} netns={ns}")
print(f"  count={len(before)}")

proc = subprocess.Popen(
    ["mix", "run", "-e", ELIXIR],
    cwd="/app", env={**os.environ, "MIX_ENV": "test",
                     "AXONN_DB_HOST": "postgres", "AXONN_DB_PORT": "5432",
                     "HOME": "/root", "LANG": "C.UTF-8"},
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

during = None
deadline = time.time() + 240
stage = None
while time.time() < deadline:
    line = proc.stdout.readline()
    if not line:
        break
    print("  BEAM:", line.rstrip(), flush=True)
    if "PROVISION-FAILED" in line:
        for _ in range(40):
            more = proc.stdout.readline()
            if not more:
                break
            print("  BEAM:", more.rstrip(), flush=True)
        print("\nINCONCLUSIVE: never provisioned, so nothing was measured "
              "about reclamation")
        proc.kill()
        sys.exit(2)
    if line.startswith("BEFORE-DESTROY"):
        say("1. while the sandbox is alive")
        during = pasta_procs()
        for pid, ns in during:
            print(f"  pid={pid} netns={ns}")
        print(f"  count={len(during)}")
    if line.startswith("SETTLED"):
        stage = "settled"
        break

if during is None:
    print("\nINCONCLUSIVE: never reached BEFORE-DESTROY")
    proc.kill()
    sys.exit(2)

# CONTROL: the launch must actually have started a pasta, or "none left after
# destroy" is trivially true and proves nothing.
new_during = [x for x in during if x not in before]
if not new_during:
    print("\nINCONCLUSIVE: the launch started no new pasta process, so the "
          "after-destroy count cannot distinguish reclaimed from never-created")
    proc.kill()
    sys.exit(2)
print(f"\n  CONTROL OK: the launch started {len(new_during)} new pasta "
      f"process(es): {[p for p, _ in new_during]}")

if stage != "settled":
    print("\nINCONCLUSIVE: destroy never settled")
    proc.kill()
    sys.exit(2)

say("2. after destroy")
after = pasta_procs()
for pid, ns in after:
    print(f"  pid={pid} netns={ns}")
print(f"  count={len(after)}")

leaked = [x for x in after if x in new_during]

say("VERDICT")
if leaked:
    print(f"  LEAKED: {len(leaked)} pasta process(es) survived destroy: "
          f"{[p for p, _ in leaked]}")
    print("  Each holds its network namespace open. T060a6 must kill pasta.")
    rc = 1
else:
    print("  RECLAIMED: every pasta the launch started is gone after destroy.")
    print("  pasta exits with its spawned command; no explicit kill needed.")
    rc = 0

proc.kill()
sys.exit(rc)

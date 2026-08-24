defmodule ExSandbox.Mechanism.Beam.ServesHttpTest do
  @moduledoc """
  A sandbox actually serves an HTTP request (`docs/legacy/specify/README.md` "Done when" 2).

  ## Why this file exists

  The slice's goal sentence is "one Elixir sandbox that **starts, serves an HTTP
  request, and stops**". Every other clause of that sentence had a test:
  lifecycle covers provision/start/stop/destroy and the stop/start cycle, and
  the census covers isolation and credentials. Serving did not.

  What stood in for it was `ExSandbox.Proxy`, which decides where to forward
  based on `status/1` — and `proxy_test.exs` exercises those decisions against
  *fake* mechanisms that return `{:ok, :running}` from a hardcoded clause. No
  socket is ever opened there. So `status/1` returning `:running` had never been
  correlated with a sandbox that can answer anything, and `006-domain-routing`
  is built entirely on that verdict.

  That gap has a specific shape, and this repo has shipped it three times:
  `can_confine_mounts?/0` probed `--unshare-net` while the launch used
  `--unshare-pid --proc`; `network_restriction`'s two probes disagreed;
  `binds_root?/0` probed flagless `bwrap` while the launch passed
  `--unshare-user`. Each was a check testing something **easier** than the real
  operation, and each read green while the real operation could not run. A
  `:running` verdict that no request has ever been served through is the same
  defect one layer up.

  ## Why the listener runs INSIDE the sandbox

  The sandbox launches under `--unshare-net` (`Hardening.Linux`, `FR-003`) with
  no network interfaces beyond its own loopback, and it boots **undistributed**
  — `:erpc` and `Node` cannot reach it at all. So this test cannot connect to
  the sandbox from the host: there is no route, by design, and building one
  would be testing a hole rather than the guarantee.

  Both ends therefore live inside the sandbox's own netns, driven over the stdio
  control channel (`Beam.call/5`), the same transport `isolation_cluster_test`
  uses for the same reason. What is demonstrated is that **the sandbox's runtime
  can bind a port, accept a connection, and answer an HTTP request** — which is
  the clause the slice names. Reachability *from outside* is `006`'s problem and
  is explicitly out of the slice ("a sandbox reachable on `localhost` is
  sufficient").

  ⚠️ **OTP modules only, and not a closure.** The sandbox runs a bare `erl` with
  no Elixir on its code path, so `Enum`, `String` and friends are `:undef`
  there, and `check_funs_loadable/3` refuses a fun whose defining module the
  sandbox cannot load. Both mistakes have shipped before in this exact seam —
  the connect probe was written as a fun and turned every network check into
  `{:sandbox_unreachable, {:fun_not_loadable, ExSandbox.Mechanism.Beam}}`. The
  server here is therefore Erlang source, parsed and evaluated on the far side.

  ⚠️ **Serve and request happen in ONE `:peer.call`.** A `gen_tcp` socket is
  owned by the process that opened it, and each `:peer.call` runs in a fresh
  process that exits when the call returns — so a listen in one call and a
  connect in the next always sees a closed socket. The connect probe shipped
  with exactly this bug, and every destination on earth read as `:refused`.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox(tag) do
    %Sandbox{
      id: "http-#{tag}-#{System.unique_integer([:positive])}",
      owner_ref: "owner-#{tag}",
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    }
  end

  defp launch(tag) do
    ExSandbox.Test.IsolationLaunch.provision_or_skip(Beam, sandbox(tag))
  end

  # Evaluates Erlang source on the sandbox node and returns its value.
  #
  # `:erl_eval.exprs/2` rather than a fun, and the parse happens *here* while the
  # evaluation happens *there*, so nothing but OTP is needed on the far side.
  defp eval_source(sandbox, source, timeout) do
    {:ok, tokens, _} = source |> String.to_charlist() |> :erl_scan.string()
    {:ok, exprs} = :erl_parse.parse_exprs(tokens)

    case Beam.call(sandbox, :erl_eval, :exprs, [exprs, []], timeout) do
      {:ok, {:value, value, _bindings}} -> {:ok, value}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:unexpected, other}}
    end
  end

  # A one-shot HTTP server and a client for it, in a single expression.
  #
  # Binds port 0 on the sandbox's loopback, spawns an acceptor that answers one
  # request with a fixed body, then connects to itself and reads the response.
  # Returns the raw response bytes, or an atom naming which step failed — never
  # a partial success, because "the listen worked" is not the property.
  defp serve_and_request_source(body) do
    """
    case gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                            {ip, {127,0,0,1}}]) of
      {ok, L} ->
        {ok, Port} = inet:port(L),
        Parent = self(),
        spawn(fun() ->
          case gen_tcp:accept(L, 5000) of
            {ok, S} ->
              %% Read the request line before answering, so this is a real
              %% request/response exchange rather than a server that shouts
              %% into a socket regardless of what arrived.
              case gen_tcp:recv(S, 0, 5000) of
                {ok, Req} ->
                  Parent ! {request_seen, Req},
                  Body = <<"#{body}">>,
                  Len = integer_to_binary(byte_size(Body)),
                  Resp = <<"HTTP/1.1 200 OK\\r\\nContent-Length: ",
                           Len/binary,
                           "\\r\\nContent-Type: text/plain\\r\\n\\r\\n",
                           Body/binary>>,
                  gen_tcp:send(S, Resp);
                _ ->
                  Parent ! {request_seen, error}
              end,
              gen_tcp:close(S);
            _ ->
              Parent ! {request_seen, no_accept}
          end
        end),
        case gen_tcp:connect({127,0,0,1}, Port, [binary, {active, false}], 5000) of
          {ok, C} ->
            gen_tcp:send(C, <<"GET /health HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n">>),
            R = case gen_tcp:recv(C, 0, 5000) of
                  {ok, Data} -> {ok, Data};
                  {error, RecvErr} -> {recv_failed, RecvErr}
                end,
            gen_tcp:close(C),
            gen_tcp:close(L),
            Seen = receive {request_seen, Q} -> Q after 5000 -> never end,
            {R, Seen};
          {error, ConnErr} ->
            gen_tcp:close(L),
            {{connect_failed, ConnErr}, never}
        end;
      {error, ListenErr} ->
        {{listen_failed, ListenErr}, never}
    end.
    """
  end

  # `kill -0`: signal 0 is not delivered, it only checks the process exists.
  defp process_alive?(os_pid) do
    case System.cmd("kill", ["-0", to_string(os_pid)], stderr_to_stdout: true) do
      {_, 0} -> true
      _ -> false
    end
  end

  # Teardown is asynchronous — `terminate/1` returns once the stop is requested,
  # not once the OS has reaped the process. Polling rather than sleeping keeps a
  # fast machine fast and a slow one correct.
  defp eventually(check, attempts \\ 40, interval_ms \\ 50) do
    Enum.reduce_while(1..attempts, false, fn _, _ ->
      if check.() do
        {:halt, true}
      else
        Process.sleep(interval_ms)
        {:cont, false}
      end
    end)
  end

  describe "a running sandbox serves an HTTP request" do
    test "the sandbox answers its own HTTP request with the body it served" do
      sb = launch("serve")
      {:ok, started} = Beam.start(sb)

      assert Beam.status(started) == {:ok, :running},
             "precondition: the sandbox must be running before it can serve"

      body = "sandbox-ok-#{System.unique_integer([:positive])}"

      assert {:ok, {{:ok, response}, request}} =
               eval_source(started, serve_and_request_source(body), 30_000)

      # The server saw a real request, not just a connection. Without this a
      # server that answered every accepted socket unconditionally would pass,
      # and "serves an HTTP request" would mean "opens a socket".
      assert is_binary(request), "the server never saw a request; got #{inspect(request)}"
      assert request =~ "GET /health", "the request line did not arrive intact"

      assert response =~ "HTTP/1.1 200 OK", "no HTTP status line in the response"
      assert response =~ body, "the served body did not come back over the socket"
    end

    test "stopping the sandbox takes the serving runtime with it" do
      # ⚠️ The adversarial half, and it took a sabotage run to get right.
      #
      # Asserting only that a *running* sandbox serves would pass against a
      # mechanism whose `status/1` returns `:running` unconditionally — the
      # over-claiming shape that has shipped in this repo three times. So the
      # contrast has to be real: the same sandbox, stopped, must not still be
      # serving.
      #
      # ⚠️ The obvious way to write that does not work, and it passes while not
      # working. `Beam.call/5` against the stopped struct returns an error — but
      # `stop/1` sets `peer: nil` on the registry row, and `lookup/1` keys by
      # `sandbox.id`, so the call fails for the *started* struct too. Measured by
      # sabotaging this test to eval against `started` after the stop: it still
      # passed, green against a sandbox that was demonstrably still alive. The
      # assertion was reading the registry, not the runtime, which is what
      # `status/1` already reports — a check that restates its own precondition.
      #
      # What distinguishes "the mechanism forgot the peer" from "the runtime is
      # gone" is the OS process. `host_pid/1` names it, and a stopped sandbox's
      # process must no longer exist — with nothing left to hold a listening
      # socket open.
      sb = launch("stopped")
      {:ok, started} = Beam.start(sb)

      body = "served-before-stop-#{System.unique_integer([:positive])}"

      # Control: it serves while running, so the absence below is about the stop
      # and not about this host being unable to run the server at all.
      assert {:ok, {{:ok, response}, _}} =
               eval_source(started, serve_and_request_source(body), 30_000)

      assert response =~ body, "precondition: the sandbox must serve before it is stopped"

      {:ok, os_pid} = Beam.host_pid(started)
      assert process_alive?(os_pid), "precondition: the sandbox's OS process must exist"

      {:ok, stopped} = Beam.stop(started)

      refute Beam.status(stopped) == {:ok, :running},
             "a stopped sandbox must not report `:running`"

      # The runtime itself is gone, so there is nothing left to serve — a
      # stronger statement than "the mechanism will not route to it", and the
      # one the sabotage showed was missing.
      assert eventually(fn -> not process_alive?(os_pid) end),
             """
             the sandbox's OS process #{os_pid} is still alive after stop/1.

             `status/1` reports it stopped and the mechanism will not route to
             it, but the runtime that served the request above is still running
             — so the sandbox can still be listening on a socket nothing has
             closed.
             """
    end
  end
end

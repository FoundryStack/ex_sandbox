defmodule ExSandbox.Mechanism.Beam.Exec do
  @moduledoc """
  Builds the expression that runs one command **inside** a BEAM sandbox, and
  decodes what comes back (008 T002, T003).

  ## Why this is source text rather than a fun

  It is evaluated on the sandbox node, which runs a bare `erl` with Elixir's
  stdlib on its code path and nothing of this project. A closure defined here
  belongs to `ExSandbox.Mechanism.Beam` and `check_funs_loadable/3` correctly
  refuses it — the same trap `ExSandbox.Mechanism.Beam.probe_exprs/3` documents,
  which shipped wrong once already. So the command runner is Erlang source,
  parsed here and evaluated there through `:erl_eval.exprs/2`, using nothing but
  OTP.

  ## `stdout` and `stderr` are separated by a redirect, not by the port

  A port has one output channel. `stderr_to_stdout` merges the two, and without
  it the child's fd 2 is simply inherited from the sandbox node and vanishes
  into the node's own stderr — captured nowhere, attributable to nothing.
  `008` data-model property 2 requires them separate, so:

      /bin/sh -c 'exec "$0" "$@" </dev/null 2>>"$EX_SANDBOX_STDERR"' CMD ARG...

  * `"$0" "$@"` passes the caller's argv through **as argv**. Nothing is
    interpolated into shell text, so there is no quoting to get wrong and no
    command injection to защит against — an argument containing `;` or `$(…)`
    is one argument.
  * `</dev/null` is the stdin-EOF rule `015` R14 measured on `MuonTrap.Daemon`:
    a child that reads stdin and never gets EOF blocks until something kills it,
    turning "this command needs no input" into a wall-clock breach.
  * `2>>` appends to a file this module creates **before** the command runs. If
    the file cannot be created the command is not run at all and the result is
    `{:could_not_run, {:stderr_capture_unavailable, reason}}` — never a silently
    merged or silently discarded stderr.

  ## `truncated?` is a fact about bytes, not about lines

  `015` R17 measured `MuonTrap`'s `:logger_fun` corrupting lines past a
  256-byte buffer, which is why the capture mechanism is decided here rather
  than inherited. This one has **no line buffer at all**: the port is opened
  with `:binary` and no `{:line, _}` option, so it delivers whatever chunks the
  OS pipe produces and the runner concatenates them. A 100 KB line arrives as
  however many chunks the kernel felt like and reassembles byte-identically.

  Truncation is applied once, at a byte limit, per stream:

    * `stdout` and `stderr` in the result are the **first `limit` bytes** of
      each stream.
    * `truncated?` is `true` if *either* stream produced more than `limit`
      bytes, so a caller reading a build log knows the tail is missing.
    * The command still runs to completion after the limit is reached — the
      runner keeps draining the port, because closing it early would leave a
      child writing into a broken pipe and change the exit status this seam is
      supposed to report faithfully.
  """

  @default_limit_bytes 1_048_576

  @typedoc "What the sandbox-side runner reports back, once decoded."
  @type outcome ::
          {:ok,
           %{
             exit_status: integer(),
             stdout: binary(),
             stderr: binary(),
             truncated?: boolean()
           }}
          | {:could_not_run, term()}

  @doc """
  The byte limit each captured stream is truncated at.

  Configurable because a build log and a linter's verdict want different
  ceilings, and a limit that cannot be raised becomes a reason to capture
  nothing.
  """
  @spec capture_limit_bytes() :: pos_integer()
  def capture_limit_bytes do
    :ex_sandbox
    |> Application.get_env(:beam, [])
    |> Keyword.get(:exec_capture_limit_bytes, @default_limit_bytes)
  end

  @doc """
  The default environment a command runs with inside a sandbox.

  ⚠️ `PATH` is named explicitly. The sandbox's environment is built by `env -i`
  with an ERTS-only allowlist (`005-FR-004`), so a child inherits no `PATH` and
  every bare command name fails `:enoent` — which reads exactly like the sandbox
  *refusing* the operation. That ambiguity is the one thing this seam exists to
  remove, so the directories are named rather than hoped for.
  """
  @spec default_env() :: [{String.t(), String.t()}]
  def default_env, do: [{"PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}]

  @doc false
  # Public for the same reason `ExSandbox.Mechanism.Beam.probe_exprs/3` is: the
  # source is written here and evaluated on the far side, so nothing else can
  # check that the two agree. `ExSandbox.Mechanism.Beam.ExecCaptureTest`
  # evaluates exactly these expressions in the test VM, which is the only way
  # the chunking and truncation behaviour is measurable on a host that cannot
  # provision a sandbox at all.
  @spec runner_exprs(String.t(), [String.t()], keyword()) :: [tuple()]
  def runner_exprs(cmd, args, opts \\ []) when is_binary(cmd) and is_list(args) do
    limit = Keyword.get(opts, :limit_bytes, capture_limit_bytes())
    env = Keyword.get(opts, :env, default_env())
    shell = Keyword.get(opts, :shell, "/bin/sh")
    dir = Keyword.get(opts, :stderr_dir)

    source = """
    Limit = #{limit},
    ShellPath = #{term(shell)},
    StderrDir = #{stderr_dir_expr(dir)},
    StderrPath = filename:join(StderrDir, #{term(stderr_basename())}),
    Env = [{"EX_SANDBOX_STDERR", StderrPath} | #{term(env)}],
    case os:find_executable(#{term(cmd)}, #{term(path_of(env))}) of
      false ->
        {ex_sandbox_exec, could_not_run, {executable_not_found, #{term(cmd)}}};
      Resolved ->
        Argv = [#{term("-c")}, #{term(script())}, Resolved | #{term(args)}],
        case file:write_file(StderrPath, <<>>) of
          {error, WriteReason} ->
            {ex_sandbox_exec, could_not_run,
             {stderr_capture_unavailable, StderrDir, WriteReason}};
          ok ->
            Opened = try
              {ok, erlang:open_port({spawn_executable, ShellPath},
                                    [binary, exit_status, eof, use_stdio,
                                     {args, Argv}, {env, Env}])}
            catch
              Kind:Why -> {error, {Kind, Why}}
            end,
            case Opened of
              {error, OpenReason} ->
                file:delete(StderrPath),
                {ex_sandbox_exec, could_not_run, {spawn_failed, ShellPath, OpenReason}};
              {ok, Port} ->
                Collect = fun Collect(Acc, Size, Trunc, Status, Eof) ->
                  case (Status =/= undefined) andalso Eof of
                    true -> {Status, iolist_to_binary(Acc), Trunc};
                    false ->
                      receive
                        {Port, {data, Bin}} ->
                          Room = Limit - Size,
                          BinSize = byte_size(Bin),
                          if
                            Room =< 0 ->
                              Collect(Acc, Size + BinSize, true, Status, Eof);
                            BinSize =< Room ->
                              Collect([Acc, Bin], Size + BinSize, Trunc, Status, Eof);
                            true ->
                              Collect([Acc, binary:part(Bin, 0, Room)], Size + BinSize, true,
                                      Status, Eof)
                          end;
                        {Port, eof} ->
                          Collect(Acc, Size, Trunc, Status, true);
                        {Port, {exit_status, S}} ->
                          Collect(Acc, Size, Trunc, S, Eof)
                      end
                  end
                end,
                {ExitStatus, Stdout, StdoutTrunc} = Collect([], 0, false, undefined, false),
                catch erlang:port_close(Port),
                {Stderr, StderrTrunc} = case file:read_file(StderrPath) of
                  {ok, ErrBin} when byte_size(ErrBin) > Limit ->
                    {binary:part(ErrBin, 0, Limit), true};
                  {ok, ErrBin} -> {ErrBin, false};
                  {error, _} -> {<<>>, false}
                end,
                file:delete(StderrPath),
                {ex_sandbox_exec, ok, ExitStatus, Stdout, StdoutTrunc, Stderr, StderrTrunc}
            end
        end
    end.
    """

    {:ok, tokens, _} = source |> String.to_charlist() |> :erl_scan.string()
    {:ok, exprs} = :erl_parse.parse_exprs(tokens)
    exprs
  end

  @doc """
  Turns whatever the sandbox-side runner returned into the seam's result shape.

  Anything unrecognised is `:could_not_run`, never a synthesised exit status.
  `008-FR-016`/`FR-026` rest on that direction: an attempt whose outcome we
  cannot read has *not* failed, and reporting it as a failure spends a
  refinement iteration the run is not allowed to spend.
  """
  @spec decode(term()) :: outcome()
  def decode({:value, value, _bindings}), do: decode(value)

  def decode({:ex_sandbox_exec, :ok, status, stdout, out_trunc, stderr, err_trunc})
      when is_integer(status) and is_binary(stdout) and is_binary(stderr) do
    {:ok,
     %{
       exit_status: status,
       stdout: stdout,
       stderr: stderr,
       # One flag for both streams, as `008/data-model.md` specifies. It is the
       # disjunction rather than a per-stream pair because the question a caller
       # asks is "am I looking at the whole thing", and the answer is no if
       # either half was cut.
       truncated?: out_trunc or err_trunc
     }}
  end

  def decode({:ex_sandbox_exec, :could_not_run, reason}), do: {:could_not_run, reason}

  def decode(other), do: {:could_not_run, {:unrecognised_runner_result, other}}

  # The `PATH` the command is resolved against, taken from the very environment
  # the command will run with -- so resolution and execution can never disagree.
  defp path_of(env) do
    Enum.find_value(env, "", fn
      {"PATH", value} -> value
      _ -> nil
    end)
  end

  # `exec` replaces the shell, so no `sh` lingers as the child's parent holding
  # the pipes open after it exits.
  defp script, do: ~s(exec "$0" "$@" </dev/null 2>>"$EX_SANDBOX_STDERR")

  # The sandbox's own writable storage, which `env -i`'s allowlist grants as
  # `HOME` (see `stdio_control_test.exs`). `/tmp` is deliberately NOT the
  # fallback's first choice: `confinement_args/2` gives the sandbox a fresh
  # mount view containing only the runtime read-only binds, its own storage
  # read-write, `/proc` and `/dev` — there is no `/tmp` in it at all, and the
  # isolation group relies on there not being one.
  defp stderr_dir_expr(nil) do
    ~s|case os:getenv("HOME") of false -> "."; Home -> Home end|
  end

  defp stderr_dir_expr(dir) when is_binary(dir), do: term(dir)

  defp stderr_basename do
    ".ex_sandbox_exec_#{System.system_time(:nanosecond)}_#{System.unique_integer([:positive])}.err"
  end

  # Erlang source for an Elixir term, with strings rendered as Erlang strings
  # rather than binaries: `open_port`'s `args` and `env` both want charlists.
  defp term(value), do: value |> to_erlang() |> then(&:io_lib.format(~c"~w", [&1])) |> to_string()

  defp to_erlang(value) when is_binary(value), do: String.to_charlist(value)
  defp to_erlang({a, b}), do: {to_erlang(a), to_erlang(b)}
  defp to_erlang(list) when is_list(list), do: Enum.map(list, &to_erlang/1)
  defp to_erlang(other), do: other
end

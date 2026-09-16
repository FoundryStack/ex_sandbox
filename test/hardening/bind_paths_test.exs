defmodule ExSandbox.Hardening.BindPathsTest do
  @moduledoc """
  Every path the launch binds must exist on the host, and the runtime it
  execs must be inside the mount view (005 T036d, FR-010).

  ## The two bugs this exists to prevent

  **`/lib64` was bound unconditionally.** It does not exist on arm64 Debian —
  the 64-bit loader lives in `/lib/aarch64-linux-gnu`. `bwrap` refuses to start
  when a `--ro-bind` source is missing:

      bwrap: Can't find source path /lib64: No such file or directory

  So every launch failed on any host without that directory, which is every
  arm64 Linux host and some x86_64 ones. The command was written against one
  distribution's layout and encoded it as a constant.

  **The Erlang runtime was not bound at all.** The command binds `/usr`, `/lib`,
  and `/lib64`, then execs `#{"/usr/local/lib/erlang/erts-N/bin/erlexec"}` — a
  path under `/usr/local`, which none of those binds covers. Even with `/lib64`
  fixed the sandbox could not see its own runtime.

  These are the same mistake in two places: assuming a filesystem layout rather
  than asking for one. Both are checked here against the *running* host, so the
  assertion is about a real layout rather than an assumed one.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Hardening.Linux

  defp args do
    {:ok, {_prog, args}} =
      Linux.compose_for_inspection(
        %ExSandbox.Sandbox{
          id: "sb-#{System.unique_integer([:positive])}",
          owner_ref: "owner-1",
          template_ref: "tpl",
          memory_limit_mb: 256,
          cpu_limit: 500,
          disk_quota_mb: 1024
        },
        []
      )

    args
  end

  # Every `--ro-bind SRC DEST` pair in the command.
  defp ro_bind_sources(args) do
    args
    |> Enum.with_index()
    |> Enum.filter(fn {arg, _i} -> arg == "--ro-bind" end)
    |> Enum.map(fn {_arg, i} -> Enum.at(args, i + 1) end)
  end

  describe "read-only binds" do
    @tag :isolation
    test "name only paths that exist on this host" do
      missing = Enum.reject(ro_bind_sources(args()), &File.exists?/1)

      assert missing == [],
             """
             bwrap refuses to start when a --ro-bind source is missing:

                 bwrap: Can't find source path #{List.first(missing)}

             Missing on this host (#{:erlang.system_info(:system_architecture)}):
             #{inspect(missing)}

             A hardcoded path that happens to exist on the author's distribution
             fails every launch on hosts laid out differently.
             """
    end

    test "cover the directory holding erlexec, or the sandbox cannot exec its runtime" do
      args = args()
      erlexec = Enum.find(args, &String.ends_with?(to_string(&1), "erlexec"))

      assert erlexec, "no erlexec in the composed command"

      sources = ro_bind_sources(args) ++ bind_sources(args)

      assert Enum.any?(sources, &String.starts_with?(to_string(erlexec), to_string(&1))),
             """
             The command execs #{erlexec} but binds none of its parent
             directories: #{inspect(sources)}

             `bwrap` builds the mount view from these binds alone, so a runtime
             outside all of them is not present in the sandbox at all.
             """
    end
  end

  describe "trust store" do
    # Without it an allowlisted HTTPS destination is permitted by egress and
    # then refused by TLS: `curl: (77) error setting certificate file`.
    test "is bound read-only when the host keeps one under /etc" do
      expected =
        Enum.filter(
          ["/etc/ssl/certs", "/etc/pki/ca-trust/extracted", "/etc/pki/tls/certs"],
          &File.dir?/1
        )

      sources = ro_bind_sources(args())

      assert Enum.all?(expected, &(&1 in sources)),
             "trust store directories #{inspect(expected)} not all in #{inspect(sources)}"

      refute "/etc" in (sources ++ bind_sources(args())),
             "the whole of /etc is in the mount view; only the trust store may be"
    end
  end

  describe "extra_ro_binds" do
    setup do
      previous = Application.get_env(:ex_sandbox, :beam)
      on_exit(fn -> Application.put_env(:ex_sandbox, :beam, previous || []) end)
    end

    test "binds each configured path read-only at the same path" do
      Application.put_env(
        :ex_sandbox,
        :beam,
        Keyword.put(Application.get_env(:ex_sandbox, :beam, []), :extra_ro_binds, [
          "/run/pooler"
        ])
      )

      args = args()

      i =
        Enum.find_index(
          Enum.chunk_every(args, 3, 1),
          &(&1 == ["--ro-bind", "/run/pooler", "/run/pooler"])
        )

      assert i, "no --ro-bind /run/pooler /run/pooler in #{inspect(args)}"
      refute "/run/pooler" in bind_sources(args), "the configured path was bound read-write"
    end

    test "refuses a relative path rather than binding it" do
      Application.put_env(
        :ex_sandbox,
        :beam,
        Keyword.put(Application.get_env(:ex_sandbox, :beam, []), :extra_ro_binds, ["run/pooler"])
      )

      assert_raise ArgumentError, ~r/absolute paths/, fn -> args() end
    end
  end

  defp bind_sources(args) do
    args
    |> Enum.with_index()
    |> Enum.filter(fn {arg, _i} -> arg == "--bind" end)
    |> Enum.map(fn {_arg, i} -> Enum.at(args, i + 1) end)
  end
end

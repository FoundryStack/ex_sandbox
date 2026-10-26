defmodule ExSandbox.Gateway.LauncherTest do
  @moduledoc """
  The gateway launcher (`priv/gateway/launcher`) and `NodeLauncher.via/2`,
  the two ends of a launch through `exec_via:`. The launcher execs only an
  argv of `ExSandbox.Hardening.Linux`'s shape.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Hardening.Linux
  alias ExSandbox.Mechanism.Beam.NodeLauncher

  @launcher Path.expand("../../priv/gateway/launcher", __DIR__)
  @via ["ssh", "-T", "gw@10.77.0.2", "--", "launch"]

  defp composed do
    sandbox =
      struct!(ExSandbox.Sandbox,
        id: "via-#{System.unique_integer([:positive])}",
        owner_ref: "o",
        template_ref: "t",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 256
      )

    {:ok, exec} = Linux.compose_for_inspection(sandbox, [])
    exec
  end

  # A stand-in for systemd-run that prints the argv it was given.
  defp echo_systemd_run(tmp_dir) do
    path = Path.join(tmp_dir, "systemd-run")
    File.write!(path, ~s(#!/bin/sh\nfor a in "$@"; do printf '%s\\n' "$a"; done\n))
    File.chmod!(path, 0o755)
    path
  end

  defp run_launcher(request, tmp_dir, slice_dir \\ "/nonexistent") do
    System.cmd("sh", [@launcher, slice_dir, echo_systemd_run(tmp_dir)],
      env: [{"SSH_ORIGINAL_COMMAND", request}],
      stderr_to_stdout: true
    )
  end

  # What ssh hands the forced command: the remote words joined by spaces.
  defp request({_ssh, args}, peer_args) do
    [_launch | words] = Enum.drop_while(args, &(&1 != "launch"))
    Enum.join(["launch" | words] ++ peer_args, " ")
  end

  describe "via/2" do
    test "no prefix leaves the command as it is" do
      exec = composed()
      assert NodeLauncher.via(exec, nil) == {:ok, exec}
    end

    test "the prefix runs first and the argv rides as one token after it" do
      {prog, args} = composed()
      assert {:ok, {"ssh", via_args}} = NodeLauncher.via({prog, args}, @via)

      assert Enum.take(via_args, 4) == tl(@via)
      assert [token] = Enum.drop(via_args, 4)
      assert Base.decode64!(token) |> String.split("\n") == [prog | args]
    end

    test "an argument that cannot travel is refused" do
      assert {:error, :mechanism_error} = NodeLauncher.via({"systemd-run", ["a\nb"]}, @via)
      assert {:error, :mechanism_error} = NodeLauncher.via({"systemd-run", [""]}, @via)
    end
  end

  describe "the launcher" do
    @describetag :tmp_dir

    test "execs the hardened argv, with the peer's arguments after it", %{tmp_dir: tmp_dir} do
      {_prog, args} = exec = composed()
      {:ok, via} = NodeLauncher.via(exec, @via)

      {out, 0} = run_launcher(request(via, ["-setcookie", "abc", "-hidden"]), tmp_dir)

      assert String.split(out, "\n", trim: true) == args ++ ["-setcookie", "abc", "-hidden"]
    end

    test "refuses an argv not of the hardened shape", %{tmp_dir: tmp_dir} do
      {prog, args} = composed()

      refusals = [
        {"a shell", {"/bin/sh", ["-c", "id"]}},
        {"setpriv to root",
         {prog, swap(args, &String.starts_with?(&1, "--reuid="), "--reuid=0")}},
        {"no new privileges dropped", {prog, List.delete(args, "--no-new-privs")}},
        {"another systemd property", {prog, ["-p", "Delegate=yes" | args]}},
        {"no env -i", {prog, List.delete(args, "-i")}},
        {"no bwrap", {prog, swap(args, &(&1 == "bwrap"), "unshare")}}
      ]

      for {label, exec} <- refusals do
        {:ok, via} = NodeLauncher.via(exec, @via)
        {out, status} = run_launcher(request(via, []), tmp_dir)

        assert status == 64, "#{label} was launched: #{out}"
        assert out =~ "refused"
      end
    end

    test "refuses a peer argument carrying anything but plain words", %{tmp_dir: tmp_dir} do
      {:ok, via} = NodeLauncher.via(composed(), @via)
      {out, 64} = run_launcher(request(via, ["$(id)"]), tmp_dir)
      assert out =~ "peer argument"
    end

    test "answers ping and samples the slice", %{tmp_dir: tmp_dir} do
      assert {"pong\n", 0} = run_launcher("ping", tmp_dir)

      File.write!(Path.join(tmp_dir, "memory.current"), "1048576\n")
      File.write!(Path.join(tmp_dir, "memory.max"), "max\n")
      assert {"1048576 max\n", 0} = run_launcher("sample", tmp_dir, tmp_dir)
    end

    test "samples a sandbox's peak and resets it", %{tmp_dir: tmp_dir} do
      scope = Path.join(tmp_dir, "sandbox-abc-1.scope")
      File.mkdir_p!(scope)
      File.write!(Path.join(tmp_dir, "memory.current"), "1048576\n")
      File.write!(Path.join(scope, "memory.peak"), "3145728\n")
      File.write!(Path.join(scope, "memory.current"), "2097152\n")

      assert {"3145728\n", 0} = run_launcher("sample abc-1", tmp_dir, tmp_dir)
      assert File.read!(Path.join(scope, "memory.peak")) == "0"
    end

    test "samples memory.current where the peak cannot be reset", %{tmp_dir: tmp_dir} do
      scope = Path.join(tmp_dir, "sandbox-abc-1.scope")
      File.mkdir_p!(scope)
      File.write!(Path.join(tmp_dir, "memory.current"), "1048576\n")
      File.write!(Path.join(scope, "memory.peak"), "3145728\n")
      File.write!(Path.join(scope, "memory.current"), "2097152\n")
      File.chmod!(Path.join(scope, "memory.peak"), 0o444)

      assert {"2097152\n", 0} = run_launcher("sample abc-1", tmp_dir, tmp_dir)

      File.rm!(Path.join(scope, "memory.peak"))
      assert {"2097152\n", 0} = run_launcher("sample abc-1", tmp_dir, tmp_dir)
    end

    test "refuses a sandbox id that could leave the slice", %{tmp_dir: tmp_dir} do
      File.write!(Path.join(tmp_dir, "memory.current"), "1048576\n")
      assert {out, 64} = run_launcher("sample ../x", tmp_dir, tmp_dir)
      assert out =~ "sandbox id"
    end

    test "conform names the groups a host without user namespaces fails", %{tmp_dir: tmp_dir} do
      assert conform(tmp_dir, bwrap_status: 1) == "filesystem_confinement\nnetwork_restriction\n"
      assert conform(tmp_dir, bwrap_status: 0) == ""
    end

    test "refuses an unknown verb", %{tmp_dir: tmp_dir} do
      assert {_out, 64} = run_launcher("shell", tmp_dir)
    end
  end

  # The host's tools as stand-ins: bwrap answers `bwrap_status`, the rest succeed.
  defp conform(tmp_dir, bwrap_status: bwrap_status) do
    bin = Path.join(tmp_dir, "bin")
    File.mkdir_p!(bin)

    for {tool, status} <- [bwrap: bwrap_status, setpriv: 0, pasta: 0] do
      path = Path.join(bin, to_string(tool))
      File.write!(path, "#!/bin/sh\nexit #{status}\n")
      File.chmod!(path, 0o755)
    end

    {out, 0} =
      System.cmd("sh", [@launcher, "/nonexistent", echo_systemd_run(tmp_dir)],
        env: [{"SSH_ORIGINAL_COMMAND", "conform"}, {"PATH", bin <> ":/usr/bin:/bin"}]
      )

    out
  end

  defp swap(args, match?, replacement) do
    Enum.map(args, &if(match?.(&1), do: replacement, else: &1))
  end
end

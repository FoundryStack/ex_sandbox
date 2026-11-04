defmodule ExSandbox.Mechanism.DockerOwnerTest do
  @moduledoc """
  `list_running/0` reports only the containers this host created and left
  listed, so two hosts on one daemon never reconcile each other's sandboxes.

  Run against a `docker` on `PATH` that answers `ps` from the labels each
  container was created with, so no daemon is needed.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  @fake_docker """
  #!/bin/sh
  [ "$1" = ps ] || exit 1
  shift
  wanted=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --filter) case "$2" in label=*) wanted="$wanted ${2#label=}";; esac; shift 2;;
      *) shift;;
    esac
  done
  while read -r id labels; do
    ok=1
    for want in $wanted; do
      case ",$labels," in *",$want,"*) ;; *) ok=0;; esac
    done
    [ $ok = 1 ] && echo "$id"
  done < "$FAKE_DOCKER_CONTAINERS"
  exit 0
  """

  setup do
    dir = Path.join(System.tmp_dir!(), "docker-owner-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    File.write!(Path.join(dir, "docker"), @fake_docker)
    File.chmod!(Path.join(dir, "docker"), 0o755)

    path = System.get_env("PATH")
    config = Application.get_env(:ex_sandbox, :docker)
    System.put_env("PATH", dir <> ":" <> path)
    System.put_env("FAKE_DOCKER_CONTAINERS", Path.join(dir, "containers"))

    on_exit(fn ->
      System.put_env("PATH", path)
      System.delete_env("FAKE_DOCKER_CONTAINERS")
      restore(config)
      File.rm_rf!(dir)
    end)

    %{containers: Path.join(dir, "containers")}
  end

  defp restore(nil), do: Application.delete_env(:ex_sandbox, :docker)
  defp restore(config), do: Application.put_env(:ex_sandbox, :docker, config)

  defp as_owner(owner), do: Application.put_env(:ex_sandbox, :docker, owner: owner)

  defp created(id, overrides \\ []) do
    sandbox = struct!(%Sandbox{id: id, owner_ref: "test", template_ref: "alpine:3"}, overrides)

    labels =
      sandbox
      |> Docker.create_args()
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.flat_map(fn
        ["--label", label] -> [label]
        _ -> []
      end)

    "#{id} #{Enum.join(labels, ",")}"
  end

  test "lists the containers this owner created, not another owner's", %{containers: file} do
    as_owner("reelsberry")
    mine = created("mine")
    as_owner("axonn")
    theirs = created("theirs")
    legacy = "legacy ex_sandbox.mechanism=docker,ex_sandbox.sandbox_id=legacy"
    File.write!(file, Enum.join([mine, theirs, legacy], "\n") <> "\n")

    as_owner("reelsberry")
    assert {:ok, ["mine"]} = Docker.list_running()
    as_owner("axonn")
    assert {:ok, ["theirs"]} = Docker.list_running()
  end

  test "does not list a sandbox created unlisted", %{containers: file} do
    as_owner("reelsberry")
    File.write!(file, created("kept") <> "\n" <> created("one-shot", listed: false) <> "\n")

    assert {:ok, ["kept"]} = Docker.list_running()
  end

  test "an unconfigured host owns its containers as \"default\"", %{containers: file} do
    Application.delete_env(:ex_sandbox, :docker)
    File.write!(file, created("plain") <> "\n")

    assert Docker.owner() == "default"
    assert {:ok, ["plain"]} = Docker.list_running()
  end
end

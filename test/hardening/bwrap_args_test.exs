defmodule ExSandbox.Hardening.BwrapArgsTest do
  @moduledoc """
  The `bwrap` layer must be a command `bwrap` will actually accept
  (005 T036c, FR-009, FR-010).

  ## The bug this exists to prevent

  The composed command ended with `--size 256M`, intended as the disk quota.
  Two things were wrong with it, and `bwrap` rejects the command outright:

      bwrap: --size takes a non-zero number of bytes

  `--size` takes **raw bytes** — `268435456`, not `256M`. And per `bwrap --help`
  it "Set[s] size of next argument (only for --tmpfs)", so even spelled
  correctly it modifies a `--tmpfs` that must follow it. Trailing the argument
  list, it modified nothing.

  The quota it was reaching for comes from elsewhere anyway: `storage_path/1`
  binds a directory on an already quota-limited filesystem, which is what
  `probe_disk_quota/0` checks for. The argument was both malformed and
  redundant — but because it was the *last* argument, the failure it caused
  looked like a launch problem rather than a quota one.

  ## Why the argument shape is asserted here rather than in a launch test

  A launch test would have caught it, on Linux, if one could run. This assertion
  is host-independent, so the composition stays checked on the machine where the
  code is written rather than only where it can run.
  """
  use ExUnit.Case, async: true

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

  describe "--size" do
    test "if present, is given raw bytes and immediately precedes a --tmpfs" do
      args = args()

      case Enum.find_index(args, &(&1 == "--size")) do
        nil ->
          # The supported outcome: the quota comes from the bound filesystem, so
          # no `--size` is needed at all.
          refute "--size" in args

        index ->
          value = Enum.at(args, index + 1)

          assert value =~ ~r/^\d+$/,
                 "--size takes raw bytes; got #{inspect(value)}, which bwrap rejects"

          assert Enum.at(args, index + 2) == "--tmpfs",
                 "--size only modifies a following --tmpfs; here it modifies " <>
                   inspect(Enum.at(args, index + 2))
      end
    end
  end

  describe "the confinement layer" do
    test "binds the sandbox's own storage read-write" do
      args = args()
      assert "--bind" in args
    end

    test "unshares the network, denying peer and platform reachability" do
      assert "--unshare-net" in args()
    end

    test "binds the runtime read-only rather than the whole filesystem" do
      args = args()
      assert "--ro-bind" in args
      refute Enum.any?(Enum.zip(args, tl(args)), fn {a, b} -> a == "--bind" and b == "/" end)
    end
  end
end

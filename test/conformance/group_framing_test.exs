defmodule ExSandbox.Conformance.GroupFramingTest do
  @moduledoc """
  `T043a`: a capability gap must read the same however it was raised.

  ⚠️ This asserts on **message text**, which is usually a brittle thing to test.
  It is the subject here rather than an implementation detail: the whole value of
  the third outcome is that a reader can tell "this host could not run the check"
  from "this mechanism is broken", and that distinction lives entirely in the
  wording. A gap raised from a group's `setup` bypassed `check/2`'s rescue and
  was reported as a bare exception -- the same verdict, stripped of the one thing
  that explained it.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Conformance.CapabilityUnavailable
  alias ExSandbox.Conformance.Group

  test "the framing names the third outcome and points at FR-012b" do
    message =
      Group.not_demonstrated(%CapabilityUnavailable{
        capability: :demo,
        detail: "no such thing on this host"
      })

    assert message =~ "NOT DEMONSTRATED"

    assert message =~ "neither a pass nor a mechanism defect",
           "the framing no longer says a capability gap is not a mechanism defect, " <>
             "which is the distinction it exists to draw"

    assert message =~ "FR-012b",
           "the framing no longer cites the requirement forbidding an undemonstrated " <>
             "guarantee from reporting as a pass"

    assert message =~ "Host capability unavailable: :demo",
           "the underlying cause was dropped, leaving no way to tell which capability " <>
             "was missing"

    assert message =~ "no such thing on this host",
           "the capability's own detail was dropped -- the part that tells an operator " <>
             "what to install"
  end

  test "check/2 and guarded_setup/1 share one framing so they cannot drift" do
    # Both macros call `not_demonstrated/1` rather than each building their own
    # string. If someone reintroduces a second copy, this catches the divergence
    # that made a `setup`-raised gap read differently from a body-raised one.
    source = File.read!("lib/ex_sandbox/conformance/group.ex")

    assert source |> String.split("NOT DEMONSTRATED") |> length() == 2,
           "the framing text appears more than once in group.ex -- `check/2` and " <>
             "`guarded_setup/1` must both delegate to `not_demonstrated/1`"
  end
end

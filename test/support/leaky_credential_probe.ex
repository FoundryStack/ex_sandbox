defmodule ExSandbox.LeakyCredentialProbe do
  @moduledoc """
  A credential probe whose credential reaches everything (005 T060g).

  This is the credentials group's `ExSandbox.PorousMechanism`: a probe backed by
  a credential that is, in effect, a superuser. It is **not** a strawman, and
  that matters — the moduledoc of the group it tests names the exact defect it
  reproduces:

    * the role exists and the sandbox can read it
    * the credential opens the sandbox's *own* store, so the positive control
      passes
    * rotation returns a genuinely new secret without touching the sandbox

  Every supporting signal says the credential model works. The only thing wrong
  is the thing the group exists to establish: the credential is refused
  **nowhere**. `013-FR-008` and `013-FR-009` are the two negative claims that
  make the model worth having, and a probe like this fails both while passing
  everything else.

  This is what a `REVOKE` that returns success while revoking nothing looks like
  from the outside, and PostgreSQL's `CONNECT`-to-`PUBLIC` default (003 T023/T031)
  produced precisely this shape against a live server.

  ## The secret also leaks

  `secret_value/1` returns a string that `inspect/1` renders in full, because
  the credential is a plain map with no `Inspect` implementation and no
  redaction. `FR-021` asserts the opposite, so that check must fail here too.

  A probe that redacted correctly would leave the leak check unexercised, and
  the meta-test could not tell "the check works" from "the check never looked".
  """

  @behaviour ExSandbox.Conformance.Credentials.Probe

  # A literal, so `inspect/1` renders it verbatim and the `FR-021` check has
  # something real to find. A generated value would work equally well; a fixed
  # one makes a failure message legible.
  @secret "leaky-probe-secret-do-not-redact"

  @impl true
  def read_credential(sandbox) do
    # Plain map: no `Inspect` implementation, nothing marked sensitive. This is
    # the default shape a credential takes when nobody has thought about it.
    {:ok, %{sandbox_id: sandbox.id, username: "tenant_#{sandbox.id}", password: @secret}}
  end

  @impl true
  # Connects to *any* store, its own or another sandbox's. The whole defect.
  def attempt_connection(_credential, _sandbox), do: {:ok, :connected}

  @impl true
  # And to the platform's own database, which is the half that was found broken
  # when research R3's SQL was first run against a live server.
  def attempt_platform_connection(_credential), do: {:ok, :connected}

  @impl true
  def rotate(sandbox) do
    # Rotation genuinely works. A probe that broke here would fail the rotation
    # check for a reason unrelated to containment, and the meta-test's claim
    # would get weaker rather than sharper.
    {:ok,
     %{
       sandbox_id: sandbox.id,
       username: "tenant_#{sandbox.id}",
       password: @secret <> "-rotated-#{System.unique_integer([:positive])}"
     }}
  end

  @impl true
  def secret_value(%{password: password}), do: password
end

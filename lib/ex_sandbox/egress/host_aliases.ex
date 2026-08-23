defmodule ExSandbox.Egress.HostAliases do
  @moduledoc """
  Every address that **is this host**, as this host currently reports itself
  (029 T014's supply half, `029-FR-015`, D103).

  ## Why this exists as a separate module

  `ExSandbox.Egress.Allowlist.parse/2` takes the alias set as **data** and must
  keep doing so: it is the module that transfers whole to a second mechanism
  precisely because it names no mechanism, and a capability query from inside it
  would be the re-coupling that argument forbids. So somebody has to *produce*
  the list, and that somebody is here — on the platform side of the seam, where
  knowing about interfaces and routing tables is allowed.

  ⚠️ **Discovered, never configured, and the difference is the whole point.**
  A configured constant would be right in the config file and wrong in the
  namespace, and the drift *is* the defect: every parse-time test stays green
  while the address actually in use is one no entry is refused for. The list is
  read from the running kernel at the moment it is needed.

  ## What counts as the host

  | source | why |
  |---|---|
  | every address on every interface (`:inet.getifaddrs/0`) | these are literally this machine, under every name it answers to |
  | the default gateway | see below |

  ⚠️ **The default gateway is included even though `--no-map-gw` is passed**,
  and that is belt-and-braces rather than confusion. `pasta`'s default is to map
  the namespace's gateway address onto the host, which makes it a second name
  for the host that is not `127.0.0.1` — the case D103 was written about. The
  flag turns that default off, so today the gateway is the real upstream router
  instead. Refusing it anyway costs an operator nothing they should have wanted
  (a sandbox has no business dialling the host's own next hop), and it means the
  exclusion does not quietly evaporate if the flag is ever dropped — which is
  exactly the kind of silent re-widening `netns.ex` documents `--no-map-gw`
  against.

  ⚠️ **`:host_alias` wins over `:rfc1918_private` when both match**, which is
  the ordering `Allowlist.host_class/2` already fixes. Nearly every address here
  is also private, so without that ordering this whole list would be invisible
  in the error an operator reads.

  ## What this cannot see

  Read at the moment of the call, so an address added afterwards is not in a
  list already produced. That is a real gap and is stated rather than papered
  over: the alternative — re-reading per comparison — would put a syscall
  inside a pure policy function, which is the coupling the seam exists to
  prevent. Provisioning is where the list is taken, and provisioning is also
  where the refusal must land, so the two are the same moment.

  ⚠️ It also cannot see a **name** for the host (`host.docker.internal` and
  friends). `Allowlist.parse/2` accepts names in the alias set and nothing here
  produces one, so an operator who writes a host *name* is not refused as
  `:host_alias` today. Unfixed here on purpose: guessing at names would produce
  a list that is wrong in a different direction, and the answer-side filter in
  `ExSandbox.Egress.Resolver` catches the name once it resolves.
  """

  require Logger

  @typedoc "An address that is this host."
  @type host_alias :: :inet.ip_address()

  @doc """
  Every address that is this host, right now.

  Returns `[]` on a host whose interfaces cannot be read — which is a **loss of
  a guard**, so it is logged rather than passing silently. It is not fatal: the
  static classes (`:loopback`, `:rfc1918_private`, …) still refuse most of what
  this list would have caught, so an empty answer narrows the guard rather than
  removing it.
  """
  @spec detect() :: [host_alias()]
  def detect do
    (interface_addresses() ++ default_gateways())
    |> Enum.uniq()
  end

  defp interface_addresses do
    case :inet.getifaddrs() do
      {:ok, interfaces} ->
        for {_name, options} <- interfaces,
            {:addr, address} <- options,
            do: address

      {:error, reason} ->
        Logger.warning("""
        egress: could not read this host's own addresses (#{inspect(reason)}).

        029-FR-015 excludes every alias for the host from what an allowlist may
        express, and the discovered half of that list is now empty. The static
        address classes still apply.
        """)

        []
    end
  end

  # ⚠️ Shelling out, and only where the tool exists. There is no portable BEAM
  # call for "what is this host's default route", and inventing one from
  # `getifaddrs` (guessing the gateway is the first host address of each
  # network) would produce a *wrong* address that reads as a right one. A host
  # without `ip(8)` — every developer macOS machine — contributes nothing here,
  # which is correct: it is not a host that runs sandboxes.
  defp default_gateways do
    case System.find_executable("ip") do
      nil ->
        []

      ip ->
        case System.cmd(ip, ["-4", "route", "show", "default"], stderr_to_stdout: true) do
          {output, 0} -> parse_default_via(output)
          _ -> []
        end
    end
  rescue
    # An `ErlangError` from `System.cmd/3` on a host where the binary vanished
    # between the lookup and the call. Losing a gateway is a narrowed guard, not
    # a failed provision.
    _ -> []
  end

  @doc """
  The gateway addresses in `ip route show default` output.

  Public so the parsing is testable on a host that has no `ip(8)` and no default
  route — which is every machine this is written on. A parser exercised only
  where the command runs is one whose failure mode is a silently empty guard.
  """
  @spec parse_default_via(String.t()) :: [host_alias()]
  def parse_default_via(output) when is_binary(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.flat_map(fn line ->
      case Regex.run(~r/\bdefault\s+via\s+(\S+)/, line) do
        [_, address] -> parse_address(address)
        _ -> []
      end
    end)
  end

  defp parse_address(text) do
    case :inet.parse_address(String.to_charlist(text)) do
      {:ok, address} -> [address]
      {:error, _} -> []
    end
  end
end

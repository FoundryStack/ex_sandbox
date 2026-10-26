import Config

if System.get_env("RELEASE_NAME") == "ex_sandbox_gateway" do
  runtime_dir = System.get_env("XDG_RUNTIME_DIR") || "/run/user/#{System.get_env("UID", "0")}"

  uids =
    case System.get_env("EX_SANDBOX_GATEWAY_UIDS") do
      nil ->
        nil

      list ->
        list |> String.split(",", trim: true) |> Enum.map(&String.to_integer(String.trim(&1)))
    end

  config :ex_sandbox,
         :gateway,
         [
           socket_path:
             System.get_env("EX_SANDBOX_GATEWAY_SOCKET") ||
               Path.join([runtime_dir, "ex-sandbox", "gateway.sock"]),
           store_dir:
             System.get_env("EX_SANDBOX_GATEWAY_STORE") ||
               Path.join([System.user_home!(), ".local", "state", "ex-sandbox", "allowlists"])
         ] ++ if(uids, do: [allowed_uids: uids], else: [])
end

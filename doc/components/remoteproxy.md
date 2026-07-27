# `remote_proxy`

The `remote_proxy` class manages a forward proxy for WPAD-based attacks. It supports two modes: running the proxy on the external server (remote mode) or on the Raspberry Pi (local mode). It is instantiated as follows:
```
proxy = remote_proxy();
```

## Methods

### `bring_up(state_up, state_err)`
Starts the proxy in the configured mode. In remote mode, the server starts a proxy on a random port and generates a PAC file. In local mode, a proxy is started locally on the Raspberry Pi and the server is instructed to host a PAC file pointing to it. The state machine enters state `state_up` if successful, and `state_err` in case of an error. At least `server` must be set before calling `bring_up()`. In local mode, `local_addr` must also be set. The `server_secret` variable or `secret` property must be set for authentication.

## Writable properties

### `server`
A string containing the URL of the VVTS server component (e.g. `https://yourserver.com/`). Set before invoking `bring_up()`.

### `secret`
A string containing the shared API secret. If not set, the global `server_secret` variable is used instead. Set before invoking `bring_up()`.

### `mode`
A string determining the proxy mode. Valid values are `"remote"` (default) and `"local"`. In remote mode, the server starts and manages the proxy. In local mode, the Raspberry Pi runs the proxy and the server only hosts the PAC file. Set before invoking `bring_up()`.

### `local_addr`
A string containing the address and port of the local proxy in `host:port` format (e.g. `192.168.60.1:8080`). This is the address that clients will connect to, as specified in the generated PAC file. Required when `mode` is `"local"`. Set before invoking `bring_up()`.

### `direct`
A string containing hosts that should bypass the proxy and use `DIRECT` in the generated PAC file. Entries are separated with semicolons (`;`) and may contain wildcard patterns (e.g. `192.168.60.1;*.local`). Only used in local mode. Set before invoking `bring_up()`.

# VLESS / 3x-ui control plane

## Trust boundary

The 3x-ui panel remains bound to loopback on the public VLESS host. Sentinel
must never expose the panel port through the public firewall. Management uses
two components:

1. `siem-xui-controller.service` runs on the VLESS host and talks to the local
   3x-ui HTTP API.
2. `siem-xui-reverse-tunnel.service` publishes only the controller loopback
   port to a loopback port on the trusted jump host.
3. SIEM-WEB reaches that loopback port through its existing private management
   channel and authenticates every request with a dedicated bearer token.

The UI and API support inbound inventory, inbound create/update/delete,
client create/update/delete, limits, expiration, traffic reset and generation
of a VLESS/Reality profile URI. The controller never returns a Reality private
key or 3x-ui credentials.

## VLESS host installation

Install the controller only after SSH connectivity to the VLESS host has been
restored. Keep the existing 3x-ui and Xray services in place.

As of 2026-08-03, there is no confirmed deployable management path to
`45.89.111.208`. A TCP connect to the public address is not sufficient: the
SSH handshake does not complete, and the operator documentation identifies
this host as a VLESS data-plane endpoint rather than a public management
entry. The jump host is reachable only through the private VPN path, and no
working jump-host-to-VLESS management hop has been verified. Do not open SSH
or the 3x-ui panel on the public interface to work around this.

Run the installer locally from a VPS console, or through a private SSH path
after that path has been independently restored. The default invocation is a
read-only plan. It does not call 3x-ui APIs, inspect or change inbounds, start
Xray, or alter firewall rules.

Prepare these files outside Git with `umask 077`:

- a controller environment based on `xui-controller.env.example`;
- a tunnel environment based on `xui-tunnel.env.example`;
- a dedicated reverse-tunnel private key;
- a `known_hosts` entry whose jump-host fingerprint was verified through a
  second trusted channel.

Set `XUI_PROTECTED_INBOUND_IDS` to every existing production inbound ID before
enabling the controller. The installer requires a non-empty list and will not
discover or modify it automatically. Generate a dedicated controller token of
at least 32 random characters and transfer the same value to the SIEM secret
store without placing it on a command line.

```bash
sudo python3 deploy/vless/install_xui_controller.py \
  --controller-env-source /root/xui-controller.env \
  --tunnel-env-source /root/xui-tunnel.env \
  --tunnel-key-source /root/xui-controller-tunnel_ed25519 \
  --jump-known-hosts-source /root/xui-controller-known_hosts \
  --enable-controller --enable-tunnel
```

Review the plan, then repeat the same command with `--apply`. Secret files that
already exist are preserved. A different source is rejected unless the
operator explicitly adds `--rotate-secrets` during an approved credential
rotation. The installer pins the SSH host key, creates dedicated unprivileged
service accounts, and checks the existing loopback panel before enabling the
controller. It never starts or reconfigures `x-ui.service`.

For a staged install without starting services, omit `--enable-controller` and
`--enable-tunnel`. This is useful when the code arrives through a console but
the private jump path is not ready yet.

```bash
sudo systemctl is-active siem-xui-controller.service siem-xui-reverse-tunnel.service
sudo ss -lntp | grep -E '127\.0\.0\.1:(2053|8787)'
```

Both controller endpoints must remain loopback-only. The reverse forward is
also bound to `127.0.0.1` on the jump host. No public listening port is added
on the VLESS VPS.

## SIEM-WEB configuration

Set these through the VM107 secret/environment deployment mechanism:

```text
SIEM_VLESS_CONTROLLER_URL=http://127.0.0.1:18787
SIEM_VLESS_CONTROLLER_TOKEN_REF=vault://secret/siem/vless-controller#token
SIEM_VLESS_PUBLIC_ENDPOINT=45.89.111.208:443/TCP
```

`SIEM_VLESS_CONTROLLER_TOKEN` may be supplied by the service credential loader,
but must not be written to documentation or committed files.

## Verification

1. Check the controller health from the VLESS host through loopback.
2. Check the tunnel service and the jump-host loopback listener.
3. Open **Security tools -> Remote access -> VLESS / Reality** in Sentinel.
4. Create a short-lived test profile, copy its URI, connect a test client and
   confirm traffic counters change.
5. Disable and delete only that test profile. Existing profiles and inbounds
   must remain unchanged.

For rollback, stop and disable only `siem-xui-reverse-tunnel.service` and
`siem-xui-controller.service`. Do not stop `x-ui.service` or Xray. Removing the
Sentinel controller has no data migration and must not alter existing inbounds.

If the VLESS server itself is unreachable, Sentinel reports `degraded` and
disables mutations. It must not invent successful operations or expose the
3x-ui panel as a workaround.

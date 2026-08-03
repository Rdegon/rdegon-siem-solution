# VLESS / 3x-ui control plane

## Security model

The 3x-ui panel and the Sentinel controller remain bound to VPS loopback. No
panel, controller, SSH or additional public management port is required. The
supported primary path is:

```text
SIEM-WEB -> 127.0.0.1:18787 -> Xray VLESS bridge -> existing VLESS port
         -> VPS 127.0.0.1:8787 controller -> VPS 127.0.0.1:<panel> 3x-ui
```

The VLESS bridge is a fixed-target `dokodemo-door`: it can reach only the
controller loopback port. It is not a general-purpose SOCKS proxy. The older
reverse-SSH service remains an optional fallback only when its complete
private path to the SIEM-WEB host is independently verified.

On its first successful start, the controller takes an atomic snapshot of all
existing inbound IDs. This production baseline is immutable. Baseline and
externally-created inbounds cannot be updated, disabled, adopted or deleted by
Sentinel. Only an inbound created by Sentinel after the snapshot can be
structurally managed, and inbound creation is disabled by default. Client
profile CRUD inside an existing VLESS inbound remains available.

The controller never returns 3x-ui credentials or Reality private keys. The
SIEM API accepts only an HTTP loopback controller URL and authenticates every
request using a dedicated secret-store token.

## Runtime blocker

As of 2026-08-03 there is no confirmed shell or console path to
`45.89.111.208`:

- TCP 443 is the active VLESS/Reality data plane;
- TCP 22 accepts a connection but does not complete an SSH banner exchange;
- the documented jump-host SSH path closes during key exchange;
- the only locally recovered VLESS URI fails its VLESS/Reality handshake and
  must not be used to enable the bridge;
- no controller is currently confirmed on VPS loopback port 8787.

Therefore the code can be installed safely, but the remote controller cannot
truthfully be reported as active until one authorized console/shell session is
available. Do not expose 3x-ui or weaken the VPS firewall to bypass this.

## One-time VPS installation

Keep `x-ui.service`, Xray and every existing inbound unchanged. Prepare a
controller environment from `deploy/vless/xui-controller.env.example` with
`umask 077`. Set the real loopback panel URL and credentials, a random
controller token of at least 32 characters, and:

```text
XUI_PROTECTED_INBOUND_IDS=auto
XUI_PROTECTION_STATE=/var/lib/siem-xui-controller/protection.json
XUI_ALLOW_INBOUND_CREATE=false
SIEM_XUI_TRANSPORT=vless-data-plane
```

First inspect the read-only plan, then apply it locally from the provider
console or a confirmed private shell:

```bash
sudo python3 deploy/vless/install_xui_controller.py \
  --controller-env-source /root/xui-controller.env \
  --enable-controller

sudo python3 deploy/vless/install_xui_controller.py \
  --controller-env-source /root/xui-controller.env \
  --enable-controller --apply
```

The installer does not call mutation APIs, alter firewall rules, or manage
`x-ui.service`. The controller performs one read-only inventory before it
starts listening and persists the immutable baseline with mode 0600.

## One-time SIEM bridge installation

Use a dedicated working VLESS profile as a secret. It may point to an existing
protected inbound; the installation does not alter that inbound. Prepare
`xui-vless-bridge.env.example` and a one-line URI file with `umask 077`:

```bash
sudo python3 deploy/vless/install_xui_vless_bridge.py \
  --env-source /root/xui-vless-bridge.env \
  --uri-source /root/xui-controller-vless-uri \
  --enable

sudo python3 deploy/vless/install_xui_vless_bridge.py \
  --env-source /root/xui-vless-bridge.env \
  --uri-source /root/xui-controller-vless-uri \
  --enable --apply
```

The renderer validates UUID, VLESS transport and Reality/TLS parameters,
creates an ephemeral Xray config under `/run`, and binds only
`127.0.0.1:18787`. The URI secret remains mode 0600 and is never printed.

Configure SIEM-WEB through its secret/environment deployment mechanism:

```text
SIEM_VLESS_CONTROLLER_URL=http://127.0.0.1:18787
SIEM_VLESS_CONTROLLER_TOKEN_REF=vault://secret/siem/vless-controller#token
SIEM_VLESS_PUBLIC_ENDPOINT=45.89.111.208:443/TCP
```

## Verification

1. On the VPS, verify `siem-xui-controller.service` and authenticated
   `http://127.0.0.1:8787/state`.
2. Confirm the state reports `immutable-baseline` and the expected baseline
   count before any profile mutation.
3. On SIEM-WEB, verify `siem-xui-vless-bridge.service` and loopback port 18787.
4. Open **VPN -> VLESS / Reality**. Confirm transport, panel and protection
   states are active and existing inbounds are marked immutable.
5. Create one short-lived client profile in an existing inbound, edit it,
   obtain its URI, connect it, verify counters, and delete only this test
   client.
6. Confirm the baseline inbound ID, port, protocol, enable flag and Reality
   settings did not change.

If the server-side Xray routing policy denies destinations in `127.0.0.0/8`,
the VLESS bridge cannot reach the controller. That policy must be inspected
during the authorized VPS session. It must not be changed automatically or by
this installer.

Rollback stops only `siem-xui-vless-bridge.service` and
`siem-xui-controller.service`. It must not stop 3x-ui/Xray or delete the
protection state. Keeping the state preserves the original immutable baseline
across reinstallations.

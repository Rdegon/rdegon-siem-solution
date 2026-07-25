# Lab-edge Suricata IDS

`configure_lab_edge_ids.py` manages the live VM102 capture configuration.

It:

- defines every current home and VPN network;
- captures `eth0-eth4` with AF_PACKET;
- validates the candidate with `suricata -T`;
- installs exact suppressions for known virtual-network artifacts;
- suppresses the informational APT user-agent signature that duplicates across
  pre-NAT and post-NAT interfaces;
- restarts Suricata only after validation;
- restores the previous files if validation or restart fails.

Install or update ET Open before applying the capture configuration:

```bash
sudo suricata-update
sudo python3 configure_lab_edge_ids.py --apply
```

If the direct ET download path is unreliable, download the official archive
through an approved transfer host and process it locally:

```bash
sudo suricata-update -s \
  --url file:///path/to/emerging.rules.tar.gz \
  --no-reload
sudo python3 configure_lab_edge_ids.py --apply
```

Validation:

```bash
systemctl is-active suricata
suricata --dump-config | grep -E '^af-packet\.[0-9]+\.(interface|cluster-id)'
for iface in eth0 eth1 eth2 eth3 eth4; do
  suricatasc -c "iface-stat ${iface}"
done
```

This deployment is IDS-only. Inline IPS belongs to the staged OPNsense
cutover described in `docs/soc_security_inventory_and_target_architecture_2026-07-25.md`.

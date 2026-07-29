# PostgreSQL standby recovery

The control-plane PostgreSQL primary runs on `siem-web` (`10.20.10.107`).
`siem-ingest` (`10.20.10.104`) is its streaming standby.

After a long outage, the standby can request a WAL segment that the primary has
already removed. Repeated `requested WAL segment ... has already been removed`
messages mean that restarting PostgreSQL cannot recover the replica.

Run the guarded rebuild from an operator workstation with the standard Proxmox
environment loaded:

```powershell
python deploy/network_relocation/repair_postgres_standby.py
```

The script:

1. verifies the exact PostgreSQL data path and internal primary address;
2. stops only the standby cluster;
3. moves the stale data directory under `/var/backups/postgresql`;
4. takes a fresh `pg_basebackup` over the `sec` network;
5. starts PostgreSQL and requires a streaming WAL receiver;
6. restores the previous data directory automatically if any step fails.

Successful output must contain:

```text
service=active
recovery=true
walreceiver=streaming
```

The stale backup is retained until the next verified backup cycle. Remove it
only after replication, application health, and cold-start checks pass.

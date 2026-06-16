ALTER TABLE siem.cmdb_assets DELETE WHERE asset_id IN
(
    'asset-siem-ingest',
    'asset-siem-processing',
    'asset-siem-storage',
    'asset-siem-web',
    'asset-siem-transport',
    'asset-proxmox-pve',
    'asset-lab-edge-01',
    'asset-minecraft-01',
    'asset-nextcloud-siem',
    'asset-navidrome-01',
    'asset-vuln-mgr-01',
    'asset-pilot-web-01',
    'asset-pilot-db-01',
    'asset-pilot-cache-01',
    'asset-openclaw-gateway',
    'asset-gamepanel-01',
    'asset-desktop-5jmjvbh',
    'asset-jump-host',
    'asset-vpn-host'
);

INSERT INTO siem.cmdb_assets
(asset_id, asset_type, hostname, ip, owner, criticality, environment, business_service, os_family, expected_ports, tags, notes, enabled)
VALUES
('asset-siem-ingest', 'server', 'siem-ingest', '192.168.1.35', 'rdegon', 'high', 'lab', 'Rdegon SIEM ingest', 'linux', '22,443,1514', 'siem,ingest,edge', 'Ingress node for JSON/syslog intake', 1),
('asset-siem-processing', 'server', 'siem-processing', '192.168.1.37', 'rdegon', 'high', 'lab', 'Rdegon SIEM processing', 'linux', '22,6379', 'siem,processing,redis', 'Normalizer and filter node', 1),
('asset-siem-storage', 'server', 'siem-storage', '192.168.1.38', 'rdegon', 'critical', 'lab', 'Rdegon SIEM storage', 'linux', '22,8123,9000', 'siem,storage,clickhouse', 'ClickHouse and correlation node', 1),
('asset-siem-web', 'server', 'siem-web', '192.168.1.39', 'rdegon', 'critical', 'lab', 'Rdegon SIEM web', 'linux', '22,443', 'siem,web,critical-asset', 'Web console node', 1),
('asset-siem-transport', 'server', 'siem-transport', '192.168.1.40', 'rdegon', 'critical', 'lab', 'Rdegon SIEM transport', 'linux', '22,9092,8123', 'siem,transport,kafka,clickhouse-standby', 'Kafka transport and ClickHouse standby node', 1),
('asset-proxmox-pve', 'hypervisor', 'pve', '192.168.1.101', 'rdegon', 'critical', 'lab', 'Proxmox VE host', 'linux', '22,8006', 'proxmox,pve,hypervisor,proxmox-fleet,critical-asset', 'Proxmox host and pve source telemetry', 1),
('asset-lab-edge-01', 'network', 'lab-edge-01', '192.168.1.102', 'soc-fleet', 'medium', 'lab', 'Lab edge and VPN gateway', 'linux', '22,53,443,51820', 'edge_gateway,router,vpn,suricata,proxmox-fleet,role:edge-gateway', 'Hostname alias for the lab edge gateway used by source events and Suricata telemetry', 1),
('asset-minecraft-01', 'server', 'minecraft-01', '192.168.1.32', 'soc-fleet', 'medium', 'lab', 'Minecraft server', 'linux', '22,25565', 'game,minecraft,linux_common,proxmox-fleet,role:minecraft', 'Game service LXC', 1),
('asset-nextcloud-siem', 'server', 'nextcloud-siem', '10.20.20.120', 'soc-fleet', 'high', 'lab', 'Nextcloud public service', 'linux', '22,80,443', 'public_services,nextcloud,linux_common,proxmox-fleet,role:nextcloud', 'Public services LXC', 1),
('asset-navidrome-01', 'server', 'navidrome-01', '10.20.20.121', 'soc-fleet', 'medium', 'lab', 'Navidrome public service', 'linux', '22,4533', 'public_services,navidrome,linux_common,proxmox-fleet,role:navidrome', 'Public services LXC', 1),
('asset-vuln-mgr-01', 'server', 'vuln-mgr-01', '10.20.30.122', 'soc-fleet', 'high', 'lab', 'Vulnerability manager', 'linux', '22,443,9392', 'vuln,scanner,security,linux_common,proxmox-fleet,role:vuln-manager', 'Vulnerability management and scanning node', 1),
('asset-pilot-web-01', 'server', 'pilot-web-01', '10.20.30.123', 'soc-fleet', 'high', 'lab', 'Pilot web tier', 'linux', '22,80,443', 'pilot,web,linux_common,proxmox-fleet,role:pilot-web', 'Pilot application web node', 1),
('asset-pilot-db-01', 'server', 'pilot-db-01', '10.20.30.124', 'soc-fleet', 'high', 'lab', 'Pilot database tier', 'linux', '22,5432', 'pilot,database,linux_common,proxmox-fleet,role:pilot-db', 'Pilot application database node', 1),
('asset-pilot-cache-01', 'server', 'pilot-cache-01', '10.20.30.125', 'soc-fleet', 'medium', 'lab', 'Pilot cache tier', 'linux', '22,6379', 'pilot,cache,linux_common,proxmox-fleet,role:pilot-cache', 'Pilot application cache node', 1),
('asset-openclaw-gateway', 'server', 'openclaw-gateway', '10.20.30.126', 'soc-fleet', 'high', 'lab', 'OpenClaw egress gateway', 'linux', '22,80,443', 'edge_gateway,public_services,gateway,openclaw,linux_common,proxmox-fleet,role:openclaw-gateway', 'Gateway node for OpenClaw traffic', 1),
('asset-gamepanel-01', 'server', 'gamepanel-01', '192.168.1.30', 'soc-fleet', 'high', 'lab', 'Game panel', 'linux', '22,80,443,8080,2022', 'game,public_services,gamepanel,pterodactyl,linux_common,proxmox-fleet,role:gamepanel', 'Pterodactyl/game panel host with additional service IP aliases', 1),
('asset-desktop-5jmjvbh', 'workstation', 'DESKTOP-5JMJVBH', '', 'rdegon', 'medium', 'lab', 'WIN-RTX-test operator workstation', 'windows', '', 'windows,endpoint,operator,win-rtx-test,identity-source', 'Current operator workstation and Windows telemetry source', 1),
('asset-jump-host', 'vpn', 'vpn-host-khanov', '176.108.250.215', 'rdegon', 'high', 'prod', 'Jump host', 'linux', '22', 'vpn,jump,edge', 'Public jump host with reverse access into the lab', 1),
('asset-vpn-host', 'vpn', 'vm15611031', '45.89.111.208', 'rdegon', 'high', 'prod', 'VPN gateway', 'linux', '22,443', 'vpn,edge,critical-asset', 'Public VLESS/Reality endpoint', 1);

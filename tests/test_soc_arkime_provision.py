from deploy.soc_arkime_provision import (
    MONITOR_INTERFACES,
    arkime_config,
    opensearch_overrides,
)


def test_arkime_captures_every_mirrored_segment() -> None:
    config = arkime_config()
    assert f"interface={';'.join(MONITOR_INTERFACES)}" in config
    assert set(MONITOR_INTERFACES) == {
        "enp6s19",
        "enp6s20",
        "enp6s21",
        "enp6s22",
        "enp6s23",
    }


def test_arkime_uses_dedicated_pcap_storage_and_bounded_retention() -> None:
    config = arkime_config()
    assert "pcapDir=/srv/arkime-pcap" in config
    assert "freeSpaceG=30" in config
    assert "maxFileTimeM=1" in config
    assert "pcapReadMethod=tpacketv3" not in config
    assert "snapLen=65535" in config
    assert "viewHost=0.0.0.0" in config
    assert "viewPort=8005" in config
    assert "elasticsearchBasicAuth=admin:$ARKIME_OPENSEARCH_PASSWORD" in config
    assert "caTrustFile=/etc/opensearch/root-ca.pem" in config
    assert "https://admin:" not in config


def test_opensearch_is_private_and_uses_dedicated_storage() -> None:
    config = opensearch_overrides()
    assert "network.host: 127.0.0.1" in config
    assert "path.data: /srv/arkime-opensearch" in config
    assert "discovery.type: single-node" in config

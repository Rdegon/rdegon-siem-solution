from services.normalizer.normalizer_core import apply_rules


def _normalize(message: str, source: str = "10.20.10.1") -> dict:
    event = apply_rules(
        [],
        {
            "source_type": "syslog",
            "source": source,
            "message": message,
        },
    )
    assert event is not None
    return event


def test_audit_rule_bootstrap_does_not_become_watched_file_change() -> None:
    event = _normalize(
        "<182>1 2026-07-27T06:00:00Z siem-web auditd - - - "
        'type=CONFIG_CHANGE msg=audit(1785132000.1:42): auid=4294967295 '
        'ses=4294967295 op=add_rule key="cron" list=4 res=1'
    )

    assert event["event.type"] == "linux_audit_rule_loaded"
    assert event["event.category"] == "configuration"
    assert event["event.severity"] == "info"


def test_auditctl_rule_load_is_not_audit_config_alert() -> None:
    event = _normalize(
        "<182>1 2026-07-27T06:00:00Z siem-web auditd - - - "
        'type=EXECVE msg=audit(1785132000.2:43): argc=4 '
        'a0="auditctl" a1="-w" a2="/etc/ssh/sshd_config" a3="-k" key="sshd_config"'
    )

    assert event["event.type"] == "linux_audit_rule_loaded"
    assert event["event.severity"] == "info"


def test_opnsense_filterlog_is_structured() -> None:
    event = _normalize(
        "<134>1 2026-07-27T06:00:00Z opnsense-staging.lab.home.arpa "
        "filterlog 17123 - [meta sequenceId=\"1277\"] "
        "7,,,rule-uuid,vtnet1,match,block,in,4,0x0,,1,34060,0,DF,"
        "17,udp,55,192.168.3.14,224.0.0.251,5353,5353,35"
    )

    assert event["event.provider"] == "opnsense"
    assert event["event.type"] == "firewall_connection_denied"
    assert event["observer.interface.name"] == "vtnet1"
    assert event["source.ip"] == "192.168.3.14"
    assert event["destination.port"] == "5353"


def test_gamepanel_audit_uses_linux_audit_normalizer() -> None:
    event = _normalize(
        "<174>1 2026-07-27T06:00:00Z gamepanel-01 gamepanel-audit - - "
        "[observer.name=\"gamepanel-01\"] "
        "type=USER_START msg=audit(1785132000.3:44): pid=3224 uid=0 "
        "auid=33 ses=76 acct=\"www-data\" exe=\"/usr/sbin/cron\" res=success"
    )

    assert event["event.provider"] == "linux.auditd"
    assert event["event.type"] == "audit_user_start_success"
    assert event["user.name"] == "www-data"


def test_gamepanel_auth_extracts_pam_session() -> None:
    event = _normalize(
        "<166>1 2026-07-27T06:00:00Z gamepanel-01 gamepanel-auth - - "
        "[observer.name=\"gamepanel-01\"] "
        "2026-07-27T06:00:00Z gamepanel-01 CRON[12836]: "
        "pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)"
    )

    assert event["event.provider"] == "linux.pam"
    assert event["event.type"] == "pam_session_opened"
    assert event["service.name"] == "cron"
    assert event["user.name"] == "root"


def test_systemd_failure_extracts_unit() -> None:
    event = _normalize(
        "<30>1 2026-07-27T06:00:00Z navidrome-01 systemd 1 - - "
        "navidrome-oauth2-proxy.service: Failed with result 'exit-code'."
    )

    assert event["event.type"] == "linux_systemd_unit_failed"
    assert event["service.name"] == "navidrome-oauth2-proxy.service"
    assert event["event.outcome"] == "failure"


def test_minecraft_watchdog_is_high_signal() -> None:
    event = _normalize(
        "<30>1 2026-07-27T06:00:00Z minecraft-01 bash 268 - - "
        "[04:24:28 ERROR]: The server has not responded for 40 seconds! "
        "Creating thread dump"
    )

    assert event["event.provider"] == "minecraft"
    assert event["event.type"] == "minecraft_server_hang"
    assert event["event.severity"] == "high"


def test_oauth2_proxy_startup_is_not_an_error() -> None:
    event = _normalize(
        "<30>1 2026-07-27T06:00:00Z navidrome-01 oauth2-proxy 126 - - "
        "[oauthproxy.go:176] OAuthProxy configured for OpenID Connect Client ID: navidrome-proxy"
    )

    assert event["event.provider"] == "oauth2-proxy"
    assert event["event.type"] == "oauth2_proxy_configured"
    assert event["event.severity"] == "info"

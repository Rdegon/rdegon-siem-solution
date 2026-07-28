from __future__ import annotations

from deploy.security.opnsense.promote_internal_ngfw import (
    ALIASES,
    RULES,
    _alias_payload,
    _rule_payload,
    _source_nat_payload,
    reconcile,
)


class FakeOPNsense:
    def __init__(self) -> None:
        self.aliases: list[dict[str, str]] = []
        self.rules: list[dict[str, str]] = []
        self.posts: list[tuple[str, dict[str, object]]] = []
        self.source_nat_mode = "automatic"
        self.source_nat_rules: list[dict[str, str]] = []

    def get(self, path: str) -> dict[str, object]:
        if "alias/search" in path:
            return {"rows": self.aliases}
        if "filter/search" in path:
            return {"rows": self.rules}
        if path.endswith("/source_nat/get"):
            return {
                "filter": {
                    "general": {
                        "snat_mode": {
                            name: {"selected": int(name == self.source_nat_mode)}
                            for name in ("automatic", "hybrid", "advanced", "disabled")
                        }
                    }
                }
            }
        if path.endswith("/source_nat/search_rule"):
            return {"rows": self.source_nat_rules}
        if "ids/service" in path or "unbound/service" in path:
            return {"status": "running"}
        raise AssertionError(path)

    def post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        self.posts.append((path, payload))
        if "alias/add" in path:
            self.aliases.append(payload["alias"])  # type: ignore[arg-type]
        if "filter/add" in path:
            self.rules.append(payload["rule"])  # type: ignore[arg-type]
        if path.endswith("/source_nat/set"):
            self.source_nat_mode = payload["filter"]["general"]["snat_mode"]  # type: ignore[index,assignment]
        if "source_nat/add" in path:
            self.source_nat_rules.append(payload["rule"])  # type: ignore[arg-type]
        return {"result": "saved"}


def test_plan_is_non_mutating() -> None:
    client = FakeOPNsense()
    result = reconcile(client, apply=False)
    assert result["aliases_pending"] == [alias.name for alias in ALIASES]
    assert result["aliases_changed"] == []
    assert result["rules_pending"] == [rule.description for rule in RULES]
    assert result["rules_changed"] == []
    assert result["ids"] == "running"
    assert result["unbound"] == "running"
    assert client.posts == []


def test_apply_is_idempotent() -> None:
    client = FakeOPNsense()
    first = reconcile(client, apply=True)
    assert first["ids"] == "running"
    assert first["unbound"] == "running"
    assert len(client.aliases) == len(ALIASES)
    assert len(client.rules) == len(RULES)

    post_count = len(client.posts)
    second = reconcile(client, apply=True)
    assert second["aliases_pending"] == []
    assert second["rules_pending"] == []
    assert second["source_nat_mode"] == "hybrid"
    assert second["source_nat_pending"] is False
    assert len(client.posts) == post_count


def test_outbound_rules_exclude_internal_destinations() -> None:
    outbound = [rule for rule in RULES if "outbound Internet" in rule.description]
    assert outbound
    assert all(rule.destination == "SOC_INTERNAL_NETS" for rule in outbound)
    assert all(rule.destination_not for rule in outbound)


def test_payloads_enable_logging_and_ipv4() -> None:
    alias = _alias_payload(ALIASES[0])["alias"]
    rule = _rule_payload(RULES[0])["rule"]
    assert alias["proto"] == "IPv4"
    assert rule["ipprotocol"] == "inet"
    assert rule["log"] == "0"
    assert rule["statetype"] == "keep"
    source_nat = _source_nat_payload()["rule"]
    assert source_nat["interface"] == "opt1"
    assert source_nat["source_net"] == "SOC_INTERNAL_NETS"
    assert source_nat["log"] == "0"

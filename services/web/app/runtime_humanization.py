from __future__ import annotations

from typing import Any

try:
    from .inventory_catalog import SOURCE_ALIAS_OVERRIDES
except ImportError:  # pragma: no cover - local test fallback
    from inventory_catalog import SOURCE_ALIAS_OVERRIDES  # type: ignore[no-redef]


_MOJIBAKE_MARKERS = ("Ð", "Ñ", "Â", "Ã", "â")


_SOURCE_FRIENDLY_COPY: dict[str, dict[str, str]] = {
    "opnsense-edge-01": {"en": "OPNsense NGFW", "ru": "OPNsense NGFW"},
    "desktop-rdegon": {"en": "Analyst workstation", "ru": "Рабочая станция аналитика"},
    "vuln-mgr-01": {"en": "Vulnerability manager", "ru": "Узел менеджера уязвимостей"},
    "pilot-web-01": {"en": "Pilot web service", "ru": "Пилотный веб-сервис"},
    "pilot-cache-01": {"en": "Pilot cache service", "ru": "Пилотный кэш-сервис"},
    "pilot-db-01": {"en": "Pilot PostgreSQL node", "ru": "Пилотный узел PostgreSQL"},
    "siem-ingest": {"en": "SIEM ingest node", "ru": "Узел приёма SIEM"},
    "siem-processing": {"en": "SIEM processing node", "ru": "Узел обработки SIEM"},
    "siem-storage": {"en": "SIEM storage node", "ru": "Узел хранения SIEM"},
    "siem-web": {"en": "SIEM web node", "ru": "Веб-узел SIEM"},
    "siem-transport": {"en": "SIEM standby transport", "ru": "Резервный транспортный узел SIEM"},
    "pve": {"en": "Proxmox hypervisor", "ru": "Гипервизор Proxmox"},
    "nextcloud-siem": {"en": "Nextcloud service", "ru": "Сервис Nextcloud"},
    "navidrome-01": {"en": "Music service", "ru": "Музыкальный сервис"},
    "openclaw-gateway": {"en": "OpenClaw gateway", "ru": "Шлюз OpenClaw"},
    "vm15611031": {"en": "External VPN node", "ru": "Внешний VPN-узел"},
    "vpn-host-khanov": {"en": "Jump and VPN host", "ru": "Прыжковый и VPN-хост"},
    "generic-http-collector": {"en": "Universal HTTP collector", "ru": "Универсальный HTTP-коллектор"},
    "generic-http-refresh": {"en": "HTTP refresh job", "ru": "Задача HTTP-обновления"},
    "asset-vpn-host": {"en": "VPN contour asset", "ru": "Актив VPN-контура"},
    "asset-jump-host": {"en": "Jump host asset", "ru": "Актив jump-host"},
}


_EVENT_TOKEN_COPY: dict[str, dict[str, str]] = {
    "USER_LOGIN": {"en": "User login", "ru": "Вход пользователя"},
    "USER_LOGOUT": {"en": "User logout", "ru": "Выход пользователя"},
    "USER_AUTH": {"en": "User authentication", "ru": "Аутентификация пользователя"},
    "USER_AUTH_FAILURE": {"en": "Authentication failure", "ru": "Ошибка аутентификации"},
    "AUDIT_USER_LOGIN_FAILURE": {"en": "Audit login failure", "ru": "Ошибка входа по аудиту"},
    "SSH_LOGIN": {"en": "SSH login", "ru": "Вход по SSH"},
    "SSH_LOGIN_FAILURE": {"en": "SSH login failure", "ru": "Ошибка входа по SSH"},
    "SUDO_ROOT": {"en": "Privilege escalation", "ru": "Повышение привилегий"},
    "POWERSHELL_ENCODED_COMMAND": {"en": "Encoded PowerShell command", "ru": "Закодированная команда PowerShell"},
    "SERVICE_CHANGE": {"en": "Service change", "ru": "Изменение сервиса"},
    "CONFIG_CHANGE": {"en": "Configuration change", "ru": "Изменение конфигурации"},
}


def _repair_mojibake(value: str) -> str:
    text = str(value or "")
    if not text or not any(marker in text for marker in _MOJIBAKE_MARKERS):
        return text
    for source_encoding in ("latin1", "cp1252"):
        try:
            repaired = text.encode(source_encoding).decode("utf-8")
        except UnicodeError:
            continue
        if repaired != text:
            return repaired
    return text


def _localized(copy: dict[str, str] | None, lang: str) -> str:
    if not copy:
        return ""
    value = str(copy.get(lang if lang == "ru" else "en") or copy.get("en") or "").strip()
    return _repair_mojibake(value)


def _title_case_parts(parts: list[str]) -> str:
    return " ".join(part[:1].upper() + part[1:].lower() for part in parts if part)


def prettify_technical_token(value: Any) -> str:
    normalized = _repair_mojibake(str(value or "").strip())
    if not normalized:
        return ""
    if normalized.isupper() and "_" in normalized:
        return " ".join(_title_case_parts([part]) for part in normalized.split("_") if part)
    if all(character.islower() or character.isdigit() or character in {"_", "-", "."} for character in normalized):
        if "_" in normalized or "-" in normalized:
            return _title_case_parts([part for part in normalized.replace(".", " ").replace("_", " ").replace("-", " ").split(" ") if part])
    return normalized


def canonicalize_source_name(value: Any) -> str:
    raw = _repair_mojibake(str(value or "").strip())
    if not raw:
        return ""
    token = raw.lower()
    if token in SOURCE_ALIAS_OVERRIDES:
        return str(SOURCE_ALIAS_OVERRIDES[token] or "").strip() or raw
    for chunk in raw.split():
        lowered = chunk.lower().strip(",;[]()")
        if lowered in SOURCE_ALIAS_OVERRIDES:
            return str(SOURCE_ALIAS_OVERRIDES[lowered] or "").strip() or raw
    return raw


def _humanize_pipe_delimited(value: str, *, lang: str = "en") -> str:
    parts = [part.strip() for part in value.split("|") if part.strip()]
    if len(parts) < 2:
        return value
    rendered: list[str] = []
    for part in parts:
        lowered = part.lower()
        if lowered in SOURCE_ALIAS_OVERRIDES or lowered in _SOURCE_FRIENDLY_COPY:
            rendered.append(humanize_source_name(part, lang=lang))
        else:
            rendered.append(prettify_technical_token(part))
    return " | ".join(item for item in rendered if item)


def humanize_source_name(value: Any, *, lang: str = "en", technical_suffix: bool = False) -> str:
    raw = _repair_mojibake(str(value or "").strip())
    if not raw:
        return ""
    if "|" in raw:
        return _humanize_pipe_delimited(raw, lang=lang)
    canonical = canonicalize_source_name(raw)
    friendly = _localized(_SOURCE_FRIENDLY_COPY.get(canonical.lower()), lang) or prettify_technical_token(canonical)
    if not technical_suffix or not friendly or canonical.lower() == raw.lower():
        return friendly or raw
    return f"{friendly} ({canonical})"


def humanize_technical_value(value: Any, *, lang: str = "en") -> str:
    raw = _repair_mojibake(str(value or "").strip())
    if not raw:
        return ""
    token_copy = _EVENT_TOKEN_COPY.get(raw.upper())
    if token_copy:
        return _localized(token_copy, lang)
    if "|" in raw:
        return _humanize_pipe_delimited(raw, lang=lang)
    if raw.lower() in SOURCE_ALIAS_OVERRIDES or raw.lower() in _SOURCE_FRIENDLY_COPY:
        return humanize_source_name(raw, lang=lang)
    return prettify_technical_token(raw)


def humanize_principal(value: Any) -> str:
    raw = _repair_mojibake(str(value or "").strip())
    if not raw:
        return ""
    if "@" in raw:
        raw = raw.split("@", 1)[0]
    return raw.replace(".", " ").replace("_", " ").replace("-", " ").strip()

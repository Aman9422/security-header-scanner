"""Shared YAML configuration loading and validation."""

from copy import deepcopy
import ipaddress
import math
import re
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import yaml


DEFAULT_CONFIG = {
    "scanner": {
        "timeout": 30,
        "max_retries": 3,
        "rate_limit_delay": 1.0,
        "follow_redirects": True,
        "user_agent": "SecurityHeadersScanner/2.0",
        "max_batch_size": 100,
    },
    "storage": {
        "type": "json",
        "path": "./data",
        "max_history": 1000,
        "auto_cleanup_days": 30,
    },
    "api": {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": False,
        "threaded": True,
        "cors_origins": [],
        "allow_private_networks": False,
        "max_request_bytes": 1_048_576,
        "max_urls_per_minute": 30,
    },
    "thresholds": {"critical": 0, "high": 25, "medium": 50, "low": 75},
}

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


def _deep_merge(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    result = deepcopy(base)
    for key, value in update.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _read_mapping(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML configuration in {path}: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"Unable to read configuration file {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("Configuration root must be a YAML mapping")
    return data


def _require_int(config: Dict[str, Any], key: str, section: str, minimum: int, maximum: int):
    value = config[section][key]
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{section}.{key} must be an integer between {minimum} and {maximum}")


def _require_number(config: Dict[str, Any], key: str, section: str, minimum: float, maximum: float):
    value = config[section][key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{section}.{key} must be a number between {minimum} and {maximum}")
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"{section}.{key} must be a number between {minimum} and {maximum}")


def _valid_host(host: str) -> bool:
    if not isinstance(host, str) or not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    host = host.rstrip(".")
    labels = host.split(".")
    return bool(labels) and all(
        len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def _validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    for section in ("scanner", "storage", "api", "thresholds"):
        if not isinstance(config.get(section), dict):
            raise ValueError(f"{section} configuration must be a mapping")

    scanner = config["scanner"]
    _require_number(config, "timeout", "scanner", 0.1, 300)
    _require_int(config, "max_retries", "scanner", 1, 10)
    _require_number(config, "rate_limit_delay", "scanner", 0, 60)
    _require_int(config, "max_batch_size", "scanner", 1, 1000)
    if not isinstance(scanner.get("follow_redirects"), bool):
        raise ValueError("scanner.follow_redirects must be a boolean")
    user_agent = scanner.get("user_agent")
    if (
        not isinstance(user_agent, str)
        or not user_agent.strip()
        or len(user_agent) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in user_agent)
    ):
        raise ValueError("scanner.user_agent must be a printable string of at most 256 characters")
    scanner["user_agent"] = user_agent.strip()

    api = config["api"]
    host = api.get("host")
    if not isinstance(host, str) or not host.strip() or any(ord(ch) < 33 for ch in host):
        raise ValueError("api.host must be a valid bind hostname or IP address")
    host = host.strip().rstrip(".")
    if not _valid_host(host):
        raise ValueError("api.host must be a valid bind hostname or IP address")
    api["host"] = host
    _require_int(config, "port", "api", 1, 65535)
    _require_int(config, "max_request_bytes", "api", 1, 10 * 1024 * 1024)
    _require_int(config, "max_urls_per_minute", "api", 1, 100_000)
    for key in ("debug", "threaded", "allow_private_networks"):
        if not isinstance(api.get(key), bool):
            raise ValueError(f"api.{key} must be a boolean")
    origins = api.get("cors_origins")
    if not isinstance(origins, list) or any(not isinstance(origin, str) for origin in origins):
        raise ValueError("api.cors_origins must be a list of HTTP(S) origins")
    for origin in origins:
        if origin != origin.strip() or any(ord(character) < 33 for character in origin):
            raise ValueError(f"Invalid CORS origin: {origin!r}")
        parsed = urlsplit(origin)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"Invalid CORS origin: {origin!r}") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError(f"Invalid CORS origin: {origin!r}")
        if (
            "*" in origin
            or parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or not _valid_host(parsed.hostname)
            or parsed.netloc.endswith(":")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(f"CORS entries must be exact HTTP(S) origins: {origin!r}")

    storage = config["storage"]
    if not isinstance(storage.get("type"), str) or storage["type"].lower() not in {"json", "sqlite"}:
        raise ValueError("storage.type must be 'json' or 'sqlite'")
    storage["type"] = storage["type"].lower()
    path = storage.get("path")
    if not isinstance(path, str) or not path.strip() or len(path) > 4096 or any(ord(character) < 32 for character in path):
        raise ValueError("storage.path must be a non-empty path of at most 4096 characters")
    storage["path"] = path.strip()
    for key, maximum in (("max_history", 1_000_000), ("auto_cleanup_days", 3650)):
        value = storage.get(key)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum
        ):
            raise ValueError(f"storage.{key} must be between 1 and {maximum}, or null")

    thresholds = config["thresholds"]
    values = []
    for key in ("critical", "high", "medium", "low"):
        value = thresholds.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 100:
            raise ValueError(f"thresholds.{key} must be a number between 0 and 100")
        values.append(value)
    if values != sorted(values):
        raise ValueError("thresholds must be ordered from critical through low")

    return config


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load repository defaults plus an optional override and validate boundaries."""
    config = deepcopy(DEFAULT_CONFIG)
    if DEFAULT_CONFIG_PATH.exists():
        config = _deep_merge(config, _read_mapping(DEFAULT_CONFIG_PATH))
    if config_path is not None:
        if not isinstance(config_path, (str, Path)) or not str(config_path).strip():
            raise ValueError("config_path must be a non-empty path")
        override_path = Path(config_path)
        if not override_path.is_file():
            raise ValueError(f"Configuration file does not exist: {override_path}")
        if override_path.resolve() != DEFAULT_CONFIG_PATH.resolve():
            config = _deep_merge(config, _read_mapping(override_path))
    return _validate_config(config)

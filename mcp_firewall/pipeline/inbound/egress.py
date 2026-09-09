"""Egress control — block SSRF, private IPs, cloud metadata endpoints."""

from __future__ import annotations

import ipaddress
import re
from socket import SOCK_STREAM, gaierror, getaddrinfo
from typing import Any
from urllib.parse import urlparse

from ...models import (
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
)
from ..base import InboundStage

# Cloud metadata endpoints
CLOUD_METADATA = {
    "169.254.169.254",  # AWS, GCP, Azure
    "100.100.100.200",  # Alibaba Cloud
    "metadata.google.internal",
    "metadata.goog",
}

# Dangerous URL schemes
DANGEROUS_SCHEMES = {"file", "gopher", "dict", "ftp", "ldap"}

# All schemes the egress control knows how to handle
_URL_SCHEMES = ("http://", "https://", "file://", "ftp://", "gopher://", "dict://", "ldap://")

_URL_PATTERN = re.compile(r"(?:https?|file|ftp|gopher|dict|ldap)://[^\s\"'<>]+", re.IGNORECASE)
_HOST_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")

# Maximum recursion depth when walking nested arguments
_MAX_DEPTH = 10


class EgressControl(InboundStage):
    """Block requests targeting private networks, cloud metadata, and dangerous URLs."""

    stage = PipelineStage.EGRESS

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        if not config.egress.enabled:
            return None

        # Extract all URL-like values from arguments
        try:
            urls = _extract_urls(request.arguments)
        except ValueError:
            return self._deny("Arguments exceed egress inspection depth", severity=Severity.HIGH)

        for url_str in urls:
            try:
                parsed = urlparse(url_str)
                hostname = (parsed.hostname or "").lower().rstrip(".")
            except ValueError:
                return self._deny("Invalid destination URL", severity=Severity.HIGH)

            # Check dangerous schemes
            if parsed.scheme.lower() in DANGEROUS_SCHEMES:
                return self._deny(
                    f"Dangerous URL scheme: {parsed.scheme}://",
                    severity=Severity.HIGH,
                    details={"url": url_str[:200], "scheme": parsed.scheme},
                )

            # Resolve IP, normalizing non-canonical IPv4 forms (short, octal, hex)
            ip = _resolve_ip(hostname)

            if config.egress.block_private_ips and (
                hostname == "localhost" or hostname.endswith(".localhost")
            ):
                return self._deny("Localhost destination blocked", severity=Severity.HIGH)

            addresses = [ip] if ip is not None else []
            if (
                hostname
                and ip is None
                and (config.egress.block_private_ips or config.egress.block_cloud_metadata)
                and hostname not in CLOUD_METADATA
            ):
                try:
                    addresses = [
                        ipaddress.ip_address(info[4][0])
                        for info in getaddrinfo(hostname, None, type=SOCK_STREAM)
                    ]
                except (gaierror, OSError, ValueError):
                    return self._deny(
                        f"Cannot verify destination addresses for {hostname}",
                        severity=Severity.HIGH,
                    )
                if not addresses:
                    return self._deny(
                        "Destination resolved to no addresses", severity=Severity.HIGH
                    )

            # Check cloud metadata
            if config.egress.block_cloud_metadata and (
                hostname in CLOUD_METADATA
                or any(
                    str(
                        address.ipv4_mapped
                        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
                        else address
                    )
                    in CLOUD_METADATA
                    for address in addresses
                )
            ):
                return self._deny(
                    f"Cloud metadata endpoint blocked: {hostname}",
                    severity=Severity.CRITICAL,
                    details={"url": url_str[:200], "host": hostname},
                )

            # Check private IPs
            if config.egress.block_private_ips:
                private = next(
                    (
                        address
                        for address in addresses
                        if (address.is_private or address.is_loopback or address.is_link_local)
                    ),
                    None,
                )
                if private is not None:
                    return self._deny(
                        f"Private/internal IP blocked: {hostname}",
                        severity=Severity.HIGH,
                        details={"url": url_str[:200], "ip": str(private)},
                    )

                # Check for numeric IP obfuscation (decimal, hex, octal)
                if re.match(r"^0x[0-9a-f]+$|^0[0-7]+$|^\d{8,}$", hostname, re.IGNORECASE):
                    return self._deny(
                        f"Obfuscated IP address blocked: {hostname}",
                        severity=Severity.HIGH,
                        details={"url": url_str[:200]},
                    )

        return None


def _extract_urls(args: dict[str, Any], depth: int = 0) -> list[str]:
    """Extract URL-like strings from arguments."""
    urls: list[str] = []
    for key, value in args.items():
        urls.extend(
            _extract_from_value(
                value,
                depth,
                str(key).lower()
                in {
                    "host",
                    "hosts",
                    "hostname",
                    "address",
                    "server",
                    "endpoint",
                    "url",
                    "urls",
                    "uri",
                },
            )
        )
    return urls


def _extract_from_value(value: object, depth: int, network_field: bool = False) -> list[str]:
    if depth > _MAX_DEPTH:
        raise ValueError("Arguments exceed egress inspection depth")

    if isinstance(value, str):
        urls: list[str] = []
        # Direct URL value
        if value.lower().startswith(_URL_SCHEMES):
            urls.append(value)
        # URLs embedded in text
        urls.extend(_URL_PATTERN.findall(value))
        # Bare IP or hostname without a scheme
        host = value.strip("[]").lower().rstrip(".")
        literal = _resolve_ip(host)
        if literal is not None and (":" in host or "." in host or _looks_like_host(host)):
            urls.append(f"//[{host}]" if ":" in host else f"//{host}")
        elif host in CLOUD_METADATA or host == "localhost" or host.endswith(".localhost"):
            urls.append(f"//{host}")
        elif network_field and (_HOST_PATTERN.fullmatch(host) or ":" in value):
            urls.append(f"//{value}")
        return urls

    if isinstance(value, dict):
        return _extract_urls(value, depth + 1)

    if isinstance(value, (list, tuple)):
        urls = []
        for item in value:
            urls.extend(_extract_from_value(item, depth + 1, network_field))
        return urls

    return []


def _looks_like_host(value: str) -> bool:
    """Heuristic: value is a bare IP or hostname (no scheme, path, or whitespace)."""
    if not 1 < len(value) <= 253:
        return False
    lowered = value.lower()
    if lowered in CLOUD_METADATA or lowered == "localhost":
        return True
    # Require a dot so plain numbers (e.g. ports) are not treated as hosts.
    if "." not in value:
        # Exception: a bare dword IP ("2130706433" == 127.0.0.1), but only
        # when it cannot be a port number (> 65535).
        return value.isdigit() and 0xFFFF < int(value) <= 0xFFFFFFFF
    return _HOST_PATTERN.fullmatch(value) is not None


def _resolve_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP address, accepting non-canonical IPv4 forms (inet_aton-style).

    Handles forms that ``ipaddress.ip_address`` rejects but curl/browsers
    resolve anyway: short forms (``127.1``), octal parts (``0177.0.0.1``),
    hex parts (``0x7f.0.0.1``) and single numbers (``2130706433``).
    """
    if not host:
        return None
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums: list[int] = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                num = int(part, 16)
            elif len(part) > 1 and part.startswith("0"):
                num = int(part, 8)
            else:
                num = int(part, 10)
        except ValueError:
            return None
        if num < 0:
            return None
        nums.append(num)

    # inet_aton semantics: leading parts are single bytes, the last part
    # fills the remaining bytes.
    if any(num > 0xFF for num in nums[:-1]):
        return None
    if nums[-1] > (1 << (8 * (5 - len(parts)))) - 1:
        return None
    value = 0
    for num in nums[:-1]:
        value = (value << 8) | num
    value = (value << (8 * (5 - len(parts)))) | nums[-1]
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None

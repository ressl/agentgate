"""Egress control — block SSRF, private IPs, cloud metadata endpoints."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..base import InboundStage
from ...models import (
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
)

# Cloud metadata endpoints
CLOUD_METADATA = {
    "169.254.169.254",  # AWS, GCP, Azure
    "100.100.100.200",  # Alibaba Cloud
    "metadata.google.internal",
    "metadata.goog",
}

# Dangerous URL schemes
DANGEROUS_SCHEMES = {"file", "gopher", "dict", "ftp", "ldap"}


class EgressControl(InboundStage):
    """Block requests targeting private networks, cloud metadata, and dangerous URLs."""

    stage = PipelineStage.EGRESS

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        if not config.egress.enabled:
            return None

        # Extract all URL-like values from arguments
        urls = _extract_urls(request.arguments)

        for url_str in urls:
            try:
                parsed = urlparse(url_str)
            except Exception:
                continue

            hostname = parsed.hostname or ""

            # Check dangerous schemes
            if parsed.scheme.lower() in DANGEROUS_SCHEMES:
                return self._deny(
                    f"Dangerous URL scheme: {parsed.scheme}://",
                    severity=Severity.HIGH,
                    details={"url": url_str[:200], "scheme": parsed.scheme},
                )

            # Check cloud metadata
            if config.egress.block_cloud_metadata and hostname in CLOUD_METADATA:
                return self._deny(
                    f"Cloud metadata endpoint blocked: {hostname}",
                    severity=Severity.CRITICAL,
                    details={"url": url_str[:200], "host": hostname},
                )

            # Check private IPs
            if config.egress.block_private_ips:
                try:
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return self._deny(
                            f"Private/internal IP blocked: {hostname}",
                            severity=Severity.HIGH,
                            details={"url": url_str[:200], "ip": str(ip)},
                        )
                except ValueError:
                    pass  # Not an IP, that's fine

                # Check for numeric IP obfuscation (decimal, hex, octal)
                if re.match(r"^0x[0-9a-f]+$|^0[0-7]+$|^\d{8,}$", hostname, re.IGNORECASE):
                    return self._deny(
                        f"Obfuscated IP address blocked: {hostname}",
                        severity=Severity.HIGH,
                        details={"url": url_str[:200]},
                    )

        return None


def _extract_urls(args: dict, depth: int = 0) -> list[str]:
    """Extract URL-like strings from arguments."""
    if depth > 5:
        return []

    urls: list[str] = []
    url_pattern = re.compile(r"https?://[^\s\"'<>]+|file://[^\s\"'<>]+", re.IGNORECASE)

    for value in args.values():
        if isinstance(value, str):
            # Direct URL value
            if value.startswith(("http://", "https://", "file://", "ftp://", "gopher://")):
                urls.append(value)
            # URLs embedded in text
            urls.extend(url_pattern.findall(value))
        elif isinstance(value, dict):
            urls.extend(_extract_urls(value, depth + 1))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    if item.startswith(("http://", "https://", "file://")):
                        urls.append(item)
                    urls.extend(url_pattern.findall(item))
                elif isinstance(item, dict):
                    urls.extend(_extract_urls(item, depth + 1))

    return urls

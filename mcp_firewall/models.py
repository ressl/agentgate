"""Core data models for mcp-firewall."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class Action(str, Enum):  # noqa: UP042 — preserve the existing Enum string representation
    """Policy decision actions."""

    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    PROMPT = "prompt"  # ask human
    ALERT = "alert"  # allow but alert


class Severity(str, Enum):  # noqa: UP042 — preserve the existing Enum string representation
    """Alert/finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.rank < other.rank


class PipelineStage(str, Enum):  # noqa: UP042 — preserve the existing Enum string representation
    """Pipeline stage identifiers."""

    KILL_SWITCH = "kill_switch"
    AGENT_IDENTITY = "agent_identity"
    RATE_LIMITER = "rate_limiter"
    INJECTION = "injection"
    EGRESS = "egress"
    THREAT_FEED = "threat_feed"
    POLICY = "policy"
    CHAIN_DETECTOR = "chain_detector"
    HUMAN_APPROVAL = "human_approval"
    SECRET_SCANNER = "secret_scanner"  # noqa: S105 — a stage identifier, not a credential
    PII_DETECTOR = "pii_detector"
    EXFIL_DETECTOR = "exfil_detector"
    CONTENT_POLICY = "content_policy"


class ToolCallRequest(BaseModel):
    """Represents an incoming MCP tool call request."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_id: str = "unknown"
    timestamp: float = Field(default_factory=time.time)
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()), pattern=UUID_PATTERN)
    protocol_id: str | int | None = None
    correlated: bool = True
    arguments_hash: str | None = None


class ToolCallResponse(BaseModel):
    """Represents an MCP tool call response."""

    request_id: str
    content: list[dict[str, Any]] = Field(default_factory=list)
    structured_content: dict[str, Any] | None = None
    extra_fields: dict[str, Any] = Field(default_factory=dict)
    is_error: bool = False
    timestamp: float = Field(default_factory=time.time)

    @field_validator("content")
    @classmethod
    def validate_text_content(cls, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in items:
            if "text" in item and not isinstance(item["text"], str):
                raise ValueError("Content text must be a string")
            if item.get("type") == "text" and "text" not in item:
                raise ValueError("Text content requires text")
            if item.get("type") == "resource":
                resource = item.get("resource")
                if not isinstance(resource, dict):
                    raise ValueError("Embedded resource must be an object")
                if "text" in resource and not isinstance(resource["text"], str):
                    raise ValueError("Resource text must be a string")
        return items


class PipelineDecision(BaseModel):
    """Result of a pipeline stage evaluation."""

    stage: PipelineStage
    action: Action
    reason: str = ""
    severity: Severity = Severity.INFO
    details: dict[str, Any] = Field(default_factory=dict)


class EventPhase(str, Enum):  # noqa: UP042
    """Observed lifecycle boundaries; admission/forwarding do not prove execution."""

    REQUEST_RECEIVED = "request_received"
    POLICY_DECISION = "policy_decision"
    REQUEST_ALLOWED = "request_allowed"
    REQUEST_DENIED = "request_denied"
    REQUEST_FORWARDED = "request_forwarded"
    RESPONSE_RECEIVED = "response_received"
    RESPONSE_FINDING = "response_finding"
    RESPONSE_ALLOWED = "response_allowed"
    RESPONSE_REDACTED = "response_redacted"
    RESPONSE_DENIED = "response_denied"
    RESPONSE_ERROR = "response_error"
    REQUEST_UNKNOWN = "request_unknown"


class SecurityEvent(BaseModel):
    """Public, immutable event envelope. No raw arguments, output, or details."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), pattern=UUID_PATTERN)
    session_id: str = Field(pattern=UUID_PATTERN)
    call_id: str = Field(pattern=UUID_PATTERN)
    request_id: StrictStr | StrictInt | None = None
    correlated: bool = True
    sequence: int = Field(ge=1, strict=True)
    timestamp: float = Field(default_factory=time.time, allow_inf_nan=False)
    phase: EventPhase
    response_is_error: bool | None = None
    tool: str = Field(max_length=1024)
    agent: str = Field(max_length=1024)
    action: Action | None = None
    severity: Severity = Severity.INFO
    stage: PipelineStage | None = None
    reason: str = Field(default="", max_length=1024)

    @field_validator("request_id")
    @classmethod
    def bounded_request_id(cls, value: str | int | None) -> str | int | None:
        if isinstance(value, str) and len(value) > 1024:
            raise ValueError("Protocol ID exceeds event field limit")
        return value


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["mcp-firewall"] = "mcp-firewall"
    event: SecurityEvent


class AuditEvent(BaseModel):
    """Immutable audit log entry."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    agent_id: str = "unknown"
    tool_name: str = ""
    arguments_hash: str = ""  # SHA-256 of arguments (not raw for privacy)
    decision: Action = Action.ALLOW
    stage: PipelineStage | None = None
    reason: str = ""
    severity: Severity = Severity.INFO
    latency_ms: float = 0.0
    previous_hash: str = ""  # hash chain
    event: SecurityEvent | None = None


class GatewayConfig(BaseModel):
    """Top-level gateway configuration."""

    version: int = 1
    default_action: Action = Action.PROMPT
    kill_switch: KillSwitchConfig = Field(default_factory=lambda: KillSwitchConfig())
    rate_limit: RateLimitConfig = Field(default_factory=lambda: RateLimitConfig())
    injection: InjectionConfig = Field(default_factory=lambda: InjectionConfig())
    egress: EgressConfig = Field(default_factory=lambda: EgressConfig())
    secrets: SecretScanConfig = Field(default_factory=lambda: SecretScanConfig())
    pii: PIIConfig = Field(default_factory=lambda: PIIConfig())
    agents: dict[str, AgentConfig] = Field(default_factory=dict)
    rules: list[RuleConfig] = Field(default_factory=list)
    audit: AuditConfig = Field(default_factory=lambda: AuditConfig())
    alerts: AlertsConfig = Field(default_factory=lambda: AlertsConfig())
    threat_feed: ThreatFeedConfig = Field(default_factory=lambda: ThreatFeedConfig())
    events: EventsConfig = Field(default_factory=lambda: EventsConfig())


class KillSwitchConfig(BaseModel):
    """Kill switch configuration."""

    enabled: bool = True
    file_path: str = ".mcp-firewall-kill"


class RateLimitConfig(BaseModel):
    """Global rate limit configuration."""

    enabled: bool = True
    max_calls: int = 200
    window_seconds: int = 60


class InjectionConfig(BaseModel):
    """Injection detection configuration."""

    enabled: bool = True
    sensitivity: str = "medium"  # low, medium, high


class EgressConfig(BaseModel):
    """Egress control configuration."""

    enabled: bool = True
    block_private_ips: bool = True
    block_cloud_metadata: bool = True


class SecretScanConfig(BaseModel):
    """Secret scanning configuration."""

    enabled: bool = True
    action: Action = Action.REDACT


class PIIConfig(BaseModel):
    """PII detection configuration."""

    enabled: bool = False  # off by default
    action: Action = Action.REDACT


class AgentConfig(BaseModel):
    """Per-agent RBAC configuration."""

    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    rate_limit: str | None = None  # e.g. "100/min"
    require_approval: list[str] = Field(default_factory=list)


class RuleConfig(BaseModel):
    """Individual policy rule."""

    name: str
    tool: str = "*"
    match: dict[str, Any] = Field(default_factory=dict)
    action: Action = Action.DENY
    message: str = ""
    rate_limit: dict[str, int] | None = None


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    enabled: bool = True
    path: str = "mcp-firewall.audit.jsonl"
    sign: bool = False  # Ed25519 signing (Phase 4)
    max_size_mb: int = 100


class SlackAlertConfig(BaseModel):
    """Slack alert channel configuration."""

    webhook_url: str | None = None
    channel: str | None = None


class WebhookAlertConfig(BaseModel):
    """Generic webhook alert channel configuration."""

    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class EventWebhookConfig(BaseModel):
    """Operator-configured event receiver; never taken from tool arguments."""

    url: str
    headers: dict[str, str] = Field(default_factory=dict, repr=False)
    timeout_seconds: float = Field(default=2, ge=0.1, le=30)
    max_retries: int = Field(default=2, ge=0, le=3)

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Event webhook needs an HTTP(S) URL")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError(
                "Use headers for authentication; URL credentials/fragments are forbidden"
            )
        return value


class EventsConfig(BaseModel):
    """Optional best-effort lifecycle export, independent of alert filtering."""

    enabled: bool = False
    queue_size: int = Field(default=256, ge=1, le=10000)
    shutdown_timeout: float = Field(default=5, ge=0, le=30)
    webhook: EventWebhookConfig | None = None

    @model_validator(mode="after")
    def require_receiver(self) -> EventsConfig:
        if self.enabled and self.webhook is None:
            raise ValueError("Enabled event export requires a webhook receiver")
        return self


class SyslogAlertConfig(BaseModel):
    """Syslog (CEF) alert channel configuration."""

    host: str = "localhost"
    port: int = 514


class AlertsConfig(BaseModel):
    """Alerting configuration — notify on denied/alerted tool calls."""

    enabled: bool = False  # off by default
    min_severity: Severity = Severity.HIGH
    slack: SlackAlertConfig | None = None
    webhook: WebhookAlertConfig | None = None
    syslog: SyslogAlertConfig | None = None


class ThreatFeedConfig(BaseModel):
    """Threat feed configuration — community detection rules."""

    enabled: bool = True
    feed_dir: str | None = None  # additional custom rules directory

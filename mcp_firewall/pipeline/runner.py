"""Pipeline runner — orchestrates inbound and outbound stages."""

from __future__ import annotations

import time
from pathlib import Path

from ..models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    ToolCallRequest,
    ToolCallResponse,
)
from ..alerts.engine import AlertChannel, AlertEngine
from ..alerts.slack import SlackChannel
from ..alerts.syslog import SyslogChannel
from ..alerts.webhook import WebhookChannel
from ..audit.logger import AuditLogger
from ..threatfeed.loader import ThreatFeed
from .inbound.kill_switch import KillSwitch
from .inbound.injection import InjectionDetector
from .inbound.egress import EgressControl
from .inbound.rate_limiter import RateLimiter
from .inbound.threat_feed import ThreatFeedStage
from .inbound.policy import PolicyEngine
from .inbound.chain_detector import ChainDetector
from .inbound.human_approval import HumanApproval
from .outbound.secrets import SecretScanner
from .outbound.pii import PIIDetector


def _build_threat_feed(config: GatewayConfig) -> ThreatFeed:
    """Load built-in threat feed rules plus any custom rules directory."""
    feed = ThreatFeed()
    builtin_dir = Path(__file__).parent.parent / "threatfeed" / "rules"
    feed.load_directory(builtin_dir)
    if config.threat_feed.feed_dir:
        feed.load_directory(config.threat_feed.feed_dir)
    return feed


def _build_alert_engine(config: GatewayConfig) -> AlertEngine | None:
    """Build an AlertEngine from the alerts: config section, or None if disabled."""
    alerts = config.alerts
    if not alerts.enabled:
        return None
    channels: list[AlertChannel] = []
    if alerts.slack and alerts.slack.webhook_url:
        channels.append(SlackChannel(alerts.slack.webhook_url, channel=alerts.slack.channel))
    if alerts.webhook and alerts.webhook.url:
        channels.append(WebhookChannel(alerts.webhook.url, headers=alerts.webhook.headers))
    if alerts.syslog:
        channels.append(SyslogChannel(host=alerts.syslog.host, port=alerts.syslog.port))
    return AlertEngine(channels=channels, min_severity=alerts.min_severity)


class PipelineRunner:
    """Runs inbound and outbound pipeline stages in order."""

    def __init__(
        self,
        config: GatewayConfig,
        auto_approve: bool = False,
        stdin_available: bool = True,
    ) -> None:
        self.config = config
        self.audit = AuditLogger(config)

        # Inbound stages (order matters!)
        self._kill_switch = KillSwitch()
        self._rate_limiter = RateLimiter()
        self._injection = InjectionDetector()
        self._egress = EgressControl()
        # Threat feed runs before policy: known-malicious patterns must not be
        # bypassed by a permissive allow rule or a prompt default.
        self._threat_feed = ThreatFeedStage(_build_threat_feed(config))
        self._policy = PolicyEngine()
        self._chain = ChainDetector()
        self._approval = HumanApproval(
            auto_approve=auto_approve,
            stdin_available=stdin_available,
        )

        # Alert engine: fires on deny/alert decisions (None when alerts are disabled)
        self._alerts = _build_alert_engine(config)

        self.inbound_stages = [
            self._kill_switch,
            self._rate_limiter,
            self._injection,
            self._egress,
            self._threat_feed,
            self._policy,
            self._chain,
        ]

        # Outbound stages
        self.outbound_stages = [
            SecretScanner(),
            PIIDetector(),
        ]

    def _fire_alerts(self, request: ToolCallRequest, decision: PipelineDecision) -> None:
        """Route a decision to the alert engine (no-op when alerts are disabled)."""
        if self._alerts is not None:
            self._alerts.process(request, decision)

    def evaluate_inbound(self, request: ToolCallRequest) -> PipelineDecision | None:
        """Run all inbound stages. Returns first blocking decision."""
        start = time.time()
        logged = False

        for stage in self.inbound_stages:
            decision = stage.evaluate(request, self.config)
            if decision is None:
                continue

            if decision.action == Action.DENY:
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                self._fire_alerts(request, decision)
                return decision

            if decision.action == Action.ALERT:
                # Non-blocking: audit and alert, then continue pipeline
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                self._fire_alerts(request, decision)
                logged = True
                continue

            if decision.action == Action.PROMPT:
                # Run human approval
                approval = self._approval.evaluate(request, self.config)
                latency = (time.time() - start) * 1000
                self.audit.log(request, approval, latency)
                logged = True
                if approval.action == Action.DENY:
                    self._fire_alerts(request, approval)
                    return approval
                # Approved, continue pipeline
                continue

            if decision.action == Action.ALLOW:
                # Explicit allow from policy, skip remaining stages
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                return None

        # All stages passed — don't log twice if approval was already logged
        if not logged:
            latency = (time.time() - start) * 1000
            self.audit.log(request, None, latency)
        return None

    async def aevaluate_inbound(self, request: ToolCallRequest) -> PipelineDecision | None:
        """Async variant of evaluate_inbound — approval runs off the event loop."""
        start = time.time()
        logged = False

        for stage in self.inbound_stages:
            decision = stage.evaluate(request, self.config)
            if decision is None:
                continue

            if decision.action == Action.DENY:
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                self._fire_alerts(request, decision)
                return decision

            if decision.action == Action.ALERT:
                # Non-blocking: audit and alert, then continue pipeline
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                self._fire_alerts(request, decision)
                logged = True
                continue

            if decision.action == Action.PROMPT:
                # Run human approval off the event loop
                approval = await self._approval.aevaluate(request, self.config)
                latency = (time.time() - start) * 1000
                self.audit.log(request, approval, latency)
                logged = True
                if approval.action == Action.DENY:
                    self._fire_alerts(request, approval)
                    return approval
                # Approved, continue pipeline
                continue

            if decision.action == Action.ALLOW:
                # Explicit allow from policy, skip remaining stages
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                return None

        # All stages passed — don't log twice if approval was already logged
        if not logged:
            latency = (time.time() - start) * 1000
            self.audit.log(request, None, latency)
        return None

    def scan_outbound(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> tuple[ToolCallResponse, list[PipelineDecision]]:
        """Run all outbound stages. Returns (modified response, decisions)."""
        start = time.time()
        decisions: list[PipelineDecision] = []

        for stage in self.outbound_stages:
            response, decision = stage.scan(response, self.config)
            if decision:
                decisions.append(decision)
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                self._fire_alerts(request, decision)
                if decision.action == Action.DENY:
                    break

        return response, decisions

    def reload_config(self, config: GatewayConfig) -> None:
        """Hot-reload configuration."""
        self.config = config
        # Rebuild config-derived components (alert channels, threat feed rules)
        if self._alerts is not None:
            self._alerts.close()
        self._alerts = _build_alert_engine(config)
        self._threat_feed.feed = _build_threat_feed(config)

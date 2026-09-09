"""Pipeline runner — orchestrates inbound and outbound stages."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

from ..alerts.engine import AlertChannel, AlertEngine
from ..alerts.slack import SlackChannel
from ..alerts.syslog import SyslogChannel
from ..alerts.webhook import WebhookChannel
from ..approvals import ApprovalBroker
from ..audit.logger import AuditLogger
from ..events import DeliveryStats, EventEmitter, EventHandler
from ..models import (
    Action,
    EventPhase,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
    ToolCallResponse,
)
from ..threatfeed.loader import ThreatFeed
from .inbound.chain_detector import ChainDetector
from .inbound.egress import EgressControl
from .inbound.human_approval import HumanApproval
from .inbound.injection import InjectionDetector
from .inbound.kill_switch import KillSwitch
from .inbound.policy import PolicyEngine
from .inbound.rate_limiter import RateLimiter
from .inbound.threat_feed import ThreatFeedStage
from .outbound.content import ResponseContentError
from .outbound.pii import PIIDetector
from .outbound.secrets import SecretScanner


def _build_threat_feed(config: GatewayConfig) -> ThreatFeed:
    """Load built-in threat feed rules plus any custom rules directory."""
    feed = ThreatFeed()
    if not config.threat_feed.enabled:
        return feed
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
        *,
        event_handler: EventHandler | None = None,
        event_observer: EventHandler | None = None,
        approval_broker: ApprovalBroker | None = None,
    ) -> None:
        self.config = config
        self.audit = AuditLogger(config)
        self.events = EventEmitter(config.events, handler=event_handler, observer=event_observer)

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
            approval_broker=approval_broker,
            session_id=self.events.session_id,
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

    def _audit_decision(
        self,
        request: ToolCallRequest,
        decision: PipelineDecision | None,
        latency: float,
        *,
        outbound: bool = False,
    ) -> None:
        event = self.events.emit(
            request,
            EventPhase.RESPONSE_FINDING if outbound else EventPhase.POLICY_DECISION,
            decision,
        )
        self.audit.log(request, decision, latency, security_event=event)

    def deny_before_forward(self, request: ToolCallRequest, decision: PipelineDecision) -> None:
        """Record an additional transport admission refusal after policy checks."""
        if decision.action != Action.DENY:
            raise ValueError("A pre-forward refusal must be a deny decision")
        self._audit_decision(request, decision, 0.0)
        self._fire_alerts(request, decision)
        self._finish_inbound(request, decision)

    def _finish_inbound(
        self,
        request: ToolCallRequest,
        decision: PipelineDecision | None,
    ) -> PipelineDecision | None:
        phase = (
            EventPhase.REQUEST_DENIED
            if decision and decision.action == Action.DENY
            else EventPhase.REQUEST_ALLOWED
        )
        self.events.emit(request, phase, decision)
        return decision

    def evaluate_inbound(
        self,
        request: ToolCallRequest,
        *,
        cancel_event: threading.Event | None = None,
    ) -> PipelineDecision | None:
        self.events.emit(request, EventPhase.REQUEST_RECEIVED)
        try:
            return self._finish_inbound(
                request, self._evaluate_inbound(request, cancel_event=cancel_event)
            )
        except BaseException:
            self.events.emit(
                request, EventPhase.REQUEST_UNKNOWN, reason="Admission did not complete"
            )
            raise

    def _evaluate_inbound(
        self,
        request: ToolCallRequest,
        *,
        cancel_event: threading.Event | None = None,
    ) -> PipelineDecision | None:
        """Run all inbound stages. Returns first blocking decision."""
        start = time.time()
        logged = False
        allowed_decision = None

        for stage in self.inbound_stages:
            decision = stage.evaluate(request, self.config)
            if decision is None:
                continue

            if decision.action == Action.DENY:
                latency = (time.time() - start) * 1000
                self._audit_decision(request, decision, latency)
                self._fire_alerts(request, decision)
                return decision

            if decision.action == Action.ALERT:
                # Non-blocking: audit and alert, then continue pipeline
                latency = (time.time() - start) * 1000
                self._audit_decision(request, decision, latency)
                self._fire_alerts(request, decision)
                logged = True
                continue

            if decision.action == Action.PROMPT:
                # Run human approval
                approval = self._approval.evaluate(request, self.config, cancel_event=cancel_event)
                latency = (time.time() - start) * 1000
                self._audit_decision(request, approval, latency)
                logged = True
                if approval.action == Action.DENY:
                    self._fire_alerts(request, approval)
                    return approval
                # Approved, continue pipeline
                continue

            if decision.action == Action.ALLOW:
                # Policy permission does not bypass subsequent security stages.
                allowed_decision = decision
                continue

        # All stages passed — don't log twice if approval was already logged
        if not logged:
            latency = (time.time() - start) * 1000
            self._audit_decision(request, allowed_decision, latency)
        return None

    async def aevaluate_inbound(self, request: ToolCallRequest) -> PipelineDecision | None:
        self.events.emit(request, EventPhase.REQUEST_RECEIVED)
        try:
            return self._finish_inbound(request, await self._aevaluate_inbound(request))
        except BaseException:
            self.events.emit(
                request, EventPhase.REQUEST_UNKNOWN, reason="Admission did not complete"
            )
            raise

    async def _aevaluate_inbound(self, request: ToolCallRequest) -> PipelineDecision | None:
        """Async variant of evaluate_inbound — approval runs off the event loop."""
        start = time.time()
        logged = False
        allowed_decision = None

        for stage in self.inbound_stages:
            if stage is self._egress:
                # DNS uses the system resolver; keep it off the protocol loop.
                try:
                    decision = await asyncio.wait_for(
                        asyncio.to_thread(stage.evaluate, request, self.config), timeout=3.0
                    )
                except TimeoutError:
                    decision = PipelineDecision(
                        stage=PipelineStage.EGRESS,
                        action=Action.DENY,
                        reason="Destination address lookup timed out",
                        severity=Severity.HIGH,
                    )
            else:
                decision = stage.evaluate(request, self.config)
            if decision is None:
                continue

            if decision.action == Action.DENY:
                latency = (time.time() - start) * 1000
                self._audit_decision(request, decision, latency)
                self._fire_alerts(request, decision)
                return decision

            if decision.action == Action.ALERT:
                # Non-blocking: audit and alert, then continue pipeline
                latency = (time.time() - start) * 1000
                self._audit_decision(request, decision, latency)
                self._fire_alerts(request, decision)
                logged = True
                continue

            if decision.action == Action.PROMPT:
                # Run human approval off the event loop
                approval = await self._approval.aevaluate(request, self.config)
                latency = (time.time() - start) * 1000
                self._audit_decision(request, approval, latency)
                logged = True
                if approval.action == Action.DENY:
                    self._fire_alerts(request, approval)
                    return approval
                # Approved, continue pipeline
                continue

            if decision.action == Action.ALLOW:
                allowed_decision = decision
                continue

        # All stages passed — don't log twice if approval was already logged
        if not logged:
            latency = (time.time() - start) * 1000
            self._audit_decision(request, allowed_decision, latency)
        return None

    def scan_outbound(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> tuple[ToolCallResponse, list[PipelineDecision]]:
        self.events.emit(request, EventPhase.RESPONSE_RECEIVED, response_is_error=response.is_error)
        try:
            response, decisions = self._scan_outbound(request, response)
        except ResponseContentError:
            self.events.emit(
                request, EventPhase.RESPONSE_DENIED, reason="Response cannot be safely scanned"
            )
            raise
        except BaseException:
            self.events.emit(
                request, EventPhase.REQUEST_UNKNOWN, reason="Response scanning did not complete"
            )
            raise
        strongest = next((d for d in decisions if d.action == Action.DENY), None)
        strongest = strongest or next((d for d in decisions if d.action == Action.REDACT), None)
        strongest = strongest or next(iter(decisions), None)
        phase = EventPhase.RESPONSE_ALLOWED
        if strongest is not None:
            if strongest.action == Action.DENY:
                phase = EventPhase.RESPONSE_DENIED
            elif strongest.action == Action.REDACT:
                phase = EventPhase.RESPONSE_REDACTED
            strongest = strongest.model_copy(
                update={
                    "severity": max(d.severity for d in decisions),
                    "reason": "; ".join(d.reason for d in decisions),
                }
            )
        self.events.emit(request, phase, strongest, response_is_error=response.is_error)
        return response, decisions

    def _scan_outbound(
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
                self._audit_decision(request, decision, latency, outbound=True)
                self._fire_alerts(request, decision)
                if decision.action == Action.DENY:
                    break

        return response, decisions

    def reload_config(self, config: GatewayConfig) -> None:
        """Hot-reload configuration."""
        # Validate replacements before publishing any of the new configuration.
        feed = _build_threat_feed(config)
        alerts = _build_alert_engine(config)
        try:
            self.events.reconfigure(config.events)
            audit = self.audit.reconfigured(config)
        except Exception:
            self.events.reconfigure(self.config.events)
            if alerts is not None:
                alerts.close()
            raise
        if self._alerts is not None:
            self._alerts.close()
        self.config = config
        self.audit = audit
        self._alerts = alerts
        self._threat_feed.feed = feed

    def cancel_pending_approvals(self) -> None:
        self._approval.close()

    def close(self) -> DeliveryStats:
        self.cancel_pending_approvals()
        if self._alerts is not None:
            self._alerts.close()
        return self.events.close()

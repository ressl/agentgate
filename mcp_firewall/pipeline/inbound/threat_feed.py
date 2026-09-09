"""Threat feed stage — match tool calls against known attack patterns."""

from __future__ import annotations

from ...models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    ToolCallRequest,
)
from ...threatfeed.loader import ThreatFeed
from ..base import InboundStage


class ThreatFeedStage(InboundStage):
    """Deny (or alert on) tool calls matching threat feed rules."""

    stage = PipelineStage.THREAT_FEED

    def __init__(self, feed: ThreatFeed | None = None) -> None:
        self.feed = feed or ThreatFeed()

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        if not config.threat_feed.enabled:
            return None

        rule = self.feed.check(request.tool_name, request.arguments)
        if rule is None:
            return None

        reason = f"Threat feed rule {rule.id} ({rule.name})"
        if rule.description:
            reason += f": {rule.description}"
        details = {"rule_id": rule.id, "rule_name": rule.name, "tags": rule.tags}

        if rule.action == Action.ALERT:
            return PipelineDecision(
                stage=self.stage,
                action=Action.ALERT,
                reason=reason,
                severity=rule.severity,
                details=details,
            )
        return self._deny(reason, severity=rule.severity, details=details)

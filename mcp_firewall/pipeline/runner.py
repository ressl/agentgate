"""Pipeline runner — orchestrates inbound and outbound stages."""

from __future__ import annotations

import time

from ..models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    ToolCallRequest,
    ToolCallResponse,
)
from ..audit.logger import AuditLogger
from .inbound.kill_switch import KillSwitch
from .inbound.injection import InjectionDetector
from .inbound.egress import EgressControl
from .inbound.rate_limiter import RateLimiter
from .inbound.policy import PolicyEngine
from .inbound.chain_detector import ChainDetector
from .inbound.human_approval import HumanApproval
from .outbound.secrets import SecretScanner
from .outbound.pii import PIIDetector


class PipelineRunner:
    """Runs inbound and outbound pipeline stages in order."""

    def __init__(self, config: GatewayConfig, auto_approve: bool = False) -> None:
        self.config = config
        self.audit = AuditLogger(config)

        # Inbound stages (order matters!)
        self._kill_switch = KillSwitch()
        self._rate_limiter = RateLimiter()
        self._injection = InjectionDetector()
        self._egress = EgressControl()
        self._policy = PolicyEngine()
        self._chain = ChainDetector()
        self._approval = HumanApproval(auto_approve=auto_approve)

        self.inbound_stages = [
            self._kill_switch,
            self._rate_limiter,
            self._injection,
            self._egress,
            self._policy,
            self._chain,
        ]

        # Outbound stages
        self.outbound_stages = [
            SecretScanner(),
            PIIDetector(),
        ]

    def evaluate_inbound(self, request: ToolCallRequest) -> PipelineDecision | None:
        """Run all inbound stages. Returns first blocking decision."""
        start = time.time()

        for stage in self.inbound_stages:
            decision = stage.evaluate(request, self.config)
            if decision is None:
                continue

            if decision.action == Action.DENY:
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                return decision

            if decision.action == Action.PROMPT:
                # Run human approval
                approval = self._approval.evaluate(request, self.config)
                latency = (time.time() - start) * 1000
                self.audit.log(request, approval, latency)
                if approval.action == Action.DENY:
                    return approval
                # Approved, continue pipeline
                continue

            if decision.action == Action.ALLOW:
                # Explicit allow from policy, skip remaining stages
                latency = (time.time() - start) * 1000
                self.audit.log(request, decision, latency)
                return None

        # All stages passed
        latency = (time.time() - start) * 1000
        self.audit.log(request, None, latency)
        return None

    def scan_outbound(
        self, request: ToolCallRequest, response: ToolCallResponse
    ) -> tuple[ToolCallResponse, list[PipelineDecision]]:
        """Run all outbound stages. Returns (modified response, decisions)."""
        decisions: list[PipelineDecision] = []

        for stage in self.outbound_stages:
            response, decision = stage.scan(response, self.config)
            if decision:
                decisions.append(decision)
                if decision.action == Action.DENY:
                    break

        return response, decisions

    def reload_config(self, config: GatewayConfig) -> None:
        """Hot-reload configuration."""
        self.config = config

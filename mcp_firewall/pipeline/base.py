"""Base class for pipeline stages."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    ToolCallRequest,
    ToolCallResponse,
)


class InboundStage(ABC):
    """Abstract base for inbound pipeline stages."""

    stage: PipelineStage

    @abstractmethod
    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        """Evaluate request. Return None to pass, PipelineDecision to act."""
        ...

    def _allow(self, reason: str = "") -> PipelineDecision:
        return PipelineDecision(stage=self.stage, action=Action.ALLOW, reason=reason)

    def _deny(self, reason: str, **kwargs) -> PipelineDecision:
        return PipelineDecision(stage=self.stage, action=Action.DENY, reason=reason, **kwargs)

    def _prompt(self, reason: str) -> PipelineDecision:
        return PipelineDecision(stage=self.stage, action=Action.PROMPT, reason=reason)


class OutboundStage(ABC):
    """Abstract base for outbound pipeline stages."""

    stage: PipelineStage

    @abstractmethod
    def scan(
        self, response: ToolCallResponse, config: GatewayConfig
    ) -> tuple[ToolCallResponse, PipelineDecision | None]:
        """Scan response. Return (possibly modified response, optional decision)."""
        ...

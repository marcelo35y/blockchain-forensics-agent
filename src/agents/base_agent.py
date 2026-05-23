"""
Base agent class for all blockchain forensics agents.
Provides common interface, lifecycle management, and shared utilities.
"""

import uuid
import time
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any

from src.models.analysis import AnalysisResult, Finding, SeverityLevel, RiskCategory
from src.config import AgentConfig


logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all forensics agents.
    Defines the standard interface and lifecycle for analysis agents.
    """

    AGENT_NAME: str = "BaseAgent"
    AGENT_VERSION: str = "1.0.0"
    AGENT_DESCRIPTION: str = "Base forensics agent"

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.agent_id = f"{self.AGENT_NAME}_{uuid.uuid4().hex[:8]}"
        self.logger = logging.getLogger(f"blockchain_forensics.{self.AGENT_NAME}")
        self._start_time: Optional[float] = None
        self._metrics: Dict[str, Any] = {}
        self._is_running = False
        self._results_cache: Dict[str, Any] = {}

    @abstractmethod
    def analyze(self, target: str, context: Dict[str, Any] = None) -> AnalysisResult:
        """
        Perform analysis on the given target.
        
        Args:
            target: The entity to analyze (address, transaction hash, etc.)
            context: Additional context from other agents or external data
            
        Returns:
            AnalysisResult with findings and recommendations
        """
        pass

    @abstractmethod
    def validate_input(self, target: str) -> bool:
        """Validate the input target before analysis."""
        pass

    def start(self, target: str, context: Dict[str, Any] = None) -> AnalysisResult:
        """
        Execute the full analysis lifecycle.
        Wraps analyze() with pre/post processing, metrics, and error handling.
        """
        self._start_time = time.time()
        self._is_running = True
        self.logger.info(f"[{self.AGENT_NAME}] Starting analysis of {target}")

        try:
            # Validate input
            if not self.validate_input(target):
                raise ValueError(f"Invalid target for {self.AGENT_NAME}: {target}")

            # Pre-processing hook
            self._pre_process(target, context)

            # Run analysis
            result = self.analyze(target, context or {})

            # Post-processing hook
            self._post_process(result)

            # Set metadata
            result.execution_time_seconds = time.time() - self._start_time
            result.status = "completed"
            result.agent_results[self.AGENT_NAME] = {
                "agent_id": self.agent_id,
                "version": self.AGENT_VERSION,
                "execution_time": result.execution_time_seconds,
                "metrics": self._metrics,
            }

            self.logger.info(
                f"[{self.AGENT_NAME}] Analysis completed in {result.execution_time_seconds:.2f}s | "
                f"findings={len(result.findings)} | risk={result.risk_score.overall:.1f}"
            )

            return result

        except Exception as e:
            elapsed = time.time() - self._start_time if self._start_time else 0
            self.logger.error(f"[{self.AGENT_NAME}] Analysis failed after {elapsed:.2f}s: {e}")
            result = AnalysisResult(
                analysis_id=f"{self.agent_id}_{uuid.uuid4().hex[:8]}",
                target=target,
                status="error",
                error=str(e),
                execution_time_seconds=elapsed,
            )
            return result

        finally:
            self._is_running = False

    def _pre_process(self, target: str, context: Optional[Dict[str, Any]]) -> None:
        """Hook for pre-processing before analysis."""
        pass

    def _post_process(self, result: AnalysisResult) -> None:
        """Hook for post-processing after analysis."""
        pass

    def create_finding(
        self,
        title: str,
        description: str,
        severity: SeverityLevel = SeverityLevel.INFO,
        category: RiskCategory = RiskCategory.UNKNOWN,
        confidence: float = 0.0,
        recommendation: str = "",
        affected_addresses: List[str] = None,
        affected_transactions: List[str] = None,
    ) -> Finding:
        """Helper to create a finding with agent metadata."""
        return Finding(
            finding_id=f"{self.agent_id}_{uuid.uuid4().hex[:8]}",
            title=title,
            description=description,
            severity=severity,
            category=category,
            confidence=confidence,
            recommendation=recommendation,
            affected_addresses=affected_addresses or [],
            affected_transactions=affected_transactions or [],
            source_agent=self.AGENT_NAME,
        )

    def update_metric(self, name: str, value: Any) -> None:
        """Update a performance/analysis metric."""
        self._metrics[name] = value

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def elapsed_time(self) -> float:
        if self._start_time:
            return time.time() - self._start_time
        return 0.0

    def get_info(self) -> Dict[str, Any]:
        """Get agent information."""
        return {
            "agent_id": self.agent_id,
            "name": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "description": self.AGENT_DESCRIPTION,
            "is_running": self._is_running,
            "metrics": self._metrics,
        }

    def __repr__(self) -> str:
        return f"<{self.AGENT_NAME}(id={self.agent_id})>"

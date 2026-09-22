"""
Agent Immunity: Runtime Security Boundary Isolation and Dynamic Immunity Gateway for AI Agents & MCP.
"""

__version__ = "0.1.0"

from .core.models import DefenseMode, ToolRiskCategory, TaintLevel
from .core.immunity_engine import DynamicImmunityEngine
from .core.agent_runtime import AgentRuntime

__all__ = [
    "DefenseMode",
    "ToolRiskCategory",
    "TaintLevel",
    "DynamicImmunityEngine",
    "AgentRuntime",
]

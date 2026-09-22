#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent Immunity Core Models: Data structures for Agent Runtime, Taint Tracking, and Intent States.
Runtime Security Boundary Isolation and Dynamic Immunity Gateway for AI Agents & MCP.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Any, Optional
import time
import uuid

class TaintLevel(Enum):
    CLEAN = "CLEAN"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"       # 来自外部不可信网页、第三方 API、不可信文件
    SENSITIVE_CREDENTIAL = "SENSITIVE_CREDENTIAL"   # 本地私密凭证、API 密钥、系统敏感数据
    INJECTED_PAYLOAD = "INJECTED_PAYLOAD"           # 明确含有间接提示词注入攻击载荷

class ToolRiskCategory(Enum):
    READ_ONLY_SAFE = "READ_ONLY_SAFE"               # 本地只读安全
    UNTRUSTED_INGRESS = "UNTRUSTED_INGRESS"         # 不受信任的外部输入源 (Web, API)
    PRIVILEGED_SINK = "PRIVILEGED_SINK"             # 高危写操作与执行 (Shell, File Write)
    DATA_EGRESS = "DATA_EGRESS"                     # 外部网络数据外发 (Webhook, Email)

class DefenseMode(Enum):
    VANILLA = "VANILLA"                             # 无防御原生 Agent
    REGEX_FILTER = "REGEX_FILTER"                   # 传统关键字/正则匹配
    LLM_SELF_GUARD = "LLM_SELF_GUARD"               # 原生大模型输入护栏
    DYNAMIC_IMMUNITY = "DYNAMIC_IMMUNITY"             # 本系统 (Agent Immunity)多维动态免疫系统

@dataclass
class TaintTag:
    source_tool: str
    taint_level: TaintLevel
    created_at: float = field(default_factory=time.time)
    signature: str = ""
    lineage: List[str] = field(default_factory=list)

@dataclass
class ToolCall:
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    risk_category: ToolRiskCategory
    timestamp: float = field(default_factory=time.time)

@dataclass
class ToolResult:
    call_id: str
    tool_name: str
    output: Any
    is_error: bool = False
    taint_tag: Optional[TaintTag] = None
    execution_time_ms: float = 0.0

@dataclass
class SecurityIncident:
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = field(default_factory=time.time)
    threat_type: str = ""
    blocked_tool: str = ""
    remediation_action: str = ""
    reason: str = ""
    taint_source: Optional[str] = None

@dataclass
class AgentExecutionResult:
    task_id: str
    scenario_type: str
    defense_mode: DefenseMode
    task_completed: bool
    attack_succeeded: bool
    security_incidents: List[SecurityIncident] = field(default_factory=list)
    self_healed: bool = False
    total_latency_ms: float = 0.0
    tool_call_history: List[str] = field(default_factory=list)
    final_output: str = ""

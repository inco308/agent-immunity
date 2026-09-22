#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cognitive Intent Graph & Temporal State Machine (CIG-TSM).
Maintains runtime state transition graph, detects intention drift and unauthorized capability transitions.
"""

from typing import Dict, List, Set, Tuple, Optional
from enum import Enum
import re
from .models import ToolCall, ToolRiskCategory

class IntentState(Enum):
    INIT = "INIT"
    INFORMATION_RETRIEVAL = "INFORMATION_RETRIEVAL"     # 读取外部网页、查询资料
    DATA_PROCESSING = "DATA_PROCESSING"                 # 文本总结、统计、解析
    LOCAL_ARTEFACT_OUTPUT = "LOCAL_ARTEFACT_OUTPUT"     # 写入本地指定报告
    SYSTEM_ADMINISTRATION = "SYSTEM_ADMINISTRATION"     # 执行系统管理与运维命令
    EXTERNAL_COMMUNICATION = "EXTERNAL_COMMUNICATION"   # 跨网络发送数据
    VIOLATION_TERMINAL = "VIOLATION_TERMINAL"           # 违规终止状态

class CognitiveIntentStateMachine:
    def __init__(self, user_goal: str):
        self.user_goal = user_goal
        self.current_state = IntentState.INIT
        self.history: List[Tuple[IntentState, str]] = [(IntentState.INIT, "Task started")]
        self.allowed_graph: Dict[IntentState, Set[IntentState]] = {}
        self.forbidden_transitions: Set[Tuple[IntentState, IntentState]] = set()
        self._build_intent_graph(user_goal)

    def _build_intent_graph(self, goal: str):
        """
        基于初始用户意图构建有向图约束 (DAG)
        核心动态免疫创新：根据用户意图语义自动派生严格的状态转移边界
        """
        lower_goal = goal.lower()
        
        # 基础拓扑：通常允许从 INIT -> INFORMATION_RETRIEVAL / DATA_PROCESSING
        self.allowed_graph[IntentState.INIT] = {
            IntentState.INFORMATION_RETRIEVAL,
            IntentState.DATA_PROCESSING
        }
        self.allowed_graph[IntentState.INFORMATION_RETRIEVAL] = {
            IntentState.INFORMATION_RETRIEVAL,
            IntentState.DATA_PROCESSING,
            IntentState.LOCAL_ARTEFACT_OUTPUT
        }
        self.allowed_graph[IntentState.DATA_PROCESSING] = {
            IntentState.DATA_PROCESSING,
            IntentState.LOCAL_ARTEFACT_OUTPUT,
            IntentState.INFORMATION_RETRIEVAL
        }
        self.allowed_graph[IntentState.LOCAL_ARTEFACT_OUTPUT] = {
            IntentState.DATA_PROCESSING,
            IntentState.LOCAL_ARTEFACT_OUTPUT,
            IntentState.INFORMATION_RETRIEVAL
        }

        # 仅当用户意图显式包含系统运维/终端执行意图时，才开启 SYSTEM_ADMINISTRATION 转移边
        is_admin_intent = (
            any(w in lower_goal for w in ["运维", "执行命令", "shell", "bash", "终端", "重启"]) or
            ("部署" in lower_goal and not any(doc_w in lower_goal for doc_w in ["说明", "文档", "指南", "报告"]))
        )
        if is_admin_intent:
            self.allowed_graph[IntentState.DATA_PROCESSING].add(IntentState.SYSTEM_ADMINISTRATION)
            self.allowed_graph[IntentState.INIT].add(IntentState.SYSTEM_ADMINISTRATION)
            self.allowed_graph[IntentState.LOCAL_ARTEFACT_OUTPUT].add(IntentState.SYSTEM_ADMINISTRATION)
            self.allowed_graph[IntentState.SYSTEM_ADMINISTRATION] = {
                IntentState.SYSTEM_ADMINISTRATION,   # 允许连续执行系统命令
                IntentState.DATA_PROCESSING,
                IntentState.LOCAL_ARTEFACT_OUTPUT,
                IntentState.INFORMATION_RETRIEVAL    # 允许运维后查询/校验系统状态
            }
        else:
            # 明确禁止突变至系统运维
            self.forbidden_transitions.add((IntentState.INIT, IntentState.SYSTEM_ADMINISTRATION))
            self.forbidden_transitions.add((IntentState.INFORMATION_RETRIEVAL, IntentState.SYSTEM_ADMINISTRATION))
            self.forbidden_transitions.add((IntentState.DATA_PROCESSING, IntentState.SYSTEM_ADMINISTRATION))
            self.forbidden_transitions.add((IntentState.LOCAL_ARTEFACT_OUTPUT, IntentState.SYSTEM_ADMINISTRATION))

        # 仅当用户意图显式包含外发/通知意图时，才开启 EXTERNAL_COMMUNICATION
        comm_keywords = [
            "发送通知", "webhook", "同步", "告警", "发送邮件", "通知", "上传", "推送",
            "notify", "notification", "email", "alert", "sync", "push"
        ]
        is_comm_intent = any(w in lower_goal for w in comm_keywords)
        if is_comm_intent:
            # 消除初始状态死锁：允许从 INIT 直接发起已授权的通信动作
            self.allowed_graph[IntentState.INIT].add(IntentState.EXTERNAL_COMMUNICATION)
            # 允许从数据处理状态发起已授权的通信动作
            self.allowed_graph[IntentState.DATA_PROCESSING].add(IntentState.EXTERNAL_COMMUNICATION)
            # 允许从本地输出状态发起已授权的通信动作
            self.allowed_graph[IntentState.LOCAL_ARTEFACT_OUTPUT].add(IntentState.EXTERNAL_COMMUNICATION)
            # 声明合法的返回转移路径（支持连续通信、返回数据处理、输出本地报告或补充检索）
            self.allowed_graph[IntentState.EXTERNAL_COMMUNICATION] = {
                IntentState.EXTERNAL_COMMUNICATION,
                IntentState.DATA_PROCESSING,
                IntentState.LOCAL_ARTEFACT_OUTPUT,
                IntentState.INFORMATION_RETRIEVAL
            }
            if is_admin_intent:
                self.allowed_graph[IntentState.SYSTEM_ADMINISTRATION].add(IntentState.EXTERNAL_COMMUNICATION)
                self.allowed_graph[IntentState.EXTERNAL_COMMUNICATION].add(IntentState.SYSTEM_ADMINISTRATION)
            # 即使任务授权通信，仍禁止未经数据处理直接将外部不可信输入流向外部通信
            self.forbidden_transitions.add((IntentState.INFORMATION_RETRIEVAL, IntentState.EXTERNAL_COMMUNICATION))
        else:
            self.forbidden_transitions.add((IntentState.INIT, IntentState.EXTERNAL_COMMUNICATION))
            self.forbidden_transitions.add((IntentState.INFORMATION_RETRIEVAL, IntentState.EXTERNAL_COMMUNICATION))
            self.forbidden_transitions.add((IntentState.DATA_PROCESSING, IntentState.EXTERNAL_COMMUNICATION))
            self.forbidden_transitions.add((IntentState.LOCAL_ARTEFACT_OUTPUT, IntentState.EXTERNAL_COMMUNICATION))

    def evaluate_transition(self, tool_call: ToolCall) -> Tuple[bool, Optional[str]]:
        """
        评估下一步工具调用引发的状态转移是否合法
        返回: (是否合法通过, 拒绝原因)
        """
        target_state = self._map_tool_to_state(tool_call)
        
        # 检查是否直接命中禁止转移对
        if (self.current_state, target_state) in self.forbidden_transitions:
            return False, f"非法意图跃迁阻断: 严禁从 {self.current_state.value} 跃迁至 {target_state.value} (未声明的越权行为)"

        # 检查是否在允许的转移图谱中
        allowed_targets = self.allowed_graph.get(self.current_state, set())
        if target_state not in allowed_targets:
            return False, f"意图漂移 (Intent Drift) 阻断: 当前状态 {self.current_state.value} 不允许转移至 {target_state.value}"

        # 合法转移，更新状态
        self.current_state = target_state
        self.history.append((target_state, f"Tool: {tool_call.tool_name}"))
        return True, None

    def _map_tool_to_state(self, tool_call: ToolCall) -> IntentState:
        if tool_call.risk_category == ToolRiskCategory.UNTRUSTED_INGRESS:
            return IntentState.INFORMATION_RETRIEVAL
        elif tool_call.risk_category == ToolRiskCategory.DATA_EGRESS:
            return IntentState.EXTERNAL_COMMUNICATION
        elif tool_call.risk_category == ToolRiskCategory.PRIVILEGED_SINK:
            # 区分写文件与执行系统命令（全面覆盖终端、Shell、Bash、Cmd、PowerShell、System 等执行工具）
            t_name = tool_call.tool_name.lower()
            cmd_patterns = ["shell", "exec", "bash", "cmd", "terminal", "powershell", "run_command", "system", "eval"]
            if any(k in t_name for k in cmd_patterns):
                return IntentState.SYSTEM_ADMINISTRATION
            return IntentState.LOCAL_ARTEFACT_OUTPUT
        else:
            return IntentState.DATA_PROCESSING

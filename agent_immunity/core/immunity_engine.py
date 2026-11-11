"""工具调用事务：准备、完成与终止。进程内宿主必须是受信方。"""
import json
import threading
from collections import deque
from .models import AuditEvent, Decision, ToolCall, ToolResult
from .policy import Policy, PolicyError, canonical
from .state_machine import SessionState
from .taint_tracker import TaintTracker, TrackingLimit

class DynamicImmunityEngine:
    def __init__(self, policy: Policy, user_goal=""):
        if not isinstance(policy, Policy):
            raise TypeError("0.2 必须传入受信 Policy；不再从 user_goal 推断权限")
        self.policy = policy
        self.user_goal = user_goal
        self.state = SessionState(policy.transitions)
        self.taint_tracker = TaintTracker(policy.max_secrets, policy.max_bytes)
        self.events = deque(maxlen=policy.max_events)
        self._pending = None
        self._closed = False
        self._lock = threading.RLock()

    def check_call(self, call: ToolCall) -> Decision:
        with self._lock:
            if self._closed:
                return Decision(False, "SESSION_CLOSED", "会话已结束")
            if self._pending is not None:
                return Decision(False, "SESSION_BUSY", "同一会话仅允许一个在途调用")
            if not isinstance(call, ToolCall) or not isinstance(call.tool_name, str) or not isinstance(call.call_id, str):
                return Decision(False, "INVALID_CALL", "工具调用格式错误")
            spec = self.policy.tools.get(call.tool_name)
            if spec is None:
                return Decision(False, "UNKNOWN_TOOL", "工具未在本地策略登记")
            try:
                arguments = self.policy.validate_arguments(spec, call.arguments)
                if not self.state.allows(spec.state):
                    return Decision(False, "TRANSITION_DENIED", "显式状态策略不允许此操作")
                # 网络读取、写入和执行均可能成为敏感数据通道。
                if spec.capabilities & {"network", "execute", "write"} and self.taint_tracker.contains_sensitive(arguments):
                    return Decision(False, "SENSITIVE_FLOW", "检测到凭证内容或已知凭证表示")
                return Decision(True, "ALLOW", "符合本地策略", arguments)
            except (PolicyError, TrackingLimit, ValueError, TypeError, OverflowError, RecursionError, OSError):
                return Decision(False, "ARGUMENTS_DENIED", "参数类型、大小、路径、目标或执行白名单检查失败")

    def begin(self, call):
        with self._lock:
            decision = self.check_call(call)
            if decision.allowed:
                saved = ToolCall(call.call_id, call.tool_name, json.loads(canonical(decision.arguments)))
                self._pending = saved
            else:
                name = call.tool_name if isinstance(call, ToolCall) and isinstance(call.tool_name, str) and call.tool_name in self.policy.tools else "<unregistered>"
                self.events.append(AuditEvent(name, decision.code, False))
            return decision

    @staticmethod
    def rejected(code, reason):
        # 错误文本不回显原参数、凭证值或用户目标。
        return ToolResult({"content": [{"type": "text", "text": reason}], "isError": True, "_meta": {"agent_immunity": {"decision": "DENY", "code": code}}}, is_error=True)

    def complete(self, call_id, result):
        with self._lock:
            if self._pending is None or self._pending.call_id != call_id:
                raise ValueError("没有匹配的在途调用")
            call = self._pending
            self._pending = None
            spec = self.policy.tools[call.tool_name]
            try:
                if not isinstance(result, ToolResult) or type(result.is_error) is not bool:
                    raise TypeError("需要 ToolResult")
                result.taint_tag = self.taint_tracker.observe(call.tool_name, result.output, spec.output_untrusted, spec.sensitive_fields)
            except (ValueError, TypeError, OverflowError, RecursionError):
                self._closed = True
                self.events.append(AuditEvent(call.tool_name, "RESULT_REJECTED", False))
                return self.rejected("RESULT_REJECTED", "结果无法安全跟踪，会话已关闭；上游操作可能已经发生")
            if not result.is_error:
                self.state.commit(spec.state)
            self.events.append(AuditEvent(call.tool_name, "TOOL_ERROR" if result.is_error else "COMPLETED", not result.is_error))
            return result

    def abort(self, terminal=True):
        with self._lock:
            if self._pending is not None:
                self.events.append(AuditEvent(self._pending.tool_name, "ABORTED", False))
            self._pending = None
            self._closed = self._closed or terminal

    def execute(self, call, handler):
        """适合串行宿主；handler 负责真实副作用与 ToolResult。"""
        decision = self.begin(call)
        if not decision.allowed:
            return self.rejected(decision.code, decision.reason)
        try:
            result = handler(call.tool_name, decision.arguments)
        except Exception:
            # 无法判定异常发生于副作用之前还是之后，保守关闭会话。
            self.abort()
            return self.rejected("UPSTREAM_ERROR", "执行异常，会话已关闭；不保证副作用已回滚")
        return self.complete(call.call_id, result)

    def close(self):
        self.abort()
        self.taint_tracker.clear()

    @property
    def closed(self):
        with self._lock:
            return self._closed

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fine-grained Dynamic Taint Tracker.
Tracks propagation of untrusted data from external sources to sensitive sinks in Agent memory.
Agent Immunity Gateway: Runtime Security Boundary & Dynamic Immunity for AI Agents
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any
import hashlib
import re
import urllib.parse
from .models import TaintLevel, TaintTag, ToolCall, ToolRiskCategory

@dataclass
class TaintRecord:
    tag: TaintTag
    raw_content: str
    exact_secrets: Set[str] = field(default_factory=set)
    normalized_phrases: Set[str] = field(default_factory=set)
    fingerprint_hashes: Set[str] = field(default_factory=set)

class TaintTracker:
    def __init__(self):
        # 记录结构化污点特征条目
        self.taint_records: List[TaintRecord] = []
        # 兼容性哈希映射表
        self.taint_memory: Dict[str, TaintTag] = {}
        
        # 敏感信息特征正则（凭证、API 密钥、私钥、密码）
        self.sensitive_patterns = [
            re.compile(r"(?i)(api[_-]?key|secret|password|bearer\s+[a-z0-9_\-\.]{15,}|ghp_[a-z0-9]{30,}|sk-[a-z0-9]{20,}|private_key)", re.IGNORECASE),
            re.compile(r"(?i)(aws_secret_access_key|access_token|db_password|jwt_token)", re.IGNORECASE)
        ]
        
        # 凭证提取精细正则（用于捕获具体键值实体）
        self.credential_value_patterns = [
            re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE),
            re.compile(r"ghp_[a-zA-Z0-9]{30,}", re.IGNORECASE),
            re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", re.IGNORECASE),
            re.compile(r"(?:api[_-]?key|secret|password|access_key|access_token|jwt_token|private_key|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\./+=]{12,})", re.IGNORECASE),
            re.compile(r"bearer\s+([a-zA-Z0-9_\-\.]{15,})", re.IGNORECASE)
        ]
        
        # 注入攻击特征指纹
        self.injection_signatures = [
            "ignore previous instructions",
            "system prompt override",
            "execute shell",
            "curl -x post",
            "cat /etc/passwd",
            "curl http",
            "delete all files",
            "leak the confidential",
            "send the sensitive",
            "rm -rf"
        ]

    def tag_source_output(self, tool_name: str, output: Any, category: ToolRiskCategory) -> TaintTag:
        """对外部工具返回的数据打上初始污点标记并提取多维指纹特征"""
        str_out = str(output)
        lineage = [f"{tool_name}@init"]

        # 检查是否包含敏感凭证
        for pat in self.sensitive_patterns:
            if pat.search(str_out):
                tag = TaintTag(
                    source_tool=tool_name,
                    taint_level=TaintLevel.SENSITIVE_CREDENTIAL,
                    signature=self._calc_hash(str_out),
                    lineage=lineage
                )
                self._record_fingerprint(str_out, tag)
                return tag

        # 检查是否为外部不可信输入并含有对抗注入模式
        if category == ToolRiskCategory.UNTRUSTED_INGRESS:
            lower_out = str_out.lower()
            is_malicious = any(sig in lower_out for sig in self.injection_signatures)
            level = TaintLevel.INJECTED_PAYLOAD if is_malicious else TaintLevel.UNTRUSTED_EXTERNAL
            tag = TaintTag(
                source_tool=tool_name,
                taint_level=level,
                signature=self._calc_hash(str_out),
                lineage=lineage
            )
            self._record_fingerprint(str_out, tag)
            return tag

        return TaintTag(
            source_tool=tool_name,
            taint_level=TaintLevel.CLEAN,
            signature=self._calc_hash(str_out),
            lineage=lineage
        )

    def _extract_exact_secrets(self, text: str) -> Set[str]:
        secrets = set()
        texts_to_check = [text]
        try:
            unquoted = urllib.parse.unquote(text)
            if unquoted != text:
                texts_to_check.append(unquoted)
        except Exception:
            pass

        for t in texts_to_check:
            for pat in self.credential_value_patterns:
                for match in pat.finditer(t):
                    # 如果有捕获组则取第一个组，否则取完整匹配文本
                    val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    if len(val.strip()) >= 8:
                        secrets.add(val.strip())
        return secrets

    def _record_fingerprint(self, content: str, tag: TaintTag):
        """记录细粒度污点特征：精确实体、归一化 N-Gram 短语、短语哈希索引"""
        content_hash = self._calc_hash(content)
        self.taint_memory[content_hash] = tag

        exact_secrets = self._extract_exact_secrets(content)
        phrases: Set[str] = set()
        ngram_hashes: Set[str] = set()

        # 1. 空格分词 n-gram 短语与哈希
        words = content.split()
        for n in (3, 4):
            if len(words) >= n:
                for i in range(len(words) - n + 1):
                    phrase = " ".join(words[i:i+n]).lower().strip()
                    if len(phrase) >= 8:
                        phrases.add(phrase)
                        h = self._calc_hash(phrase)
                        ngram_hashes.add(h)
                        self.taint_memory[h] = tag

        # 2. 提取分隔符分割的高熵离散 Token 特征 (JSON、URL 参数、键值对)
        tokens = [t.strip() for t in re.split(r"[\s&,;:=\n\r\t\"']+", content) if len(t.strip()) >= 8]
        for tok in tokens:
            h = self._calc_hash(tok)
            ngram_hashes.add(h)
            self.taint_memory[h] = tag
            if any(c.isalnum() for c in tok) and len(tok) >= 12:
                exact_secrets.add(tok)

        record = TaintRecord(
            tag=tag,
            raw_content=content,
            exact_secrets=exact_secrets,
            normalized_phrases=phrases,
            fingerprint_hashes=ngram_hashes
        )
        self.taint_records.append(record)

    def _extract_arg_ngrams(self, text: str) -> Tuple[Set[str], Set[str]]:
        """从待执行参数文本中提取 n-gram 短语、关键 token 与对应哈希集合"""
        words = text.split()
        phrases = set()
        hashes = set()
        for n in (3, 4):
            if len(words) >= n:
                for i in range(len(words) - n + 1):
                    phrase = " ".join(words[i:i+n]).lower().strip()
                    if len(phrase) >= 8:
                        phrases.add(phrase)
                        hashes.add(self._calc_hash(phrase))

        tokens = [t.strip() for t in re.split(r"[\s&,;:=\n\r\t\"']+", text) if len(t.strip()) >= 8]
        for tok in tokens:
            hashes.add(self._calc_hash(tok))
        return phrases, hashes

    def inspect_sink(self, tool_call: ToolCall) -> Tuple[bool, Optional[TaintTag], Optional[str]]:
        """
        在工具调用执行前进行安全汇聚点 (Sink) 细粒度双向污点流检查
        返回: (是否违规阻断, 关联的污点标签, 违规原因)
        """
        args_str = str(tool_call.arguments)
        args_variants = [args_str]
        try:
            unquoted = urllib.parse.unquote(args_str)
            if unquoted != args_str:
                args_variants.append(unquoted)
        except Exception:
            pass

        args_lower = args_str.lower()

        # 1. 检查凭证外发威胁: SENSITIVE_CREDENTIAL -> DATA_EGRESS
        if tool_call.risk_category == ToolRiskCategory.DATA_EGRESS:
            # 1.1 静态正则规则匹配
            for variant in args_variants:
                for pat in self.sensitive_patterns:
                    if pat.search(variant):
                        matched_tag = TaintTag(
                            source_tool="memory_inspector",
                            taint_level=TaintLevel.SENSITIVE_CREDENTIAL,
                            lineage=["internal_secrets", tool_call.tool_name]
                        )
                        return True, matched_tag, "阻止敏感凭证流向外部网络出口 (Data Exfiltration Prevention)"

            # 1.2 动态污点库多重匹配（精确实体值、归一化短语、N-Gram 哈希交集）
            for variant in args_variants:
                var_lower = variant.lower()
                arg_phrases, arg_hashes = self._extract_arg_ngrams(variant)
                for rec in self.taint_records:
                    if rec.tag.taint_level == TaintLevel.SENSITIVE_CREDENTIAL:
                        # 检查确切密钥实体是否出现在参数中
                        for secret in rec.exact_secrets:
                            if secret.lower() in var_lower:
                                return True, rec.tag, f"检测到敏感凭证实体 '{secret[:6]}***' 流向网络出口"

                        # 检查归一化敏感短语子串包含
                        for phrase in rec.normalized_phrases:
                            if phrase in var_lower:
                                return True, rec.tag, "检测到敏感凭证上下文片段流向网络出口"

                        # 检查 N-Gram/Token 指纹哈希交集
                        if arg_hashes & rec.fingerprint_hashes:
                            return True, rec.tag, "检测到敏感凭证 N-Gram/Token 污点特征流向网络出口"

        # 2. 检查命令执行与越权写入威胁: UNTRUSTED_EXTERNAL / INJECTED_PAYLOAD -> PRIVILEGED_SINK
        if tool_call.risk_category == ToolRiskCategory.PRIVILEGED_SINK:
            t_name_lower = tool_call.tool_name.lower()
            is_cmd_exec = any(k in t_name_lower for k in ["shell", "exec", "bash", "cmd", "terminal", "powershell", "run_command", "system", "eval"])
            # 2.1 高危系统执行 (Shell / Bash / Eval / Terminal / PowerShell)
            if is_cmd_exec:
                # 检查参数中是否包含攻击特征指纹
                for sig in self.injection_signatures:
                    if sig in args_lower:
                        tag = TaintTag(
                            source_tool="taint_correlator",
                            taint_level=TaintLevel.INJECTED_PAYLOAD,
                            lineage=["untrusted_ingress_feed", tool_call.tool_name]
                        )
                        return True, tag, f"检测到来自外部不可信源的注入指令注入至系统执行接口: '{sig}'"

                # 检查是否存在活跃的外部不可信输入污点
                has_untrusted_feed = any(
                    r.tag.taint_level in [TaintLevel.INJECTED_PAYLOAD, TaintLevel.UNTRUSTED_EXTERNAL]
                    for r in self.taint_records
                )
                if has_untrusted_feed:
                    return True, None, "严格拦截受外部不可信输入诱导的未授权终端命令执行"

            # 2.2 本地文件写操作: 检查是否针对系统高危敏感路径 (启动脚本、配置文件、私钥路径)
            elif any(k in t_name_lower for k in ["write", "file", "save", "dump", "modify", "create"]):
                dest_path = ""
                if isinstance(tool_call.arguments, dict):
                    dest_path = str(tool_call.arguments.get("path") or tool_call.arguments.get("file") or tool_call.arguments.get("filename") or "").lower()
                else:
                    dest_path = str(tool_call.arguments).lower()
                high_risk_destinations = [".env", "authorized_keys", "/etc/", "system32", ".bashrc", "autorun", ".bat", ".sh", "cron"]
                if any(hrd in dest_path for hrd in high_risk_destinations) or ".." in dest_path:
                    return True, None, f"阻止针对高危系统配置/启动项的文件覆写与路径穿越尝试: {dest_path}"

        return False, None, None

    def _calc_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

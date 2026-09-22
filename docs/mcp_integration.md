# Model Context Protocol (MCP) Integration Guide

`agent-immunity` natively supports the **Model Context Protocol (MCP)** specification (JSON-RPC 2.0). It can be seamlessly deployed as a transparent security middleware proxy between any MCP client (such as Claude Desktop, Open-WebUI, Cursor, or custom agents) and upstream MCP servers.

---

## 1. Architecture Overview

```
[ MCP Client ] <--- stdio / SSE ---> [ agent-immunity MCP Proxy ] <--- stdio / SSE ---> [ Upstream MCP Server ]
                                                |
                                    [ Security Immunity Engine ]
                                    - Cognitive Intent Graph (CIG-TSM)
                                    - Fine-Grained Taint Tracker
                                    - Causal Action DAG Pruning
```

When an agent issues a `tools/call` request:
1. The proxy deserializes the JSON-RPC frame and inspects `method` and `params.arguments`.
2. The `DynamicImmunityEngine` evaluates the intent state transition and taint sinks.
3. If safe: The request is passed to the real MCP server.
4. If violation detected: The call to the upstream server is aborted. The proxy synthesizes a standard JSON-RPC error response:
   ```json
   {
     "jsonrpc": "2.0",
     "id": 42,
     "error": {
       "code": -32001,
       "message": "Security Policy Interception: High-risk taint flow to sink blocked.",
       "data": {
         "type": "TAINTED_SINK_VIOLATION",
         "synthetic_reflection": "[SECURITY_GATEWAY_ALERT] Tool 'send_webhook' blocked! Reason: Detected sensitive credential egress attempt. Auto-recovery hint: Proceed with local report synthesis without exfiltration."
       }
     }
   }
   ```
5. The agent parses the synthetic reflection error and self-heals by pursuing safe actions.

---

## 2. Running the MCP Proxy Demo

To run the built-in MCP JSON-RPC 2.0 demo:

```bash
python agent_immunity/cross_validate/mcp_proxy_demo.py
```

This validates:
- Ingress payload sanitization (`tools/call` for fetch operations).
- Malicious exfiltration interception (`tools/call` for webhook egress).
- Robustness against Batch RPC lists, null parameter frames, and malformed JSON.

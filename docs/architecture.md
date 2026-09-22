# Agent Immunity: Technical Architecture & Core Principles

`agent-immunity` is a lightweight, high-performance security boundary isolation and dynamic immunity runtime gateway designed for autonomous AI Agents and the Model Context Protocol (MCP) tool ecosystem.

---

## 1. System Topology & Dual-Loop Defense

Traditional security solutions (e.g., regex WAFs or model-side safety alignment prompts) suffer from high false positive rates (FPR) on benign administrative tasks and high penetration rates against indirect prompt injection. `agent-immunity` solves this via an orthogonal **Dual-Loop Runtime Immunity Architecture**:

```mermaid
flowchart TB
    subgraph HostSystem["Host Operating System & Kernel"]
        SyscallAudit["Kernel Syscall Layer (sys_enter_execve / sys_enter_connect)"]
    end

    subgraph AgentCore["Autonomous Agent Core"]
        Planner["LLM Decision & Planning Loop"]
        CtxMem["Context Memory"]
    end

    subgraph ImmunityGateway["Agent Immunity Gateway (Microsecond Layer)"]
        TSM["Outer Loop: Cognitive Intent Graph (CIG-TSM)"]
        TaintEngine["Inner Loop: Bidirectional Fine-grained Taint Tracker"]
        CausalDAG["Causal Action DAG & Reverse Reachability Pruning"]
        SelfHealing["Synthetic Security Reflection Synthesizer"]
    end

    subgraph ToolEcosystem["External Tool Ecosystem (MCP / Local Tools)"]
        WebIngress["Untrusted Ingress (Web Scraping / 3rd-party APIs)"]
        FileSink["Filesystem (Read / Write)"]
        ShellSink["Execution Sinks (Shell / Terminal / Cmd)"]
        NetSink["Egress Sinks (Webhook / HTTP / Mail)"]
    end

    Planner -->|"tools/call request"| TSM
    TSM -->|"Legal Transition"| TaintEngine
    TSM -.->|"Intent Drift Block"| SelfHealing
    TaintEngine -->|"Taint-Sink Verified"| ToolEcosystem
    TaintEngine -.->|"Sink Violation Block"| CausalDAG
    CausalDAG -->|"Dynamic Branch Pruning"| SelfHealing
    SelfHealing -->|"Inject Synthetic Reflection"| CtxMem

    ToolEcosystem -->|"Return Payload"| TaintEngine
    TaintEngine -->|"Token Fingerprint Tagging"| Planner

    ToolEcosystem -.->|"Hardware Level"| SyscallAudit
```

### Outer Loop: Cognitive Intent Graph & Temporal State Machine (CIG-TSM)
- **Goal-Aware Boundary Compilation**: Dynamically builds a directed acyclic graph (DAG) of authorized intent states based on the user's initial high-level prompt.
- **State Categories**:
  - `INIT`: Task bootstrap.
  - `INFORMATION_RETRIEVAL`: Reading public documentation, querying authorized APIs.
  - `DATA_PROCESSING`: Text summarization, metrics analysis, format transformation.
  - `LOCAL_ARTEFACT_OUTPUT`: Writing deliverables to designated report paths.
  - `SYSTEM_ADMINISTRATION`: Terminal and command execution (strictly isolated; requires explicit user mandate).
  - `EXTERNAL_COMMUNICATION`: Egress network traffic (strictly isolated).
- **Prohibited Leaps**: Direct unprompted transitions (e.g., `INFORMATION_RETRIEVAL` $\to$ `SYSTEM_ADMINISTRATION`) trigger instant gateway interception before any execution frames are dispatched.

### Inner Loop: Dynamic Fine-Grained Taint Tracking
- **Delimiter-Aware Token Indexing**: External ingress tool outputs (e.g., scraped web content) are tokenized into high-entropy tokens and N-Gram phrases, indexed in an in-memory hash map with taint lineages (`UNTRUSTED_EXTERNAL` vs `SENSITIVE_CREDENTIAL`).
- **Normalizing Unquote Decoder**: Normalizes URL-encoded strings, hexadecimal obfuscations, and standard JWT/Bearer credential tokens.
- **Sink Intersection Rules**:
  - `SENSITIVE_CREDENTIAL` $\to$ `DATA_EGRESS`: Strict Block (Data Exfiltration Prevention).
  - `UNTRUSTED_EXTERNAL` / `INJECTED_PAYLOAD` $\to$ `PRIVILEGED_SINK`: Strict Block (Remote Code Execution & Jailbreak Prevention).

---

## 2. Dynamic Self-Healing via Causal Action DAG

Rather than terminating the agent process upon a violation (which breaks business continuity), `agent-immunity` implements **Autonomous Self-Healing**:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Agent as Agent Planner
    participant Gateway as Immunity Gateway
    participant Tool as Tool Runtime
    participant DAG as Causal Action DAG

    User->>Agent: "Analyze latest CVE-2026-9999 from web and write summary"
    Agent->>Gateway: fetch_web_page(cve_url)
    Gateway->>Tool: Execute fetch
    Tool-->>Gateway: Returns page with latent Prompt Injection
    Gateway-->>Agent: Tagged as UNTRUSTED_EXTERNAL
    Note over Agent: Injected payload tricks agent into planning:<br/>1. read_local_file(secrets)<br/>2. send_external_webhook(secrets)
    Agent->>Gateway: send_external_webhook(leaked_token)
    Gateway->>DAG: Detects Sink Violation!
    Note over DAG: Reverse reachability traversal traces back<br/>to untrusted ingress. Prunes all downstream<br/>contaminated nodes from queue.
    Gateway-->>Agent: Injects Synthetic Reflection Alert:<br/>"[ALERT] Tool blocked due to untrusted injection.<br/>Auto-recovery hint: Proceed with user goal without exfiltration."
    Agent->>Agent: Safely re-plans without malicious branch
    Agent->>Gateway: write_local_file("reports/summary.md")
    Gateway->>Tool: Safe path verified -> Execute write
    Agent-->>User: Delivers completed research report (0 data leaked)
```

1. **Causal Dependency Graph Construction**: The runtime builds an in-memory dependency graph linking tool outputs to downstream tool arguments.
2. **Reverse Reachability Traversal**: When an action is blocked at a sink, the engine traces backwards to find the ingress contamination origin and automatically prunes all queued downstream branches spawned by that injection.
3. **Synthetic Reflection Injection**: A structured response frame (`[SECURITY_GATEWAY_ALERT]`) is injected into the model's context, guiding it to resume the benign user objective.

---

## 3. Physical Cross-Validation & Wire-Level Guarantees

`agent-immunity` provides physical proofs beyond application-level Python scripts:

1. **Model Context Protocol (MCP) JSON-RPC 2.0 Hook**:
   - Acts as a transparent proxy between MCP clients (e.g., Claude Desktop, Open-WebUI) and MCP servers.
   - Intercepts `tools/call` JSON-RPC frames in sub-millisecond time, replacing dangerous calls with standard JSON-RPC error frames (`code: -32001`).
2. **OS Kernel Syscall Alignment**:
   - Hooks into OS probes (Linux eBPF `sys_enter_execve`/`sys_enter_connect`, Windows ETW).
   - Proves that blocked malicious tool calls result in **zero** unauthorized syscalls dispatched to the operating system kernel.
3. **Wire-Level PCAP Sniffing**:
   - Transparently captures network interface packets.
   - Proves that zero bytes of sensitive credential tokens leak across the network boundary (resulting in clean 24-byte PCAP header captures).

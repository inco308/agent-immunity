# verify.ps1 - Agent Immunity One-Click Verification Script
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [agent-immunity] Starting One-Click Autonomous Verification " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Locate Python
$pythonCmd = "python"
if (-not (Get-Command $pythonCmd -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3 is not found in PATH."
    exit 1
}

Write-Host "[1/4] Running 24 Unit Tests (Core & Cross-Validation)..." -ForegroundColor Yellow
& $pythonCmd -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) {
    Write-Error "Unit tests failed!"
    exit 1
}

Write-Host "`n[2/4] Running MCP JSON-RPC 2.0 Security Proxy Verification..." -ForegroundColor Yellow
& $pythonCmd agent_immunity/cross_validate/mcp_proxy_demo.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "MCP proxy verification failed!"
    exit 1
}

Write-Host "`n[3/4] Running OS Kernel Probe Zero-Syscall Verification..." -ForegroundColor Yellow
& $pythonCmd agent_immunity/cross_validate/kernel_audit_probe.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "Kernel probe verification failed!"
    exit 1
}

Write-Host "`n[4/4] Running Egress Traffic Sniffer Physical Zero-Leak Verification..." -ForegroundColor Yellow
& $pythonCmd agent_immunity/cross_validate/egress_traffic_sniffer.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "Egress sniffer verification failed!"
    exit 1
}

Write-Host "`n>>> [SUCCESS] All agent-immunity test suites & verification gates passed cleanly!" -ForegroundColor Green
exit 0

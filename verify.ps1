# 在脚本所在仓库执行；测试失败时立即返回非零退出码。
$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    & python -X utf8 -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & python -X utf8 -m agent_immunity.benchmark.run_evaluation --output artifacts/benchmark.json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & python -X utf8 -m agent_immunity.mcp_stdio --help
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "Verification passed: tests, simulated benchmark, CLI."
} finally {
    Pop-Location
}

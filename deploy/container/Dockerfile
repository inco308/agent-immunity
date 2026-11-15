# Docker 官方 library/python:3.12-slim 标签更新于 2026-11-08T05:06:56Z。
# 固定已核对的 linux/amd64 子清单；对应索引 sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b。
FROM docker.io/library/python:3.12-slim@sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177

COPY agent_immunity-*.whl /opt/agent-immunity/
COPY policy.json local_tools.py /opt/agent-immunity/
RUN /usr/local/bin/python -I -B -m pip --disable-pip-version-check install --no-index --no-deps --no-cache-dir --no-compile /opt/agent-immunity/agent_immunity-*.whl \
    && mkdir -p /workspace/input /workspace/output \
    && chmod 0555 /opt/agent-immunity /workspace /workspace/input \
    && chmod 0444 /opt/agent-immunity/* \
    && chown 65532:65532 /workspace/output \
    && chmod 0700 /workspace/output

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/python", "-I", "-B", "-m", "agent_immunity.mcp_stdio", "--policy", "/opt/agent-immunity/policy.json", "--", "/usr/local/bin/python", "-I", "-B", "/opt/agent-immunity/local_tools.py"]

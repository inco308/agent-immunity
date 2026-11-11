"""有限凭证表示检测；不是任意程序或模型推理的数据流跟踪器。"""
import base64
import re
from urllib.parse import unquote
from .models import TaintTag
from .policy import canonical, strict_json

class TrackingLimit(ValueError):
    pass

DEFAULT_FIELDS = frozenset({"password", "secret", "api_key", "apikey", "access_token", "access_key", "private_key", "jwt_token", "aws_secret_access_key"})
ASSIGNMENT = re.compile(r"""(?i)\b(?:password|secret|api[_-]?key|access[_-]?token|jwt[_-]?token|aws_secret_access_key)\s*[:=]\s*["']?([^\s"'<>;,}{]{4,})""")
TOKEN = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,})\b")

def strings(value, depth=0):
    if depth > 32:
        raise TrackingLimit("数据嵌套过深")
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from strings(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item, depth + 1)

class TaintTracker:
    def __init__(self, max_secrets=128, max_bytes=262144):
        self.max_secrets = max_secrets
        self.max_bytes = max_bytes
        self._secrets = set()

    def _check_size(self, output):
        if len(canonical(output).encode("utf-8")) > self.max_bytes:
            raise TrackingLimit("工具结果超过大小限制")

    def _extract(self, output, fields=()):
        found = set()
        names = DEFAULT_FIELDS | {x.lower() for x in fields}
        def visit(value, depth=0):
            if depth > 32:
                raise TrackingLimit("数据嵌套过深")
            if isinstance(value, dict):
                for key, item in value.items():
                    if str(key).lower() in names and isinstance(item, str) and item:
                        found.add(item)
                    visit(item, depth + 1)
            elif isinstance(value, list):
                for item in value:
                    visit(item, depth + 1)
            elif isinstance(value, str):
                found.update(m.group(1) for m in ASSIGNMENT.finditer(value))
                found.update(TOKEN.findall(value))
                # 文件读取等工具可能将 JSON 文档放在文本 content 中。
                if value.lstrip().startswith(("{", "[")):
                    try:
                        decoded = strict_json(value)
                    except (ValueError, RecursionError):
                        pass
                    else:
                        visit(decoded, depth + 1)
        visit(output)
        return found

    def observe(self, tool_name, output, untrusted=True, sensitive_fields=()):
        self._check_size(output)
        found = self._extract(output, sensitive_fields)
        if any(len(x.encode("utf-8")) > 4096 for x in found) or len(self._secrets | found) > self.max_secrets:
            # 不能悄悄逐出旧凭证，否则会重新放行旧数据。
            raise TrackingLimit("凭证跟踪容量耗尽，需要结束会话")
        self._secrets.update(found)
        return TaintTag(tool_name, untrusted=untrusted, sensitive=bool(found))

    def contains_sensitive(self, arguments):
        self._check_size(arguments)
        if self._extract(arguments):
            return True
        candidates = []
        for value in strings(arguments):
            candidates.extend((value, unquote(value), unquote(unquote(value))))
        for secret in self._secrets:
            raw = secret.encode("utf-8")
            variants = {secret, base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(), raw.hex(), raw.hex().upper()}
            variants |= {v.rstrip("=") for v in variants if v}
            if any(variant in text for variant in variants for text in candidates):
                return True
        return False

    @property
    def secret_count(self):
        return len(self._secrets)

    def clear(self):
        self._secrets.clear()

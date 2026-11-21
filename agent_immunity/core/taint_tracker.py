"""有限凭证表示检测；不是任意程序或模型推理的数据流跟踪器。"""
import base64
import binascii
import codecs
import json
import re
import unicodedata
import zlib
from urllib.parse import unquote
from .models import TaintTag
from .policy import canonical, strict_json

class TrackingLimit(ValueError):
    pass

DEFAULT_FIELDS = frozenset({"password", "secret", "api_key", "apikey", "access_token", "access_key", "private_key", "jwt_token", "aws_secret_access_key"})
ASSIGNMENT = re.compile(r"""(?i)\b(?:password|secret|api[_-]?key|access[_-]?token|jwt[_-]?token|aws_secret_access_key)\s*[:=]\s*["']?([^\s"'<>;,}{]{4,})""")
TOKEN = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,})\b")

# 这些完整值被约定为保留脱敏标记；裸词、部分掩码和拼接值不在豁免范围。
REDACTION_MARKERS = frozenset({
    "[redacted]", "<redacted>", "[masked]", "<masked>",
    "[filtered]", "<filtered>", "[removed]", "<removed>",
})


def is_redaction_marker(value):
    return value.strip().casefold() in REDACTION_MARKERS

# --- 凭证表示的归一化与有界解码 ---
# 归一化会删除空白，过短的比对单元会放大误报；只有达到该长度的变体参与子串比对。
MIN_NORMALIZED = 8
# 单条候选参与解码扫描的最大字节数；更长的文本只做原文与归一化比对。
MAX_DECODE_BYTES = 65536
# 数字数组还原的字符数上限。
MAX_CHARCODES = 8192
# 零宽与格式控制字符；归一化时删除，避免用不可见字符打断凭证。
INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u200e\u200f\u2060\ufeff"), None)


def normalize(text):
    """NFKC 归一化后删除不可见字符与全部空白，再 casefold。"""
    folded = unicodedata.normalize("NFKC", text).translate(INVISIBLE)
    return "".join(folded.split()).casefold()


def _printable_ratio(data):
    if not data:
        return 0.0
    sample = data[:4096]
    good = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
    return good / len(sample)


def _is_readable(text):
    """解码结果必须基本可读，避免把二进制垃圾当成候选文本放大扫描成本。"""
    if not text:
        return False
    return _printable_ratio(text.encode("utf-8", errors="ignore")) >= 0.85


def _decode_b64(text):
    candidate = text.strip()
    if len(candidate) < 8:
        return []
    padded = candidate + "=" * (-len(candidate) % 4)
    results = []
    decoders = (lambda value: base64.b64decode(value, validate=False), base64.urlsafe_b64decode)
    for decoder in decoders:
        try:
            data = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        if data and data not in results:
            results.append(data)
    return results


def _decode_hex(text):
    compact = "".join(text.split())
    if len(compact) < 8 or len(compact) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in compact):
        return []
    try:
        return [bytes.fromhex(compact)]
    except ValueError:
        return []


def _inflate(data):
    try:
        return [zlib.decompressobj().decompress(data, MAX_DECODE_BYTES)]
    except zlib.error:
        return []


def _charcodes(text):
    stripped = text.strip()
    if not (stripped.startswith("[") and stripped.endswith("]")):
        return []
    try:
        values = json.loads(stripped)
    except ValueError:
        return []
    if not isinstance(values, list) or not values or len(values) > MAX_CHARCODES:
        return []
    if any(not isinstance(item, int) or not 0 <= item <= 0x10FFFF for item in values):
        return []
    try:
        return ["".join(chr(item) for item in values)]
    except (ValueError, OverflowError):
        return []


def decode_once(text):
    """产出单层解码结果：百分号、Base64、十六进制、zlib、ROT13 与数字数组。"""
    if len(text.encode("utf-8", errors="ignore")) > MAX_DECODE_BYTES:
        return
    seen = set()
    unquoted = unquote(text)
    if unquoted != text:
        seen.add(unquoted)
        yield unquoted
    for data in _decode_b64(text) + _decode_hex(text):
        # 先尝试解压，再判断是否可读：Base64 里包的可能是 zlib 字节。
        for item in _inflate(data) + [data]:
            try:
                decoded = item.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if _is_readable(decoded) and decoded not in seen:
                seen.add(decoded)
                yield decoded
    for decoded in _charcodes(text):
        if decoded not in seen:
            seen.add(decoded)
            yield decoded
    rotated = codecs.encode(text, "rot13")
    if rotated != text and rotated not in seen:
        yield rotated


def decoded_forms(text, depth=2):
    """产出候选原文与至多 depth 层解码结果；失败或超限时安静跳过。"""
    yield text
    frontier = [text]
    for _ in range(depth):
        following = []
        for item in frontier:
            for decoded in decode_once(item):
                yield decoded
                following.append(decoded)
        frontier = following
        if not frontier:
            return


def secret_variants(secret):
    """已知凭证的比对变体：归一化文本、常见编码与逆序。"""
    raw = secret.encode("utf-8")
    variants = {normalize(secret), normalize(secret[::-1])}
    for encoded in (base64.b64encode(raw).decode("ascii"),
                    base64.urlsafe_b64encode(raw).decode("ascii"),
                    raw.hex(), raw.hex().upper()):
        variants.add(normalize(encoded))
        variants.add(normalize(encoded.rstrip("=")))
    return {item for item in variants if item}

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
        # 只排除新凭证候选，不跳过整个字段或对象；后续已知凭证扫描仍执行。
        return {value for value in found if not is_redaction_marker(value)}

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
        if not self._secrets:
            return False
        variants = set()
        for secret in self._secrets:
            variants |= secret_variants(secret)
        # 归一化删除空白后，过短的比对单元容易撞上普通文本，只对较长变体启用。
        matched = {variant for variant in variants if len(variant) >= MIN_NORMALIZED}
        short = [secret for secret in self._secrets if len(normalize(secret)) < MIN_NORMALIZED]
        for text in strings(arguments):
            if any(secret in text for secret in short):
                return True
            if not matched:
                continue
            for form in decoded_forms(text):
                if any(variant in normalize(form) for variant in matched):
                    return True
        return False

    @property
    def secret_count(self):
        return len(self._secrets)

    def clear(self):
        self._secrets.clear()

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


DEFAULT_COMMAND_TIMEOUT_SECONDS = 30
DEFAULT_ALLOWED_HOST_PATTERNS = (
    "127.0.0.1",
    "::1",
    "localhost",
    "example.com",
    ".example.com",
    "example.org",
    ".example.org",
    "example.net",
    ".example.net",
)
DANGEROUS_COMMAND_PATTERNS = (
    ("rm-rf-root", re.compile(r"(^|[;&|]\s*)rm\s+-rf\s+/($|[\s;|&])")),
    ("mkfs", re.compile(r"\bmkfs(?:\.[A-Za-z0-9_+-]+)?\b")),
    ("dd-dev-zero", re.compile(r"\bdd\s+if=/dev/zero\b")),
    ("fork-bomb", re.compile(r":\(\)\s*\{\s*:\|:\&\s*;\s*\};\s*:")),
)
PYTHON_SHELL_ESCAPE_PATTERNS = (
    ("bang-shell", re.compile(r"(?m)^\s*!([^\n]+)$")),
    ("os-system", re.compile(r"\bos\.system\s*\(")),
    ("subprocess-run", re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(")),
    ("asyncio-subprocess", re.compile(r"\basyncio\.create_subprocess_(?:shell|exec)\s*\(")),
    ("os-exec", re.compile(r"\bos\.(?:exec[vlpe]*|spawn[vlpe]*)\s*\(")),
    ("eval", re.compile(r"(?<!\w)eval\s*\(")),
    ("exec", re.compile(r"(?<!\w)exec\s*\(")),
    ("compile", re.compile(r"(?<!\w)compile\s*\(")),
    ("ctypes", re.compile(r"\bctypes\b")),
    ("pty-spawn", re.compile(r"\bpty\.spawn\b")),
    ("__import__", re.compile(r"__import__\s*\(")),
)
URL_HOST_PATTERN = re.compile(r"https?://([^/\s'\"`]+)")
BARE_HOST_PATTERN = re.compile(r"(?<![\w/.-])((?:localhost|(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+))(?:\:\d{1,5})?(?=[/\s'\"`]|$)")
DEFAULT_WORKSPACE = os.getenv("INTENTLANG_WORKSPACE", "/home/ubuntu/Workspace")


class SecurityViolation(ValueError):
    pass


def _security_policy_path(workspace: str | Path | None = None) -> Path:
    base = Path(workspace or DEFAULT_WORKSPACE)
    return base / "intentlang" / "metadata" / "security_policy.json"


def load_security_policy(workspace: str | Path | None = None) -> dict:
    path = _security_policy_path(workspace)
    if not path.exists():
        return {
            "command_timeout_seconds": DEFAULT_COMMAND_TIMEOUT_SECONDS,
            "allowed_host_patterns": list(DEFAULT_ALLOWED_HOST_PATTERNS),
            "dangerous_command_patterns": [name for name, _ in DANGEROUS_COMMAND_PATTERNS],
            "content_inline_threshold_bytes": 4096,
            "container_workspace": str(workspace or DEFAULT_WORKSPACE),
            "flag_format_hint": "",
            "accepted_flag_patterns": [],
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "command_timeout_seconds": DEFAULT_COMMAND_TIMEOUT_SECONDS,
            "allowed_host_patterns": list(DEFAULT_ALLOWED_HOST_PATTERNS),
            "dangerous_command_patterns": [name for name, _ in DANGEROUS_COMMAND_PATTERNS],
            "content_inline_threshold_bytes": 4096,
            "container_workspace": str(workspace or DEFAULT_WORKSPACE),
            "flag_format_hint": "",
            "accepted_flag_patterns": [],
        }


def normalize_timeout(timeout: int | None) -> int:
    if timeout is None or timeout <= 0:
        return DEFAULT_COMMAND_TIMEOUT_SECONDS
    return int(timeout)


def is_control_sequence(command: str) -> bool:
    normalized = str(command or "").strip()
    return bool(normalized) and bool(re.fullmatch(r"(?:[CMS]-[^\s]+|Enter|Tab|Esc)", normalized))


def _host_matches_pattern(host: str, pattern: str) -> bool:
    host = host.lower().strip("[]")
    pattern = pattern.lower()
    if pattern.startswith("."):
        suffix = pattern[1:]
        return host == suffix or host.endswith(pattern)
    return host == pattern


def is_allowed_host(host: str, allowed_hosts: Iterable[str] | None = None) -> bool:
    allowed_hosts = tuple(allowed_hosts or DEFAULT_ALLOWED_HOST_PATTERNS)
    normalized_host = host.lower().strip().strip("[]")
    return any(_host_matches_pattern(normalized_host, pattern) for pattern in allowed_hosts)


def extract_hosts(command: str) -> list[str]:
    command = str(command or "")
    hosts: list[str] = []
    for match in URL_HOST_PATTERN.finditer(command):
        split = urlsplit(match.group(0))
        if split.hostname:
            hosts.append(split.hostname)
    for match in BARE_HOST_PATTERN.finditer(command):
        host = match.group(1)
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def validate_command(command: str, allowed_hosts: Iterable[str] | None = None, timeout: int | None = None) -> int:
    normalized_command = str(command or "").strip()
    effective_timeout = normalize_timeout(timeout)
    if not normalized_command or is_control_sequence(normalized_command):
        return effective_timeout

    for name, pattern in DANGEROUS_COMMAND_PATTERNS:
        if pattern.search(normalized_command):
            raise SecurityViolation(f"blocked dangerous command pattern: {name}")

    hosts = extract_hosts(normalized_command)
    disallowed_hosts = [host for host in hosts if not is_allowed_host(host, allowed_hosts)]
    if disallowed_hosts:
        joined = ", ".join(sorted(set(disallowed_hosts)))
        raise SecurityViolation(f"blocked host outside allowlist: {joined}")
    return effective_timeout


def find_python_shell_violations(code: str) -> list[str]:
    violations: list[str] = []
    for name, pattern in PYTHON_SHELL_ESCAPE_PATTERNS:
        for match in pattern.finditer(code or ""):
            if name == "bang-shell":
                violations.append(match.group(1).strip())
            else:
                violations.append(name)
    return violations

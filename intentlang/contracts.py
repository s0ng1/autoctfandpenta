from __future__ import annotations

from urllib.parse import urlsplit


ARTIFACT_SCHEMAS: dict[str, dict[str, object]] = {
    "recon_summary": {
        "required": ["summary"],
        "optional": ["scope", "tech_stack", "auth", "source", "timestamp"],
        "defaults": {"source": "agent"},
    },
    "surface_map": {
        "required": ["url", "kind"],
        "optional": ["method", "params", "notes", "source", "timestamp"],
        "enums": {"kind": ["page", "endpoint", "api", "form", "file", "script"]},
        "defaults": {"source": "agent"},
    },
    "hypotheses": {
        "required": ["title", "rationale"],
        "optional": ["confidence", "next_step", "related_urls", "source", "timestamp"],
        "enums": {"confidence": ["low", "medium", "high"]},
        "defaults": {"confidence": "medium", "source": "agent"},
    },
    "candidate_findings": {
        "required": ["title", "type", "summary"],
        "optional": ["severity", "location", "payload", "confidence", "finding_id", "evidence_id", "source", "timestamp"],
        "enums": {
            "severity": ["严重", "高危", "中危", "低危", "信息"],
            "confidence": ["low", "medium", "high"],
            "type": ["sqli", "xss", "idor", "rce", "upload", "auth", "ssrf", "xxe", "logic", "flag", "other"],
        },
        "defaults": {"severity": "信息", "confidence": "medium", "source": "agent"},
    },
    "candidate_evidence": {
        "required": ["kind", "summary"],
        "optional": ["content", "url", "path", "related_finding", "finding_id", "evidence_id", "source", "timestamp"],
        "enums": {"kind": ["http", "browser", "screenshot", "terminal", "note", "flag"]},
        "defaults": {"source": "agent"},
    },
    "verified_findings": {
        "required": ["title", "type", "summary"],
        "optional": [
            "finding_id",
            "evidence_id",
            "severity",
            "description",
            "evidence_summary",
            "reproduction_steps",
            "screenshot_path",
            "remediation",
            "control_point",
            "evaluation_unit",
            "risk_analysis",
            "vuln_url",
            "test_process",
            "vuln_code",
            "source",
            "timestamp",
            "flag",
            "proof",
            "target",
            "recorded_at",
            "format_hint",
            "matches_hint",
            "format_confidence",
        ],
        "enums": {
            "severity": ["严重", "高危", "中危", "低危", "信息"],
            "type": ["sqli", "xss", "idor", "rce", "upload", "auth", "ssrf", "xxe", "logic", "flag", "other"],
            "format_confidence": ["low", "medium", "high"],
        },
        "defaults": {"severity": "信息", "source": "agent"},
    },
    "final_report_reference": {
        "required": ["path", "type"],
        "optional": ["summary", "target", "total_findings", "recorded_at"],
        "enums": {"type": ["docx", "md", "html"]},
    },
}


def extract_target_host_patterns(target: str) -> list[str]:
    raw_target = str(target or "").strip()
    if not raw_target:
        return []
    parsed = urlsplit(raw_target if "://" in raw_target else f"http://{raw_target}")
    host = (parsed.hostname or raw_target).strip().strip("[]").lower()
    return [host] if host else []

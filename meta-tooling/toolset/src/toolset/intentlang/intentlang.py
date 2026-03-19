import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from core import namespace, tool, toolset

namespace()


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


_CTF_FLAG_PATTERN = re.compile(r"^(?:flag|FLAG)\{[^{}\n]+\}$")


@toolset()
class IntentLangMemory:
    """
    Manage structured runtime metadata and artifacts for intent-native runs.
    """

    ARTIFACT_SCHEMAS = {
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
            "optional": ["severity", "location", "payload", "confidence", "source", "timestamp"],
            "enums": {
                "severity": ["严重", "高危", "中危", "低危", "信息"],
                "confidence": ["low", "medium", "high"],
                "type": ["sqli", "xss", "idor", "rce", "upload", "auth", "ssrf", "xxe", "logic", "flag", "other"],
            },
            "defaults": {"severity": "信息", "confidence": "medium", "source": "agent"},
        },
        "candidate_evidence": {
            "required": ["kind", "summary"],
            "optional": ["content", "url", "path", "related_finding", "source", "timestamp"],
            "enums": {"kind": ["http", "browser", "screenshot", "terminal", "note", "flag"]},
            "defaults": {"source": "agent"},
        },
        "verified_findings": {
            "required": ["title", "type", "summary"],
            "optional": [
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
            ],
            "enums": {
                "severity": ["严重", "高危", "中危", "低危", "信息"],
                "type": ["sqli", "xss", "idor", "rce", "upload", "auth", "ssrf", "xxe", "logic", "flag", "other"],
            },
            "defaults": {"severity": "信息", "source": "agent"},
        },
        "final_report_reference": {
            "required": ["path", "type"],
            "optional": ["summary", "target", "total_findings", "recorded_at"],
            "enums": {"type": ["docx", "md"]},
        },
    }

    def __init__(self, workspace: str = "/home/ubuntu/Workspace"):
        self.workspace = Path(workspace)
        self.root = self.workspace / "intentlang"
        self.metadata_dir = self.root / "metadata"
        self.artifacts_dir = self.root / "artifacts"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def _metadata_path(self, name: str) -> Path:
        return self.metadata_dir / f"{name}.json"

    def _artifact_path(self, name: str) -> Path:
        return self.artifacts_dir / f"{name}.json"

    def _read_json(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"{path} does not exist")
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_json(self, path: Path, payload: dict[str, Any]) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return str(path)

    def _artifact_payload(self, name: str) -> dict[str, Any]:
        path = self._artifact_path(name)
        return self._read_json(path) if path.exists() else {"artifact": name, "items": []}

    def _normalize_artifact_item(self, name: str, item: dict[str, Any]) -> dict[str, Any]:
        schema = self.ARTIFACT_SCHEMAS.get(name, {})
        normalized = dict(item)
        for key, value in schema.get("defaults", {}).items():
            normalized.setdefault(key, value)
        if "timestamp" in schema.get("required", []) or "timestamp" in schema.get("optional", []):
            normalized.setdefault("timestamp", _timestamp())
        if name == "verified_findings":
            normalized = self._normalize_verified_finding(normalized)
        return normalized

    def _normalize_text_key(self, value: Any) -> str:
        return " ".join(str(value or "").strip().lower().split())

    def _template_defaults_for_verified_finding(self, item: dict[str, Any]) -> tuple[str, str]:
        vuln_type = self._normalize_text_key(item.get("type"))
        title = self._normalize_text_key(item.get("title"))
        text = f"{title} {vuln_type}"
        if any(keyword in text for keyword in ["weak password", "auth", "login", "credential", "鉴权", "认证", "弱口令"]):
            return (
                "身份鉴别",
                "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换。",
            )
        if any(keyword in text for keyword in ["sql", "xss", "upload", "idor", "rce", "xxe", "ssrf", "注入", "上传", "越权", "执行"]):
            return (
                "入侵防范",
                "应提供数据有效性校验与安全防护措施，保证通过人机接口或通信接口输入的内容符合系统设定要求。",
            )
        if any(keyword in text for keyword in ["leak", "exposure", "cors", "clickjacking", "明文", "泄露", "信息"]):
            return (
                "数据保密性",
                "应采用安全控制措施保证重要数据在传输、处理或展示过程中的安全性。",
            )
        return ("待补充", "待补充")

    def _normalize_verified_finding(self, item: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(item)
        title = str(normalized.get("title", "")).strip()
        summary = str(normalized.get("summary", "")).strip()
        evidence_summary = str(normalized.get("evidence_summary", "")).strip()
        description = str(normalized.get("description", "")).strip()
        reproduction = str(normalized.get("reproduction_steps", "")).strip()
        test_process = str(normalized.get("test_process", "")).strip()
        risk_analysis = str(normalized.get("risk_analysis", "")).strip()
        remediation = str(normalized.get("remediation", "")).strip()
        vuln_url = str(normalized.get("vuln_url", "")).strip()
        target = str(normalized.get("target", "")).strip()
        control_point, evaluation_unit = self._template_defaults_for_verified_finding(normalized)

        normalized["title"] = title
        normalized["summary"] = summary
        normalized["description"] = description or summary
        normalized["evidence_summary"] = evidence_summary or test_process or reproduction or summary
        normalized["reproduction_steps"] = reproduction or test_process or evidence_summary or summary
        normalized["test_process"] = test_process or reproduction or evidence_summary or summary
        normalized["risk_analysis"] = risk_analysis or evidence_summary or summary or "待补充"
        normalized["remediation"] = remediation or "待补充"
        normalized["control_point"] = str(normalized.get("control_point", "")).strip() or control_point
        normalized["evaluation_unit"] = str(normalized.get("evaluation_unit", "")).strip() or evaluation_unit
        normalized["vuln_url"] = vuln_url or target
        if target:
            normalized["target"] = target
        if not normalized.get("vuln_code"):
            normalized["vuln_code"] = ""
        return normalized

    def _verified_finding_identity(self, item: dict[str, Any]) -> tuple[str, str, str, str]:
        return (
            self._normalize_text_key(item.get("vuln_code")),
            self._normalize_text_key(item.get("title")),
            self._normalize_text_key(item.get("type")),
            self._normalize_text_key(item.get("vuln_url") or item.get("target")),
        )

    def _merge_verified_finding(self, current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        merged = dict(current)
        schema_defaults = self.ARTIFACT_SCHEMAS["verified_findings"].get("defaults", {})
        for key, value in incoming.items():
            if key in schema_defaults and value == schema_defaults[key] and current.get(key) not in ("", None, []):
                continue
            if value not in ("", None, []):
                merged[key] = value
        for key in ("promoted_from", "promoted_at"):
            if key in current and key not in merged:
                merged[key] = current[key]
        return self._normalize_verified_finding(merged)

    def _validate_artifact_item(self, name: str, item: dict[str, Any]) -> None:
        schema = self.ARTIFACT_SCHEMAS.get(name)
        if not schema:
            return
        missing = [key for key in schema["required"] if key not in item or item[key] in ("", None, [])]
        if missing:
            raise ValueError(f"artifact {name} missing required fields: {', '.join(missing)}")
        for field, values in schema.get("enums", {}).items():
            if field in item and item[field] not in values:
                raise ValueError(f"artifact {name} field {field} must be one of: {', '.join(values)}")

    def _validate_artifact_items(self, name: str, items: list[dict[str, Any]]) -> None:
        for item in items:
            self._validate_artifact_item(name, item)

    def _validate_ctf_flag(self, flag: str) -> str:
        normalized = str(flag).strip()
        if not _CTF_FLAG_PATTERN.fullmatch(normalized):
            raise ValueError("ctf flag must match flag{...} or FLAG{...}")
        return normalized

    @tool()
    def list_metadata(self) -> list[str]:
        """List available metadata objects for the current run."""
        return sorted(path.stem for path in self.metadata_dir.glob("*.json"))

    @tool()
    def list_artifacts(self) -> list[str]:
        """List available artifact collections for the current run."""
        return sorted(path.stem for path in self.artifacts_dir.glob("*.json"))

    @tool()
    def read_metadata(
        self,
        name: Annotated[str, "Metadata object name, for example run, intents, strategy, or runtime_objects."],
    ) -> dict[str, Any]:
        """Read one metadata object from the workspace intentlang metadata directory."""
        return self._read_json(self._metadata_path(name))

    @tool()
    def read_artifact(
        self,
        name: Annotated[str, "Artifact name, for example hypotheses, surface_map, or verified_findings."],
    ) -> dict[str, Any]:
        """Read one artifact collection from the workspace intentlang artifacts directory."""
        return self._read_json(self._artifact_path(name))

    @tool()
    def read_artifact_schema(
        self,
        name: Annotated[str, "Artifact name to inspect."],
    ) -> dict[str, Any]:
        """Read the minimum schema definition for one artifact collection."""
        return self.ARTIFACT_SCHEMAS.get(name, {"required": [], "optional": []})

    @tool()
    def append_artifact_item(
        self,
        name: Annotated[str, "Artifact name to update."],
        item: Annotated[dict[str, Any], "Structured JSON item to append into the artifact collection."],
    ) -> str:
        """
        Append one item into an artifact collection, preserving existing items and refreshing updated_at.
        """
        path = self._artifact_path(name)
        item = self._normalize_artifact_item(name, item)
        self._validate_artifact_item(name, item)
        payload = self._artifact_payload(name)
        items = payload.get("items", [])
        if name == "verified_findings":
            identity = self._verified_finding_identity(item)
            existing_index = next(
                (idx for idx, existing in enumerate(items) if self._verified_finding_identity(existing) == identity),
                -1,
            )
            if existing_index >= 0:
                items[existing_index] = self._merge_verified_finding(items[existing_index], item)
            else:
                items.append(item)
        else:
            items.append(item)
        payload["artifact"] = name
        payload["items"] = items
        payload["updated_at"] = _timestamp()
        return self._write_json(path, payload)

    @tool()
    def replace_artifact_items(
        self,
        name: Annotated[str, "Artifact name to replace."],
        items: Annotated[list[dict[str, Any]], "Full replacement list for the artifact collection."],
        summary: Annotated[str, "Short note describing why the collection was replaced."] = "",
    ) -> str:
        """
        Replace the full item list of an artifact collection when you need to merge, deduplicate, or promote results.
        """
        payload = {
            "artifact": name,
            "items": [self._normalize_artifact_item(name, item) for item in items],
            "updated_at": _timestamp(),
        }
        self._validate_artifact_items(name, payload["items"])
        if summary:
            payload["summary"] = summary
        return self._write_json(self._artifact_path(name), payload)

    @tool()
    def promote_artifact_item(
        self,
        source_name: Annotated[str, "Source artifact name, for example candidate_findings."],
        target_name: Annotated[str, "Target artifact name, for example verified_findings."],
        item_index: Annotated[int, "Zero-based index of the source item to promote. Use -1 together with item_title to resolve by title."] = -1,
        item_title: Annotated[str, "Optional title to locate the source item when you do not want to rely on index."] = "",
        updates: Annotated[dict[str, Any], "Fields to merge into the promoted item."] = {},
        remove_from_source: Annotated[bool, "Whether to remove the original item from the source artifact."] = False,
    ) -> dict[str, str]:
        """
        Promote one item from a source artifact into another artifact, optionally updating fields and removing the original item.
        """
        source_payload = self._artifact_payload(source_name)
        source_items = source_payload.get("items", [])
        resolved_index = item_index
        if item_title:
            resolved_index = next(
                (idx for idx, item in enumerate(source_items) if str(item.get("title", "")) == item_title),
                -1,
            )
        if resolved_index < 0 or resolved_index >= len(source_items):
            raise IndexError(f"unable to resolve source item for artifact {source_name}")

        promoted_item = self._normalize_artifact_item(target_name, dict(source_items[resolved_index]))
        promoted_item.update(updates)
        promoted_item["promoted_from"] = source_name
        promoted_item["promoted_at"] = _timestamp()
        self._validate_artifact_item(target_name, promoted_item)

        target_payload = self._artifact_payload(target_name)
        target_items = target_payload.get("items", [])
        target_items.append(promoted_item)
        target_payload["artifact"] = target_name
        target_payload["items"] = target_items
        target_payload["updated_at"] = _timestamp()
        target_path = self._write_json(self._artifact_path(target_name), target_payload)

        if remove_from_source:
            del source_items[resolved_index]
            source_payload["items"] = source_items
            source_payload["updated_at"] = _timestamp()
            source_path = self._write_json(self._artifact_path(source_name), source_payload)
        else:
            source_path = str(self._artifact_path(source_name))

        return {"source": source_path, "target": target_path}

    @tool()
    def upsert_verified_finding(
        self,
        item: Annotated[dict[str, Any], "Structured verified finding item. Uses vuln_code first, otherwise title+type+target/url as identity."],
    ) -> str:
        """
        Insert or update one verified finding. Existing items are merged instead of duplicated.
        """
        return self.append_artifact_item("verified_findings", item)

    @tool()
    def deduplicate_verified_findings(
        self,
        summary: Annotated[str, "Short note explaining why deduplication was performed."] = "deduplicated verified findings",
    ) -> str:
        """
        Deduplicate verified findings by vuln_code first, then by title/type/target identity, merging richer fields forward.
        """
        payload = self._artifact_payload("verified_findings")
        items = payload.get("items", [])
        merged_items: list[dict[str, Any]] = []
        for item in items:
            normalized = self._normalize_artifact_item("verified_findings", item)
            identity = self._verified_finding_identity(normalized)
            existing_index = next(
                (idx for idx, existing in enumerate(merged_items) if self._verified_finding_identity(existing) == identity),
                -1,
            )
            if existing_index >= 0:
                merged_items[existing_index] = self._merge_verified_finding(merged_items[existing_index], normalized)
            else:
                merged_items.append(normalized)
        return self.replace_artifact_items("verified_findings", merged_items, summary)

    @tool()
    def set_final_report_reference(
        self,
        report_path: Annotated[str, "Absolute report path in the workspace."],
        report_type: Annotated[str, "Report type, for example docx or md."] = "docx",
        summary: Annotated[str, "One-line summary of the final assessment output."] = "",
    ) -> str:
        """Write the final report reference artifact once reporting is complete."""
        payload = {
            "artifact": "final_report_reference",
            "items": [
                self._normalize_artifact_item("final_report_reference", {
                    "path": report_path,
                    "type": report_type,
                    "summary": summary,
                    "recorded_at": _timestamp(),
                })
            ],
            "updated_at": _timestamp(),
        }
        self._validate_artifact_items("final_report_reference", payload["items"])
        return self._write_json(self._artifact_path("final_report_reference"), payload)

    @tool()
    def append_verified_finding(
        self,
        title: Annotated[str, "漏洞标题。"],
        vuln_type: Annotated[str, "漏洞类型，使用 schema 中的短类型，如 sqli/xss/upload/auth/other。"],
        summary: Annotated[str, "一句话概述漏洞与验证结果。"],
        severity: Annotated[str, "严重程度: 严重/高危/中危/低危/信息"] = "信息",
        description: Annotated[str, "漏洞描述。"] = "",
        test_process: Annotated[str, "测试过程或复现步骤。"] = "",
        risk_analysis: Annotated[str, "风险分析。"] = "",
        remediation: Annotated[str, "修复建议。"] = "",
        screenshot_path: Annotated[str, "验证截图路径。"] = "",
        vuln_url: Annotated[str, "漏洞链接或验证 URL。"] = "",
        vuln_code: Annotated[str, "报告中的漏洞编号，如 VUL-AUTO-01。"] = "",
        control_point: Annotated[str, "安全控制点。"] = "",
        evaluation_unit: Annotated[str, "测评单元。"] = "",
        evidence_summary: Annotated[str, "简短证据摘要。"] = "",
        target: Annotated[str, "目标 URL 或标识。"] = "",
    ) -> str:
        """
        Append one verified finding using the template-friendly schema expected by the report generator.
        """
        item = {
            "title": title,
            "type": vuln_type,
            "summary": summary,
            "severity": severity,
            "description": description or summary,
            "test_process": test_process or evidence_summary or summary,
            "risk_analysis": risk_analysis or evidence_summary or summary,
            "remediation": remediation,
            "screenshot_path": screenshot_path,
            "vuln_url": vuln_url,
            "vuln_code": vuln_code,
            "control_point": control_point,
            "evaluation_unit": evaluation_unit,
            "evidence_summary": evidence_summary or test_process or summary,
            "target": target,
        }
        return self.append_artifact_item("verified_findings", item)

    @tool()
    def save_ctf_report(
        self,
        target: Annotated[str, "Challenge target URL or identifier."],
        flag: Annotated[str, "Recovered real flag value."],
        process: Annotated[str, "Chinese summary of the solve path and proof steps."],
    ) -> str:
        """
        Save a Chinese CTF solve report in the workspace and set final_report_reference.
        """
        flag = self._validate_ctf_flag(flag)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c if c.isalnum() or c in "-._" else "_" for c in target)
        filename = f"CTF_Report_{safe_target}_{timestamp}.md"
        report_path = self.workspace / filename
        content = f"""# CTF解题报告

## 题目信息
- 目标: {target}
- 完成时间: {timestamp}

## 解题过程
{process}

## 结果
- Flag: `{flag}`
"""
        report_path.write_text(content, encoding="utf-8")
        self.set_final_report_reference(str(report_path), "md", "CTF 解题报告")
        return str(report_path)

    @tool()
    def record_ctf_flag(
        self,
        flag: Annotated[str, "Recovered real flag value."],
        proof: Annotated[str, "Short evidence summary showing how the flag was obtained."],
        target: Annotated[str, "Target URL or challenge identifier."] = "",
    ) -> str:
        """
        Record the final flag as verified evidence for CTF runs.
        """
        flag = self._validate_ctf_flag(flag)
        item = {
            "title": "CTF Flag Retrieved",
            "type": "flag",
            "summary": proof,
            "severity": "信息",
            "flag": flag,
            "proof": proof,
            "target": target,
            "recorded_at": _timestamp(),
        }
        return self.append_artifact_item("verified_findings", item)

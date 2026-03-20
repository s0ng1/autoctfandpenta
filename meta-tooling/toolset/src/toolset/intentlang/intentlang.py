import json
import importlib
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4
from typing import Annotated, Any

from core import namespace, tool, toolset

PROJECT_ROOT = Path(__file__).resolve().parents[5]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from intentlang.contracts import ARTIFACT_SCHEMAS

namespace()


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")

CONTENT_INLINE_THRESHOLD_BYTES = 4096
CONTENT_SUMMARY_LENGTH = 200
MAX_CTF_FLAG_LENGTH = 512


@toolset()
class IntentLangMemory:
    """
    Manage structured runtime metadata and artifacts for intent-native runs.
    """

    ARTIFACT_SCHEMAS = ARTIFACT_SCHEMAS

    def __init__(self, workspace: str = "/home/ubuntu/Workspace"):
        self.workspace = Path(workspace)
        self.root = self.workspace / "intentlang"
        self.metadata_dir = self.root / "metadata"
        self.artifacts_dir = self.root / "artifacts"
        self.payloads_dir = self.root / "payloads"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.payloads_dir.mkdir(parents=True, exist_ok=True)

    def _metadata_path(self, name: str) -> Path:
        return self.metadata_dir / f"{name}.json"

    def _artifact_path(self, name: str) -> Path:
        return self.artifacts_dir / f"{name}.json"

    def _read_json(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"{path} does not exist")
        return json.loads(path.read_text(encoding="utf-8"))

    def _read_json_if_exists(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        return self._read_json(path)

    def _write_json(self, path: Path, payload: dict[str, Any]) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return str(path)

    def _artifact_payload(self, name: str) -> dict[str, Any]:
        path = self._artifact_path(name)
        return self._read_json(path) if path.exists() else {"artifact": name, "items": []}

    def _payload_path(self, artifact_name: str, suffix: str = ".txt") -> Path:
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", artifact_name).strip("._") or "artifact"
        return self.payloads_dir / f"{safe_name}_{uuid4().hex}{suffix}"

    def _write_large_content(self, artifact_name: str, content: Any) -> str:
        serialized = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False, indent=2)
        payload_path = self._payload_path(artifact_name)
        payload_path.write_text(serialized, encoding="utf-8")
        return str(payload_path)

    def _summarize_content(self, content: Any) -> str:
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        return text[:CONTENT_SUMMARY_LENGTH]

    def _normalize_content_storage(self, artifact_name: str, item: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(item)
        if "content" not in normalized:
            return normalized
        content = normalized.get("content")
        if content in ("", None, []):
            return normalized
        serialized = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        if len(serialized.encode("utf-8")) <= CONTENT_INLINE_THRESHOLD_BYTES:
            return normalized

        normalized["path"] = self._write_large_content(artifact_name, content)
        normalized["summary"] = str(normalized.get("summary") or self._summarize_content(content))
        normalized.pop("content", None)
        return normalized

    def _hydrate_artifact_item(self, artifact_name: str, item: dict[str, Any]) -> dict[str, Any]:
        hydrated = dict(item)
        schema = self.ARTIFACT_SCHEMAS.get(artifact_name, {})
        if "content" not in schema.get("optional", []) and "content" not in schema.get("required", []):
            return hydrated
        if "content" in hydrated:
            return hydrated
        path = hydrated.get("path")
        if not path:
            return hydrated
        try:
            hydrated["content"] = Path(path).read_text(encoding="utf-8")
        except OSError:
            hydrated["content"] = f"[ERROR: payload file missing: {path}]"
        return hydrated

    def _normalize_artifact_item(self, name: str, item: dict[str, Any]) -> dict[str, Any]:
        schema = self.ARTIFACT_SCHEMAS.get(name, {})
        normalized = self._normalize_content_storage(name, item)
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
        finding_id = self._normalize_text_key(item.get("finding_id"))
        if finding_id:
            return (finding_id, "", "", "")
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

    def _merge_non_empty_fields(self, current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        merged = dict(current)
        for key, value in incoming.items():
            if value not in ("", None, []):
                merged[key] = value
        return merged

    def _read_security_policy(self) -> dict[str, Any]:
        return self._read_json_if_exists(self._metadata_path("security_policy"))

    def _read_ctf_flag_hints(self) -> tuple[str, list[str]]:
        policy = self._read_security_policy()
        hint = str(policy.get("flag_format_hint", "")).strip()
        patterns = [str(pattern).strip() for pattern in policy.get("accepted_flag_patterns", []) if str(pattern).strip()]
        if hint or patterns:
            return hint, patterns

        intents = self._read_json_if_exists(self._metadata_path("intents"))
        for item in intents.get("items", []):
            if item.get("kind") != "CTFGoalIntent":
                continue
            contexts = item.get("contexts", {})
            intent_hint = str(contexts.get("flag_format_hint", "")).strip()
            intent_patterns = [str(pattern).strip() for pattern in contexts.get("accepted_flag_patterns", []) if str(pattern).strip()]
            if intent_hint or intent_patterns:
                return intent_hint, intent_patterns
        return "", []

    def _hint_to_regex(self, hint: str) -> str:
        escaped = re.escape(hint.strip())
        return escaped.replace(r"\.\.\.", r"[^{}\n]+")

    def _flag_matches_hints(self, flag: str, format_hint: str, accepted_patterns: list[str]) -> bool:
        patterns = list(accepted_patterns)
        if format_hint:
            patterns.append(self._hint_to_regex(format_hint))
        if not patterns:
            return True
        for pattern in patterns:
            try:
                if re.fullmatch(pattern, flag):
                    return True
            except re.error:
                if pattern == flag:
                    return True
        return False

    def _validate_ctf_flag(self, flag: str) -> tuple[str, dict[str, Any]]:
        normalized = str(flag).strip()
        if not normalized:
            raise ValueError("ctf flag must not be empty")
        if "\n" in normalized or "\r" in normalized:
            raise ValueError("ctf flag must be a single line")
        if len(normalized) > MAX_CTF_FLAG_LENGTH:
            raise ValueError(f"ctf flag must be at most {MAX_CTF_FLAG_LENGTH} characters")

        format_hint, accepted_patterns = self._read_ctf_flag_hints()
        matches_hint = self._flag_matches_hints(normalized, format_hint, accepted_patterns)
        if format_hint or accepted_patterns:
            format_confidence = "high" if matches_hint else "low"
        else:
            format_confidence = "medium"
        metadata = {
            "format_hint": format_hint,
            "matches_hint": matches_hint,
            "format_confidence": format_confidence,
        }
        return normalized, metadata

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
        payload = self._read_json(self._artifact_path(name))
        payload["items"] = [self._hydrate_artifact_item(name, item) for item in payload.get("items", [])]
        return payload

    @tool()
    def read_artifact_schema(
        self,
        name: Annotated[str, "Artifact name to inspect."],
    ) -> dict[str, Any]:
        """Read the minimum schema definition for one artifact collection."""
        return self.ARTIFACT_SCHEMAS.get(name, {"required": [], "optional": []})

    @tool()
    def validate_runtime_contract(self) -> dict[str, Any]:
        """
        Inspect the currently installed toolset surface and report missing core capabilities.
        """
        contract: dict[str, list[str]] = {
            "terminal": ["run_command", "new_session", "send_keys", "get_output"],
            "proxy": ["list_traffic", "view_traffic", "replay_request"],
            "intentlang": ["read_metadata", "append_artifact_item", "promote_artifact_item", "record_ctf_flag"],
            "report": ["add_screenshot", "generate_word_report_from_artifacts", "generate_report"],
        }
        try:
            toolset_module = importlib.import_module("toolset")
        except Exception as exc:
            return {
                "ok": False,
                "error": f"failed to import toolset: {exc}",
                "missing_namespaces": sorted(contract.keys()),
                "missing_methods": contract,
                "recommendations": [
                    "Confirm the runtime is loading the expected toolset package before continuing.",
                ],
            }

        missing_namespaces: list[str] = []
        missing_methods: dict[str, list[str]] = {}
        available: dict[str, list[str]] = {}
        for namespace_name, methods in contract.items():
            namespace_obj = getattr(toolset_module, namespace_name, None)
            if namespace_obj is None:
                missing_namespaces.append(namespace_name)
                missing_methods[namespace_name] = methods
                continue
            present = [method for method in methods if hasattr(namespace_obj, method)]
            missing = [method for method in methods if method not in present]
            available[namespace_name] = present
            if missing:
                missing_methods[namespace_name] = missing

        return {
            "ok": not missing_namespaces and not missing_methods,
            "available_methods": available,
            "missing_namespaces": missing_namespaces,
            "missing_methods": missing_methods,
            "recommended_usage": {
                "terminal": "Prefer run_command for one-shot commands; use interactive sessions only when shell state matters.",
                "proxy": "Use list_traffic/view_traffic/replay_request. Do not guess proxy API names.",
                "artifacts": "Write candidate artifacts early; promote to verified findings only after validation.",
            },
        }

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
        if target_name == "verified_findings":
            promoted_item = self._merge_verified_finding(promoted_item, updates)
        else:
            promoted_item = self._merge_non_empty_fields(promoted_item, updates)
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
        finding_id: Annotated[str, "可选 finding ID，用于与证据稳定关联。"] = "",
        evidence_id: Annotated[str, "可选 primary evidence ID。"] = "",
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
            "finding_id": finding_id,
            "evidence_id": evidence_id,
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
        flag, _ = self._validate_ctf_flag(flag)
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
        flag, flag_metadata = self._validate_ctf_flag(flag)
        item = {
            "title": "CTF Flag Retrieved",
            "type": "flag",
            "summary": proof,
            "severity": "信息",
            "flag": flag,
            "proof": proof,
            "target": target,
            "recorded_at": _timestamp(),
            **flag_metadata,
        }
        return self.append_artifact_item("verified_findings", item)

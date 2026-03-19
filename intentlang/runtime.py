from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


TEMPLATE_SOURCE = Path(__file__).resolve().parent.parent / "docs" / "渗透测试报告模板V1.2.docx"


@dataclass(slots=True)
class RuntimeObject:
    name: str
    kind: str
    location: str
    description: str


@dataclass(slots=True)
class BaseIntent:
    kind: str = field(init=False)
    target: str
    objective: str
    success_criteria: list[str]
    constraints: list[str]
    inputs: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class WebReconIntent(BaseIntent):
    kind: str = field(default="WebReconIntent", init=False)


@dataclass(slots=True)
class WebVerificationIntent(BaseIntent):
    kind: str = field(default="WebVerificationIntent", init=False)


@dataclass(slots=True)
class CTFGoalIntent(BaseIntent):
    kind: str = field(default="CTFGoalIntent", init=False)


@dataclass(slots=True)
class BaseStrategy:
    name: str = field(init=False)
    priority_testing_types: list[str]
    aggression_level: str
    allow_early_stop: bool
    evidence_requirements: list[str]
    hypothesis_sorting: list[str]
    report_requirements: list[str]


@dataclass(slots=True)
class PentestStrategy(BaseStrategy):
    name: str = field(default="PentestStrategy", init=False)
    priority_testing_types: list[str] = field(
        default_factory=lambda: [
            "tech-stack reconnaissance",
            "authentication and authorization review",
            "input validation flaws",
            "file handling and upload abuse",
            "injection and remote execution",
        ]
    )
    aggression_level: str = "controlled"
    allow_early_stop: bool = False
    evidence_requirements: list[str] = field(
        default_factory=lambda: [
            "preserve reproducible HTTP/browser evidence",
            "capture screenshots for every verified finding",
            "retain candidate findings even when confidence is low",
        ]
    )
    hypothesis_sorting: list[str] = field(
        default_factory=lambda: [
            "impact",
            "reachability",
            "exploitability",
            "verification cost",
        ]
    )
    report_requirements: list[str] = field(
        default_factory=lambda: [
            "final report must be written in Chinese",
            "verified findings must include remediation guidance",
            "prefer HTML report with embedded screenshots",
        ]
    )


@dataclass(slots=True)
class CTFStrategy(BaseStrategy):
    name: str = field(default="CTFStrategy", init=False)
    priority_testing_types: list[str] = field(
        default_factory=lambda: [
            "rapid surface discovery",
            "high-yield exploit paths",
            "flag-oriented privilege or data access",
        ]
    )
    aggression_level: str = "competitive"
    allow_early_stop: bool = True
    evidence_requirements: list[str] = field(
        default_factory=lambda: [
            "retain notes and payloads needed to reproduce flag path",
            "record the final flag evidence before stopping",
        ]
    )
    hypothesis_sorting: list[str] = field(
        default_factory=lambda: [
            "flag proximity",
            "expected payoff",
            "time cost",
        ]
    )
    report_requirements: list[str] = field(
        default_factory=lambda: [
            "stop once the real flag is obtained and recorded",
            "leave enough artifacts for replay in workspace",
        ]
    )


class ArtifactStore:
    """Persist intent-native artifacts inside the existing workspace."""

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

    REQUIRED_ARTIFACTS = (
        "recon_summary",
        "surface_map",
        "hypotheses",
        "candidate_findings",
        "candidate_evidence",
        "verified_findings",
        "final_report_reference",
    )

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace)
        self.root = self.workspace / "intentlang"
        self.artifacts_dir = self.root / "artifacts"
        self.metadata_dir = self.root / "metadata"

    def bootstrap(self) -> None:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        for name in self.REQUIRED_ARTIFACTS:
            path = self.artifacts_dir / f"{name}.json"
            if not path.exists():
                self.write_json(path, {"artifact": name, "items": [], "updated_at": _utc_timestamp()})
        if TEMPLATE_SOURCE.exists():
            template_target = self.metadata_dir / "pentest_report_template.docx"
            if not template_target.exists():
                shutil.copy2(TEMPLATE_SOURCE, template_target)

    def write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def update_artifact(self, name: str, items: list[dict[str, Any]], **extra: Any) -> Path:
        payload = {"artifact": name, "items": items, "updated_at": _utc_timestamp(), **extra}
        path = self.artifacts_dir / f"{name}.json"
        self.write_json(path, payload)
        return path

    def write_metadata(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.metadata_dir / f"{name}.json"
        self.write_json(path, payload)
        return path


class IntentRuntime:
    """Build and persist the minimum intent-native runtime state for a run."""

    def __init__(self, *, target: str, mode: str, workspace: str | Path):
        self.target = target
        self.mode = mode
        self.workspace = Path(workspace)
        self.artifacts = ArtifactStore(self.workspace)
        self.runtime_objects = self._build_runtime_objects()
        self.strategy = self._build_strategy()
        self.intents = self._build_intents()

    def _build_runtime_objects(self) -> list[RuntimeObject]:
        return [
            RuntimeObject(
                name="browser",
                kind="embedded-runtime-object",
                location="toolset.browser",
                description="Interactive browser automation for recon, login flow analysis, and screenshots.",
            ),
            RuntimeObject(
                name="terminal",
                kind="embedded-runtime-object",
                location="toolset.terminal",
                description="Stateful terminal sessions for reconnaissance and exploit tooling.",
            ),
            RuntimeObject(
                name="proxy",
                kind="embedded-runtime-object",
                location="toolset.proxy",
                description="HTTP traffic inspection for evidence capture and request replay.",
            ),
            RuntimeObject(
                name="report",
                kind="embedded-runtime-object",
                location="toolset.report",
                description="Report generation and screenshot persistence inside the workspace.",
            ),
        ]

    def _build_strategy(self) -> BaseStrategy:
        if self.mode == "pentest":
            return PentestStrategy()
        return CTFStrategy()

    def _build_intents(self) -> list[BaseIntent]:
        base_constraints = [
            "Do not scan ports or IP segments outside the target.",
            "Use structured artifacts in /home/ubuntu/Workspace/intentlang/ instead of relying on memory only.",
        ]

        if self.mode == "pentest":
            return [
                WebReconIntent(
                    target=self.target,
                    objective="Map web entry points, technologies, auth model, and reachable parameters.",
                    success_criteria=[
                        "recon summary artifact updated",
                        "surface map artifact updated",
                        "at least one hypothesis recorded when suspicious behavior is observed",
                    ],
                    constraints=base_constraints
                    + [
                        "Avoid destructive actions and stop if the target becomes unstable.",
                        "Rate-limit requests and do not perform DoS-style activity.",
                    ],
                ),
                WebVerificationIntent(
                    target=self.target,
                    objective="Convert candidate findings into verified findings with reproducible evidence.",
                    success_criteria=[
                        "verified findings artifact updated for every confirmed issue",
                        "candidate evidence retained even if verification fails",
                        "final report reference artifact points to generated report when reporting is complete",
                    ],
                    constraints=base_constraints
                    + [
                        "Every verified vulnerability must have screenshot evidence.",
                        "No destructive database or state-changing payloads.",
                    ],
                ),
            ]

        return [
            CTFGoalIntent(
                target=self.target,
                objective="Recover the real competition flag as quickly as possible and preserve the proof path.",
                success_criteria=[
                    "flag captured in reproducible evidence",
                    "candidate artifacts retain the path that led to the flag",
                ],
                constraints=base_constraints
                + [
                    "End immediately after obtaining a real flag and recording evidence.",
                ],
            )
        ]

    def bootstrap(self) -> None:
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.artifacts.bootstrap()
        self.artifacts.write_metadata(
            "run",
            {
                "target": self.target,
                "mode": self.mode,
                "created_at": _utc_timestamp(),
            },
        )
        self.artifacts.write_metadata(
            "strategy",
            asdict(self.strategy),
        )
        self.artifacts.write_metadata(
            "runtime_objects",
            {"items": [asdict(obj) for obj in self.runtime_objects]},
        )
        self.artifacts.write_metadata(
            "intents",
            {"items": [asdict(intent) for intent in self.intents]},
        )
        self.artifacts.write_metadata(
            "artifact_schemas",
            {"items": self.artifacts.ARTIFACT_SCHEMAS},
        )

    def render_agent_task(self) -> str:
        runtime_objects = "\n".join(
            f"- {obj.name}: {obj.location} ({obj.description})" for obj in self.runtime_objects
        )
        intent_section = "\n".join(
            [
                f"- {intent.kind}: {intent.objective}\n"
                f"  Success criteria: {'; '.join(intent.success_criteria)}\n"
                f"  Constraints: {'; '.join(intent.constraints)}"
                for intent in self.intents
            ]
        )

        strategy = self.strategy
        task_header = (
            "Use the security-agent with an intent-native workflow."
            if self.mode == "pentest"
            else "Use the security-agent with an intent-native workflow for this CTF target."
        )

        mode_specific = (
            "\n".join(
                [
                    "This is a WEB PENETRATION TEST (NOT a CTF).",
                    "Do not stop on flag-like strings or trivia; complete recon, verification, and reporting.",
                    "The final report MUST be written entirely in Chinese.",
                    "The final report MUST be a Word document (.docx).",
                    "Use toolset.report.generate_word_report() for the final report with embedded screenshots.",
                ]
            )
            if self.mode == "pentest"
            else "\n".join(
                [
                    "This is a CTF challenge.",
                    "Your goal is to obtain the real flag (format flag{...} or FLAG{...}).",
                    "Do not stop on decoy strings, hashes, tokens, or plaintext values that do not exactly match flag{...} or FLAG{...}.",
                    "Record non-matching values only as candidate evidence or intermediate findings, not as the final flag.",
                    "Stop only after a real flag matching flag{...} or FLAG{...} is obtained and recorded.",
                ]
            )
        )

        return f"""
{task_header}

Target: {self.target}
Mode: {self.mode}

{mode_specific}

Intent-native contract:
1. Read and follow the structured runtime metadata in /home/ubuntu/Workspace/intentlang/metadata/.
2. Treat /home/ubuntu/Workspace/intentlang/artifacts/ as the persistent memory plane for this run.
3. Update candidate artifacts aggressively when you discover useful signals; only be strict when promoting to verified findings or final report reference.
4. Use Python code to orchestrate runtime objects instead of step-by-step conversational tool calls.

Runtime objects:
{runtime_objects}
- intentlang memory: toolset.intentlang (use it to read metadata and append/replace structured artifacts)

Strategy:
- name: {strategy.name}
- aggression: {strategy.aggression_level}
- allow early stop: {strategy.allow_early_stop}
- priority testing types: {', '.join(strategy.priority_testing_types)}
- evidence requirements: {', '.join(strategy.evidence_requirements)}
- hypothesis sorting: {', '.join(strategy.hypothesis_sorting)}
- report requirements: {', '.join(strategy.report_requirements)}

Intents:
{intent_section}

Safety rules:
- Do not scan ports or IP segments outside the target.
- Avoid DoS behavior, destructive writes, or unsafe high-rate activity.
- Prefer storing findings and evidence into artifacts as you go instead of relying on context recall.
""".strip()

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .contracts import ARTIFACT_SCHEMAS, extract_target_host_patterns

CONTAINER_WORKSPACE = "/home/ubuntu/Workspace"
CONTENT_INLINE_THRESHOLD_BYTES = 4096
DEFAULT_COMMAND_TIMEOUT_SECONDS = 30
DEFAULT_ALLOWED_HOST_PATTERNS = [
    "127.0.0.1",
    "::1",
    "localhost",
    "example.com",
    ".example.com",
    "example.org",
    ".example.org",
    "example.net",
    ".example.net",
]
DANGEROUS_COMMAND_PATTERNS = [
    "rm -rf /",
    "mkfs.*",
    "dd if=/dev/zero",
    ":(){ :|:& };:",
]


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


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
    contexts: dict[str, Any] = field(default_factory=dict)
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
            "entry-point reconnaissance",
            "authz+authn review",
            "high-signal injection tests",
        ]
    )
    aggression_level: str = "controlled"
    allow_early_stop: bool = True
    evidence_requirements: list[str] = field(
        default_factory=lambda: [
            "preserve reproducible HTTP/browser evidence",
            "capture screenshots for high-risk verified findings; allow HTTP or terminal evidence for medium/low risk issues",
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
            "generate structured artifacts first and prefer a docx report as the finalize step; fall back to markdown or html if docx tooling is unavailable",
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
    ARTIFACT_SCHEMAS = ARTIFACT_SCHEMAS

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
            f"Use structured artifacts in {CONTAINER_WORKSPACE}/intentlang/ instead of relying on memory only.",
        ]
        target_host = self._target_host()

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
                    contexts={
                        "authorization_scope": "Only test the supplied target and directly related in-scope web paths.",
                        "target_host": target_host,
                        "known_limitations": "Do not assume credentials, internal network reachability, or out-of-scope hosts.",
                    },
                ),
                WebVerificationIntent(
                    target=self.target,
                    objective="Convert candidate findings into verified findings with reproducible evidence.",
                    success_criteria=[
                        "verified findings artifact updated for every confirmed issue",
                        "candidate evidence retained even if verification fails",
                    ],
                    constraints=base_constraints
                    + [
                        "High-risk verified vulnerabilities must include screenshot evidence; medium/low-risk findings may use HTTP transcripts or terminal output as equivalent proof.",
                        "No destructive database or state-changing payloads.",
                    ],
                    contexts={
                        "authorization_scope": "Validate only findings discovered on the supplied target.",
                        "target_host": target_host,
                        "evidence_policy": "Prefer reproducible HTTP, browser, screenshot, or terminal proof tied to artifacts.",
                    },
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
                contexts={
                    "challenge_context": "Flag format must come from challenge/platform hints or runtime metadata, not a hardcoded prefix.",
                    "flag_format_hint": "",
                    "accepted_flag_patterns": [],
                    "target_host": target_host,
                },
            )
        ]

    def _target_host(self) -> str:
        parsed = urlsplit(self.target if "://" in self.target else f"http://{self.target}")
        return parsed.hostname or self.target

    def _security_policy_payload(self) -> dict[str, Any]:
        return {
            "command_timeout_seconds": DEFAULT_COMMAND_TIMEOUT_SECONDS,
            "allowed_host_patterns": [
                *DEFAULT_ALLOWED_HOST_PATTERNS,
                *[pattern for pattern in extract_target_host_patterns(self.target) if pattern not in DEFAULT_ALLOWED_HOST_PATTERNS],
            ],
            "dangerous_command_patterns": DANGEROUS_COMMAND_PATTERNS,
            "content_inline_threshold_bytes": CONTENT_INLINE_THRESHOLD_BYTES,
            "container_workspace": CONTAINER_WORKSPACE,
            "flag_format_hint": "",
            "accepted_flag_patterns": [],
        }

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
        self.artifacts.write_metadata(
            "security_policy",
            self._security_policy_payload(),
        )

    def render_agent_task(self) -> str:
        task_header = "Use the security-agent with an intent-native workflow."

        mode_specific = (
            "\n".join(
                [
                    "This is a WEB PENETRATION TEST (NOT a CTF).",
                    "Default time budget: 15-25 minutes unless the user explicitly requests deeper coverage.",
                    "Do not stop on flag-like strings or trivia; focus on verified security findings.",
                    "The final report MUST be written entirely in Chinese.",
                ]
            )
            if self.mode == "pentest"
            else "\n".join(
                [
                    "This is a CTF challenge.",
                    "Prefer the shortest high-yield path to the real flag over exhaustive coverage or long-running scans.",
                    "Take the final flag format from the challenge, platform, or runtime metadata hints; do not assume a fixed prefix.",
                    "Record promising values as candidate evidence even when they do not match a known hint yet.",
                ]
            )
        )

        return f"""
{task_header}

Target: {self.target}
Mode: {self.mode}

{mode_specific}

Intent-native contract:
1. Read run, strategy, intents, runtime_objects, artifact_schemas, and security_policy from {CONTAINER_WORKSPACE}/intentlang/metadata/ before taking action.
2. Treat {CONTAINER_WORKSPACE}/intentlang/artifacts/ as the persistent memory plane for this run.
3. Use metadata as the source of truth for strategy, contexts, and allowed runtime behavior instead of relying on prompt-local copies.
4. Update candidate artifacts aggressively when you discover useful signals; only be strict when promoting to verified findings or final report reference.
5. Use Python code to orchestrate runtime objects instead of step-by-step conversational tool calls.
6. Prefer toolset.terminal.run_command(...) for one-shot shell commands; use interactive terminal sessions only when shell state or incremental input truly matters.
7. Use proxy methods by their real names: list_traffic(...), view_traffic(...), and replay_request(...). Do not guess API names.
8. If the runtime surface looks incomplete or unexpected, call toolset.intentlang.validate_runtime_contract() before proceeding.
9. Write candidate artifacts before expanding coverage so promising leads are not lost.

Safety rules:
- Do not scan ports or IP segments outside the target.
- Avoid DoS behavior, destructive writes, or unsafe high-rate activity.
- Prefer storing findings and evidence into artifacts as you go instead of relying on context recall.
- Respect security_policy.json for command timeout, dangerous command blocking, and allowed target hosts.
""".strip()

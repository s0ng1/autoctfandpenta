import importlib.util
import io
import json
import sys
import types
import unittest
import zipfile
from builtins import __import__ as builtin_import
from base64 import b64decode
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOLSET_SRC = ROOT / "meta-tooling" / "toolset" / "src"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TOOLSET_SRC))
DOCX_AVAILABLE = importlib.util.find_spec("docx") is not None

import YuPentestPilot
from intentlang import IntentRuntime
from intentlang.contracts import ARTIFACT_SCHEMAS


def _load_intentlang_memory_class():
    core_stub = types.ModuleType("core")

    def _identity_decorator(*args, **kwargs):
        if args and callable(args[0]) and len(args) == 1 and not kwargs:
            return args[0]

        def decorator(obj):
            return obj

        return decorator

    core_stub.namespace = lambda: None
    core_stub.tool = _identity_decorator
    core_stub.toolset = _identity_decorator
    sys.modules.setdefault("core", core_stub)

    module_path = ROOT / "meta-tooling" / "toolset" / "src" / "toolset" / "intentlang" / "intentlang.py"
    spec = importlib.util.spec_from_file_location("intentlang_memory_module", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.IntentLangMemory


def _load_report_generator_class():
    core_stub = sys.modules["core"]
    module_path = ROOT / "meta-tooling" / "toolset" / "src" / "toolset" / "report" / "report.py"
    spec = importlib.util.spec_from_file_location("report_module", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.ReportGenerator


def _load_proxy_class():
    requests_stub = types.ModuleType("requests")
    requests_stub.request = lambda *args, **kwargs: None
    sys.modules.setdefault("requests", requests_stub)

    gql_stub = types.ModuleType("gql")
    gql_stub.gql = lambda query: query

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def execute(self, *args, **kwargs):
            return {}

    gql_stub.Client = _FakeClient
    sys.modules.setdefault("gql", gql_stub)

    gql_transport_stub = types.ModuleType("gql.transport")
    sys.modules.setdefault("gql.transport", gql_transport_stub)

    gql_requests_stub = types.ModuleType("gql.transport.requests")

    class _FakeTransport:
        def __init__(self, *args, **kwargs):
            pass

    gql_requests_stub.RequestsHTTPTransport = _FakeTransport
    sys.modules.setdefault("gql.transport.requests", gql_requests_stub)

    module_path = ROOT / "meta-tooling" / "toolset" / "src" / "toolset" / "proxy" / "proxy.py"
    spec = importlib.util.spec_from_file_location("proxy_module", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.Proxy


IntentLangMemory = _load_intentlang_memory_class()
ReportGenerator = _load_report_generator_class()
Proxy = _load_proxy_class()

from security_guard import SecurityViolation, validate_command


def _load_python_executor_class():
    nbformat_stub = types.ModuleType("nbformat")
    nbformat_stub.write = lambda *args, **kwargs: None
    nbformat_v4_stub = types.ModuleType("nbformat.v4")
    nbformat_v4_stub.new_notebook = lambda: types.SimpleNamespace(cells=[])
    nbformat_v4_stub.new_code_cell = lambda code, execution_count=None: types.SimpleNamespace(code=code, execution_count=execution_count, outputs=[])
    nbformat_v4_stub.new_output = lambda output_type, **kwargs: types.SimpleNamespace(output_type=output_type, **kwargs)
    nbformat_stub.v4 = nbformat_v4_stub
    sys.modules.setdefault("nbformat", nbformat_stub)
    sys.modules.setdefault("nbformat.v4", nbformat_v4_stub)

    jupyter_client_stub = types.ModuleType("jupyter_client")
    jupyter_client_stub.KernelManager = object
    sys.modules.setdefault("jupyter_client", jupyter_client_stub)

    fastmcp_stub = types.ModuleType("fastmcp")

    class _FakeFastMCP:
        def __init__(self, *args, **kwargs):
            pass

        def tool(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

        def run(self, *args, **kwargs):
            return None

    fastmcp_stub.FastMCP = _FakeFastMCP
    sys.modules.setdefault("fastmcp", fastmcp_stub)

    module_path = ROOT / "meta-tooling" / "service" / "python_executor_mcp.py"
    spec = importlib.util.spec_from_file_location("python_executor_module", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.PythonExecutor


PythonExecutor = _load_python_executor_class()


class _FakeExecResult:
    def __init__(self, exit_code, output):
        self.exit_code = exit_code
        self.output = output


class _FakeContainer:
    def __init__(self):
        self.calls = []
        self.last_task = ""

    def exec_run(self, args, workdir=None):
        self.calls.append({"args": args, "workdir": workdir})
        if args == ["bash", "wait.sh"]:
            return _FakeExecResult(0, b"ready")
        self.last_task = args[-1]
        return _FakeExecResult(0, b"agent finished")


class _FakeSandboxRuntime:
    instances = []

    def __init__(self, vnc_port, workspace):
        self.vnc_port = vnc_port
        self.workspace = workspace
        self.container = _FakeContainer()
        self.cleaned = False
        type(self).instances.append(self)

    def cleanup(self):
        self.cleaned = True


class IntentLangCliE2ETest(unittest.TestCase):
    def setUp(self):
        _FakeSandboxRuntime.instances.clear()

    def test_pentest_cli_bootstraps_workspace_and_hands_structured_task_to_agent(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir) / "workspace"
            stdout = io.StringIO()
            argv = [
                "YuPentestPilot.py",
                "--ctf",
                "https://target.example",
                "--mode",
                "pentest",
                "--workspace",
                str(workspace),
                "--vnc-port",
                "5991",
            ]

            with patch.object(YuPentestPilot, "YuPentestPilotRuntime", _FakeSandboxRuntime):
                with patch.object(sys, "argv", argv):
                    with redirect_stdout(stdout):
                        YuPentestPilot.main()

            self.assertEqual(len(_FakeSandboxRuntime.instances), 1)
            sandbox = _FakeSandboxRuntime.instances[0]
            self.assertTrue(sandbox.cleaned)
            self.assertEqual(sandbox.vnc_port, 5991)

            task = sandbox.container.last_task
            self.assertIn("Mode: pentest", task)
            self.assertIn("Default time budget: 15-25 minutes unless the user explicitly requests deeper coverage.", task)
            self.assertIn("Use metadata as the source of truth for strategy, contexts, and allowed runtime behavior", task)
            self.assertIn("Prefer toolset.terminal.run_command(...) for one-shot shell commands", task)
            self.assertIn("Use proxy methods by their real names: list_traffic(...), view_traffic(...), and replay_request(...).", task)
            self.assertIn("Read run, strategy, intents, runtime_objects, artifact_schemas, and security_policy", task)
            self.assertNotIn("Strategy:", task)
            self.assertNotIn("Intents:", task)

            metadata_dir = workspace / "intentlang" / "metadata"
            artifacts_dir = workspace / "intentlang" / "artifacts"
            self.assertTrue((metadata_dir / "run.json").exists())
            self.assertTrue((metadata_dir / "strategy.json").exists())
            self.assertTrue((artifacts_dir / "verified_findings.json").exists())

            run_payload = json.loads((metadata_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(run_payload["mode"], "pentest")
            self.assertEqual(run_payload["target"], "https://target.example")
            security_policy = json.loads((metadata_dir / "security_policy.json").read_text(encoding="utf-8"))
            self.assertIn("target.example", security_policy["allowed_host_patterns"])

            output = stdout.getvalue()
            self.assertIn("[+] 模式: 渗透测试", output)
            self.assertIn("[+] 结束运行", output)

    def test_ctf_cli_bootstraps_workspace_and_hands_ctf_task_to_agent(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir) / "workspace"
            stdout = io.StringIO()
            argv = [
                "YuPentestPilot.py",
                "--ctf",
                "http://ctf.local/challenge",
                "--mode",
                "ctf",
                "--workspace",
                str(workspace),
            ]

            with patch.object(YuPentestPilot, "YuPentestPilotRuntime", _FakeSandboxRuntime):
                with patch.object(sys, "argv", argv):
                    with redirect_stdout(stdout):
                        YuPentestPilot.main()

            sandbox = _FakeSandboxRuntime.instances[0]
            task = sandbox.container.last_task
            self.assertIn("Mode: ctf", task)
            self.assertIn("This is a CTF challenge.", task)
            self.assertIn("Prefer the shortest high-yield path to the real flag over exhaustive coverage or long-running scans.", task)
            self.assertIn("Take the final flag format from the challenge, platform, or runtime metadata hints; do not assume a fixed prefix.", task)
            self.assertIn("Record promising values as candidate evidence even when they do not match a known hint yet.", task)

            intents_payload = json.loads((workspace / "intentlang" / "metadata" / "intents.json").read_text(encoding="utf-8"))
            self.assertEqual(len(intents_payload["items"]), 1)
            self.assertEqual(intents_payload["items"][0]["kind"], "CTFGoalIntent")
            self.assertIn("contexts", intents_payload["items"][0])

            output = stdout.getvalue()
            self.assertIn("[+] 模式: CTF 解题", output)


class IntentLangMemoryE2ETest(unittest.TestCase):
    def _write_test_png(self, path: Path) -> None:
        png_bytes = b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WnR6ukAAAAASUVORK5CYII="
        )
        path.write_bytes(png_bytes)

    def test_pentest_runtime_round_trip_reaches_verified_finding_and_report_reference(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://app.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            self.assertIn("strategy", memory.list_metadata())
            self.assertIn("candidate_findings", memory.list_artifacts())

            memory.append_artifact_item(
                "candidate_findings",
                {
                    "title": "Reflected XSS in search",
                    "type": "xss",
                    "summary": "Search parameter reflects raw HTML.",
                    "severity": "高危",
                    "confidence": "high",
                },
            )
            memory.promote_artifact_item(
                "candidate_findings",
                "verified_findings",
                item_index=0,
                updates={
                    "evidence_summary": "Payload executed in browser and screenshot captured.",
                    "reproduction_steps": "Open /search?q=<svg/onload=alert(1)>",
                    "screenshot_path": "/home/ubuntu/Workspace/screenshots/xss.png",
                    "remediation": "Escape reflected output and add contextual encoding.",
                },
            )
            memory.set_final_report_reference(
                str(workspace / "reports" / "pentest.docx"),
                "docx",
                "已生成正式渗透测试报告",
            )

            verified = memory.read_artifact("verified_findings")
            self.assertEqual(len(verified["items"]), 1)
            self.assertEqual(verified["items"][0]["type"], "xss")
            self.assertEqual(verified["items"][0]["severity"], "高危")
            self.assertEqual(verified["items"][0]["promoted_from"], "candidate_findings")

            report_ref = memory.read_artifact("final_report_reference")
            self.assertEqual(report_ref["items"][0]["type"], "docx")
            self.assertTrue(report_ref["items"][0]["path"].endswith("pentest.docx"))

    def test_large_candidate_evidence_content_spills_to_file_and_is_hydrated_on_read(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://spill.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            large_content = "A" * 5000
            memory.append_artifact_item(
                "candidate_evidence",
                {
                    "kind": "http",
                    "summary": "Large HTTP transcript",
                    "content": large_content,
                },
            )

            raw_payload = json.loads((workspace / "intentlang" / "artifacts" / "candidate_evidence.json").read_text(encoding="utf-8"))
            raw_item = raw_payload["items"][0]
            self.assertNotIn("content", raw_item)
            self.assertIn("path", raw_item)
            self.assertTrue(Path(raw_item["path"]).exists())
            self.assertEqual(raw_item["summary"], "Large HTTP transcript")

            hydrated_payload = memory.read_artifact("candidate_evidence")
            self.assertEqual(hydrated_payload["items"][0]["content"], large_content)

    def test_verified_findings_upsert_merges_duplicate_entries_and_preserves_richer_fields(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://merge.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            memory.upsert_verified_finding(
                {
                    "title": "Reflected XSS in search",
                    "type": "xss",
                    "summary": "User-controlled search term is reflected.",
                    "severity": "高危",
                    "target": "https://merge.example/search",
                    "evidence_summary": "Initial browser proof captured.",
                }
            )
            memory.upsert_verified_finding(
                {
                    "title": " Reflected   XSS in Search ",
                    "type": "xss",
                    "summary": "Confirmed code execution via payload.",
                    "target": "https://merge.example/search",
                    "screenshot_path": "/tmp/xss-proof.png",
                    "remediation": "Apply contextual output encoding.",
                }
            )
            memory.deduplicate_verified_findings()

            verified = memory.read_artifact("verified_findings")
            self.assertEqual(len(verified["items"]), 1)
            finding = verified["items"][0]
            self.assertEqual(finding["severity"], "高危")
            self.assertEqual(finding["screenshot_path"], "/tmp/xss-proof.png")
            self.assertEqual(finding["remediation"], "Apply contextual output encoding.")
            self.assertEqual(finding["control_point"], "入侵防范")
            self.assertNotEqual(finding["evaluation_unit"], "")

    def test_ctf_runtime_round_trip_records_flag_and_generates_report(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="http://ctf.example", mode="ctf", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            memory.record_ctf_flag(
                "HTB{demo-flag}",
                "Obtained from admin panel after SQL injection.",
                target="http://ctf.example",
            )
            report_path = Path(
                memory.save_ctf_report(
                    "http://ctf.example",
                    "HTB{demo-flag}",
                    "先通过注入拿到管理员会话，再进入后台读取 flag。",
                )
            )

            self.assertTrue(report_path.exists())
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("HTB{demo-flag}", report_text)

            verified = memory.read_artifact("verified_findings")
            self.assertEqual(len(verified["items"]), 1)
            self.assertEqual(verified["items"][0]["type"], "flag")
            self.assertEqual(verified["items"][0]["flag"], "HTB{demo-flag}")
            self.assertEqual(verified["items"][0]["format_confidence"], "medium")
            self.assertTrue(verified["items"][0]["matches_hint"])

            report_ref = memory.read_artifact("final_report_reference")
            self.assertEqual(report_ref["items"][0]["type"], "md")
            self.assertEqual(report_ref["items"][0]["path"], str(report_path))

    def test_ctf_flag_recording_uses_hint_without_blocking_storage(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="http://ctf.example", mode="ctf", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))
            policy_path = workspace / "intentlang" / "metadata" / "security_policy.json"
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            policy["flag_format_hint"] = "HTB{...}"
            policy_path.write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

            memory.record_ctf_flag(
                "token-demo-123",
                "Found after SQL injection, but does not match the expected HTB flag wrapper.",
                target="http://ctf.example",
            )
            verified = memory.read_artifact("verified_findings")
            self.assertEqual(verified["items"][0]["flag"], "token-demo-123")
            self.assertEqual(verified["items"][0]["format_hint"], "HTB{...}")
            self.assertFalse(verified["items"][0]["matches_hint"])
            self.assertEqual(verified["items"][0]["format_confidence"], "low")

            report_path = Path(
                memory.save_ctf_report(
                    "http://ctf.example",
                    "token-demo-123",
                    "虽然格式不匹配题面 hint，但报告保存不应被阻塞。",
                )
            )
            self.assertTrue(report_path.exists())

    def test_ctf_flag_recording_rejects_empty_or_multiline_values(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="http://ctf.example", mode="ctf", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            with self.assertRaisesRegex(ValueError, "ctf flag must not be empty"):
                memory.record_ctf_flag("", "missing")
            with self.assertRaisesRegex(ValueError, "ctf flag must be a single line"):
                memory.record_ctf_flag("line1\nline2", "invalid")

    def test_artifact_schemas_are_shared_between_runtime_and_toolset(self):
        self.assertIs(IntentRuntime(target="https://schema.example", mode="pentest", workspace="/tmp").artifacts.ARTIFACT_SCHEMAS, ARTIFACT_SCHEMAS)
        self.assertIs(IntentLangMemory.ARTIFACT_SCHEMAS, ARTIFACT_SCHEMAS)

    def test_promote_artifact_item_ignores_empty_updates(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://merge.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            memory.append_artifact_item(
                "candidate_findings",
                {
                    "title": "SQL Injection in login",
                    "type": "sqli",
                    "summary": "The login form is injectable.",
                    "severity": "高危",
                },
            )
            memory.promote_artifact_item(
                source_name="candidate_findings",
                target_name="verified_findings",
                item_index=0,
                updates={"severity": "", "screenshot_path": ""},
            )

            finding = memory.read_artifact("verified_findings")["items"][0]
            self.assertEqual(finding["severity"], "高危")
            self.assertNotIn("screenshot_path", finding)

    def test_read_artifact_marks_missing_large_payload_files(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://payload.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            large_content = "A" * 4106
            memory.append_artifact_item(
                "candidate_evidence",
                {
                    "kind": "terminal",
                    "summary": "Large terminal output",
                    "content": large_content,
                },
            )
            artifact = memory.read_artifact("candidate_evidence")
            payload_path = Path(artifact["items"][0]["path"])
            payload_path.unlink()

            hydrated = memory.read_artifact("candidate_evidence")
            self.assertIn("[ERROR: payload file missing:", hydrated["items"][0]["content"])

    def test_generate_word_report_from_artifacts_updates_final_report_reference(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://report.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))
            report = ReportGenerator(workspace=str(workspace))

            memory.append_verified_finding(
                title="SQL Injection in login",
                vuln_type="sqli",
                summary="The login form is injectable.",
                severity="高危",
                description="The username field is concatenated into the SQL statement.",
                test_process="POST /login with payload ' OR '1'='1",
                risk_analysis="An attacker can bypass authentication and access sensitive data.",
                remediation="Use parameterized queries.",
                vuln_url="https://report.example/login",
                target="https://report.example",
            )

            report_path = Path(report.generate_word_report_from_artifacts("https://report.example"))
            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.suffix, ".docx" if DOCX_AVAILABLE else ".md")

            report_ref = memory.read_artifact("final_report_reference")
            self.assertEqual(report_ref["items"][0]["type"], "docx" if DOCX_AVAILABLE else "md")
            self.assertEqual(report_ref["items"][0]["path"], str(report_path))

    def test_generate_word_report_does_not_require_private_template_file(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://report.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))
            report = ReportGenerator(workspace=str(workspace))

            memory.append_verified_finding(
                title="IDOR in order detail",
                vuln_type="idor",
                summary="Changing the order id exposes another user's record.",
                severity="中危",
                test_process="Request /order/1002/detail after logging in as a different user.",
                risk_analysis="Attackers can view unauthorized order information.",
                remediation="Enforce object-level authorization checks.",
                target="https://report.example/order/1002/detail",
            )

            self.assertFalse((workspace / "intentlang" / "metadata" / "pentest_report_template.docx").exists())
            report_path = Path(report.generate_word_report_from_artifacts("https://report.example"))
            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.suffix, ".docx" if DOCX_AVAILABLE else ".md")

    def test_generate_word_report_falls_back_to_markdown_when_docx_dependency_is_missing(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://report.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))
            report = ReportGenerator(workspace=str(workspace))

            memory.append_verified_finding(
                title="Open Redirect in redirect endpoint",
                vuln_type="logic",
                summary="The redirect endpoint accepts arbitrary external targets.",
                severity="中危",
                test_process="Submit ?next=https://evil.example and observe external redirect.",
                risk_analysis="Attackers can abuse trust relationships for phishing.",
                remediation="Restrict redirects to an allowlist.",
                target="https://report.example/redirect",
            )

            def _import_without_docx(name, globals=None, locals=None, fromlist=(), level=0):
                if name == "docx":
                    raise ImportError("docx unavailable in sandbox")
                return builtin_import(name, globals, locals, fromlist, level)

            with patch("builtins.__import__", side_effect=_import_without_docx):
                report_path = Path(report.generate_word_report_from_artifacts("https://report.example"))

            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.suffix, ".md")
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("python-docx 不可用", report_text)

            report_ref = memory.read_artifact("final_report_reference")
            self.assertEqual(report_ref["items"][0]["type"], "md")
            self.assertEqual(report_ref["items"][0]["path"], str(report_path))

    def test_generate_word_report_uses_candidate_evidence_screenshot_when_verified_finding_path_is_missing(self):
        if not DOCX_AVAILABLE:
            self.skipTest("python-docx not installed")
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://report.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))
            report = ReportGenerator(workspace=str(workspace))

            screenshot_path = workspace / "screenshots" / "xss-proof.png"
            screenshot_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_test_png(screenshot_path)

            memory.append_artifact_item(
                "candidate_evidence",
                {
                    "kind": "screenshot",
                    "summary": "Stored XSS proof screenshot.",
                    "path": str(screenshot_path),
                    "related_finding": "Reflected XSS in search",
                },
            )
            memory.append_verified_finding(
                title="Reflected XSS in search",
                vuln_type="xss",
                summary="Search parameter triggers script execution.",
                severity="高危",
                test_process="Open the vulnerable URL and observe script execution.",
                risk_analysis="An attacker can execute JavaScript in the victim browser.",
                remediation="Escape output before rendering.",
                target="https://report.example/search",
            )

            report_path = Path(report.generate_word_report_from_artifacts("https://report.example"))
            self.assertTrue(report_path.exists())

            with zipfile.ZipFile(report_path) as archive:
                media_files = [name for name in archive.namelist() if name.startswith("word/media/")]
            self.assertTrue(media_files)

    def test_generate_word_report_prefers_evidence_and_finding_ids_for_screenshot_association(self):
        if not DOCX_AVAILABLE:
            self.skipTest("python-docx not installed")
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://report.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))
            report = ReportGenerator(workspace=str(workspace))

            screenshot_path = workspace / "screenshots" / "idor-proof.png"
            screenshot_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_test_png(screenshot_path)

            memory.append_artifact_item(
                "candidate_evidence",
                {
                    "kind": "screenshot",
                    "summary": "ID-based screenshot proof.",
                    "path": str(screenshot_path),
                    "finding_id": "finding-123",
                    "evidence_id": "evidence-456",
                    "related_finding": "Some Other Title",
                },
            )
            memory.append_verified_finding(
                title="Order detail IDOR",
                vuln_type="idor",
                summary="Unauthorized order access is possible.",
                severity="中危",
                test_process="Replay another user's order request after login.",
                risk_analysis="Attackers can access another user's order details.",
                remediation="Enforce object-level authorization checks.",
                target="https://report.example/order/1002/detail",
                finding_id="finding-123",
                evidence_id="evidence-456",
            )

            report_path = Path(report.generate_word_report_from_artifacts("https://report.example"))
            self.assertTrue(report_path.exists())

            with zipfile.ZipFile(report_path) as archive:
                media_files = [name for name in archive.namelist() if name.startswith("word/media/")]
            self.assertTrue(media_files)

    def test_generate_report_supports_html_format(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://report.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))
            report = ReportGenerator(workspace=tempdir)

            memory.append_verified_finding(
                title="Directory Listing Enabled",
                vuln_type="other",
                summary="Web server exposes index listing.",
                severity="低危",
                test_process="Browse to /uploads/ and observe auto-generated directory listing.",
                risk_analysis="Attackers can enumerate uploaded content and internal filenames.",
                remediation="Disable directory indexing on the web server.",
                target="https://report.example/uploads/",
            )

            report_path = Path(report.generate_report("https://report.example", [], format="html"))
            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.suffix, ".html")
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("<html", report_text)
            self.assertIn("Directory Listing Enabled", report_text)

            report_ref = memory.read_artifact("final_report_reference")
            self.assertEqual(report_ref["items"][0]["type"], "html")
            self.assertEqual(report_ref["items"][0]["path"], str(report_path))

    def test_validate_runtime_contract_reports_available_core_methods(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="https://contract.example", mode="pentest", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            toolset_stub = types.SimpleNamespace(
                terminal=types.SimpleNamespace(
                    run_command=lambda *args, **kwargs: None,
                    new_session=lambda *args, **kwargs: None,
                    send_keys=lambda *args, **kwargs: None,
                    get_output=lambda *args, **kwargs: None,
                ),
                proxy=types.SimpleNamespace(
                    list_traffic=lambda *args, **kwargs: None,
                    view_traffic=lambda *args, **kwargs: None,
                    replay_request=lambda *args, **kwargs: None,
                ),
                intentlang=types.SimpleNamespace(
                    read_metadata=lambda *args, **kwargs: None,
                    append_artifact_item=lambda *args, **kwargs: None,
                    promote_artifact_item=lambda *args, **kwargs: None,
                    record_ctf_flag=lambda *args, **kwargs: None,
                ),
                report=types.SimpleNamespace(
                    add_screenshot=lambda *args, **kwargs: None,
                    generate_word_report_from_artifacts=lambda *args, **kwargs: None,
                    generate_report=lambda *args, **kwargs: None,
                ),
            )

            with patch("importlib.import_module", return_value=toolset_stub):
                contract = memory.validate_runtime_contract()

            self.assertTrue(contract["ok"])
            self.assertEqual(contract["missing_namespaces"], [])
            self.assertEqual(contract["missing_methods"], {})
            self.assertIn("run_command", contract["available_methods"]["terminal"])
            self.assertIn("list_traffic", contract["available_methods"]["proxy"])


class ProxyCompatibilityTest(unittest.TestCase):
    def test_get_traffic_compat_alias_returns_list_traffic_result_with_migration_hint(self):
        proxy = object.__new__(Proxy)
        proxy.list_traffic = lambda limit=5, offset=0, filter=None: {
            "count": {"value": 1},
            "nodes": [{"request": {"id": "123"}}],
        }

        result = proxy.get_traffic(limit=3, filter='req.path.like:"%login%"')

        self.assertEqual(result["count"]["value"], 1)
        self.assertEqual(result["_compat"]["deprecated_method"], "get_traffic")
        self.assertEqual(result["_compat"]["replacement"], "list_traffic")


class SecurityAgentContractTest(unittest.TestCase):
    def test_security_agent_examples_use_official_fast_path_apis(self):
        agent_path = ROOT / "claude_code" / ".claude" / "agents" / "security-agent.md"
        text = agent_path.read_text(encoding="utf-8")

        self.assertIn("toolset.intentlang.validate_runtime_contract()", text)
        self.assertIn("toolset.terminal.run_command(...)", text)
        self.assertIn("toolset.proxy.list_traffic(...)", text)
        self.assertIn("toolset.proxy.view_traffic(first_id)", text)
        self.assertIn("replay_request(...)", text)
        self.assertNotIn("toolset.proxy.get_traffic(", text)


class SecurityPolicyE2ETest(unittest.TestCase):
    def test_validate_command_blocks_dangerous_commands_and_disallowed_hosts(self):
        with self.assertRaises(SecurityViolation):
            validate_command("rm -rf /")
        with self.assertRaises(SecurityViolation):
            validate_command("curl https://evil.test")
        self.assertEqual(validate_command("curl https://app.example.com", timeout=12), 12)

    def test_python_executor_blocks_shell_escapes_before_kernel_execution(self):
        executor = PythonExecutor()

        def _should_not_create_session(_session_name):
            raise AssertionError("kernel should not start for blocked shell escapes")

        executor._create_session = _should_not_create_session  # type: ignore[method-assign]
        result = executor.execute_code("blocked", "!curl https://evil.test", timeout=5)
        self.assertEqual(result[0]["type"], "display_data")
        self.assertIn("[SECURITY]", result[0]["data"]["text/plain"])
        self.assertIn("blocked host outside allowlist", result[0]["data"]["text/plain"])


if __name__ == "__main__":
    unittest.main()

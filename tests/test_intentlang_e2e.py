import importlib.util
import io
import json
import sys
import types
import unittest
import zipfile
from base64 import b64decode
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOLSET_SRC = ROOT / "meta-tooling" / "toolset" / "src"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TOOLSET_SRC))

import YuPentestPilot
from intentlang import IntentRuntime


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


IntentLangMemory = _load_intentlang_memory_class()
ReportGenerator = _load_report_generator_class()

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
            self.assertIn("You may stop expanding coverage once you have either 1 high-risk finding or 2-3 medium-risk findings with complete evidence.", task)
            self.assertIn("Generate artifacts/markdown first; create a Word document (.docx) only as a finalize step when needed.", task)
            self.assertIn("toolset.intentlang", task)

            metadata_dir = workspace / "intentlang" / "metadata"
            artifacts_dir = workspace / "intentlang" / "artifacts"
            self.assertTrue((metadata_dir / "run.json").exists())
            self.assertTrue((metadata_dir / "strategy.json").exists())
            self.assertTrue((artifacts_dir / "verified_findings.json").exists())

            run_payload = json.loads((metadata_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(run_payload["mode"], "pentest")
            self.assertEqual(run_payload["target"], "https://target.example")

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
            self.assertIn("Do not stop on decoy strings, hashes, tokens, or plaintext values", task)
            self.assertIn("Stop only after a real flag matching flag{...} or FLAG{...} is obtained and recorded.", task)

            intents_payload = json.loads((workspace / "intentlang" / "metadata" / "intents.json").read_text(encoding="utf-8"))
            self.assertEqual(len(intents_payload["items"]), 1)
            self.assertEqual(intents_payload["items"][0]["kind"], "CTFGoalIntent")

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
                "flag{demo-flag}",
                "Obtained from admin panel after SQL injection.",
                target="http://ctf.example",
            )
            report_path = Path(
                memory.save_ctf_report(
                    "http://ctf.example",
                    "flag{demo-flag}",
                    "先通过注入拿到管理员会话，再进入后台读取 flag。",
                )
            )

            self.assertTrue(report_path.exists())
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("flag{demo-flag}", report_text)

            verified = memory.read_artifact("verified_findings")
            self.assertEqual(len(verified["items"]), 1)
            self.assertEqual(verified["items"][0]["type"], "flag")
            self.assertEqual(verified["items"][0]["flag"], "flag{demo-flag}")

            report_ref = memory.read_artifact("final_report_reference")
            self.assertEqual(report_ref["items"][0]["type"], "md")
            self.assertEqual(report_ref["items"][0]["path"], str(report_path))

    def test_ctf_flag_recording_rejects_non_standard_flag_values(self):
        with TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            runtime = IntentRuntime(target="http://ctf.example", mode="ctf", workspace=workspace)
            runtime.bootstrap()
            memory = IntentLangMemory(workspace=str(workspace))

            with self.assertRaisesRegex(ValueError, "ctf flag must match flag\\{...\\} or FLAG\\{...\\}"):
                memory.record_ctf_flag(
                    "htryyujryfhyjtrjn",
                    "Found after SQL injection, but not in final flag format.",
                    target="http://ctf.example",
                )

            with self.assertRaisesRegex(ValueError, "ctf flag must match flag\\{...\\} or FLAG\\{...\\}"):
                memory.save_ctf_report(
                    "http://ctf.example",
                    "not-a-real-flag",
                    "This should not produce a final report.",
                )

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
            self.assertEqual(report_path.suffix, ".docx")

            report_ref = memory.read_artifact("final_report_reference")
            self.assertEqual(report_ref["items"][0]["type"], "docx")
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
            self.assertEqual(report_path.suffix, ".docx")

    def test_generate_word_report_uses_candidate_evidence_screenshot_when_verified_finding_path_is_missing(self):
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

    def test_generate_report_rejects_html_format(self):
        with TemporaryDirectory() as tempdir:
            report = ReportGenerator(workspace=tempdir)
            result = report.generate_report("https://report.example", [], format="html")
            self.assertEqual(result, "[ERROR] Only docx reports are supported in Phase 1.")


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

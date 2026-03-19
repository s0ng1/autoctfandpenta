"""
报告生成模块 - 基于 verified_findings artifact 生成 Word 报告
"""

import json
import os
import re
from copy import deepcopy
from datetime import datetime
from typing import Annotated, Dict, List, Optional

from core import namespace, tool, toolset

namespace()


@toolset()
class ReportGenerator:
    """生成包含漏洞详情和截图的 Word 渗透测试报告"""

    SEVERITY_ORDER = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}

    def __init__(self, workspace: str = "/home/ubuntu/Workspace"):
        self.workspace = workspace
        self.screenshots_dir = os.path.join(workspace, "screenshots")
        self.template_path = os.path.join(workspace, "intentlang", "metadata", "pentest_report_template.docx")
        os.makedirs(self.workspace, exist_ok=True)
        os.makedirs(self.screenshots_dir, exist_ok=True)

    def _safe_filename(self, value: str) -> str:
        sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
        return sanitized or "report"

    def _write_final_report_reference(self, report_path: str, report_type: str, target: str, total_findings: int) -> None:
        artifacts_dir = os.path.join(self.workspace, "intentlang", "artifacts")
        os.makedirs(artifacts_dir, exist_ok=True)
        artifact_path = os.path.join(artifacts_dir, "final_report_reference.json")
        now = datetime.now().isoformat(timespec="seconds")
        payload = {
            "artifact": "final_report_reference",
            "items": [
                {
                    "path": report_path,
                    "type": report_type,
                    "target": target,
                    "total_findings": total_findings,
                    "recorded_at": now,
                }
            ],
            "updated_at": now,
        }
        with open(artifact_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write("\n")

    def _read_run_metadata(self) -> dict:
        metadata_path = os.path.join(self.workspace, "intentlang", "metadata", "run.json")
        if not os.path.exists(metadata_path):
            return {}
        with open(metadata_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _read_verified_findings_artifact(self) -> List[Dict]:
        artifact_path = os.path.join(self.workspace, "intentlang", "artifacts", "verified_findings.json")
        if not os.path.exists(artifact_path):
            return []
        with open(artifact_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return payload.get("items", [])

    def _read_candidate_evidence_artifact(self) -> List[Dict]:
        artifact_path = os.path.join(self.workspace, "intentlang", "artifacts", "candidate_evidence.json")
        if not os.path.exists(artifact_path):
            return []
        with open(artifact_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return payload.get("items", [])

    def _normalize_lookup_key(self, value: str) -> str:
        return " ".join(str(value or "").strip().lower().split())

    def _candidate_screenshot_index(self) -> dict[str, str]:
        screenshots: dict[str, str] = {}
        for item in self._read_candidate_evidence_artifact():
            if item.get("kind") != "screenshot":
                continue
            path = str(item.get("path") or item.get("screenshot_path") or "").strip()
            related_finding = self._normalize_lookup_key(item.get("related_finding", ""))
            if not path or not related_finding or not os.path.exists(path):
                continue
            screenshots[related_finding] = path
        return screenshots

    def _finding_title(self, finding: Dict) -> str:
        return str(finding.get("name") or finding.get("title") or "未命名漏洞")

    def _coerce_finding(self, finding: Dict, screenshot_index: dict[str, str] | None = None) -> Dict:
        title = self._finding_title(finding)
        screenshot_index = screenshot_index or {}
        resolved_screenshot = finding.get("screenshot_path", "")
        if not resolved_screenshot:
            resolved_screenshot = screenshot_index.get(self._normalize_lookup_key(title), "")
        evidence = finding.get("evidence")
        if not evidence:
            evidence = finding.get("test_process") or finding.get("evidence_summary") or finding.get("summary", "")
        impact = finding.get("impact")
        if not impact:
            impact = finding.get("risk_analysis") or finding.get("evidence_summary") or evidence or finding.get("summary", "")
        return {
            "name": title,
            "title": title,
            "severity": finding.get("severity", "信息"),
            "description": finding.get("description", finding.get("summary", "无描述")),
            "evidence": evidence,
            "impact": impact,
            "remediation": finding.get("remediation", "暂无修复建议"),
            "screenshot_path": resolved_screenshot,
            "type": finding.get("type", "其他"),
            "url": finding.get("url", finding.get("vuln_url", "")),
            "control_point": finding.get("control_point", ""),
            "evaluation_unit": finding.get("evaluation_unit", ""),
            "risk_analysis": finding.get("risk_analysis", impact),
            "test_process": finding.get("test_process", evidence),
            "vuln_code": finding.get("vuln_code", ""),
            "target": finding.get("target", ""),
        }

    def _count_severities(self, findings: List[Dict]) -> dict[str, int]:
        counts = {"严重": 0, "高危": 0, "中危": 0, "低危": 0, "信息": 0}
        for finding in findings:
            severity = finding.get("severity", "信息")
            if severity in counts:
                counts[severity] += 1
        return counts

    def _sort_findings(self, findings: List[Dict]) -> List[Dict]:
        return sorted(
            findings,
            key=lambda finding: (
                self.SEVERITY_ORDER.get(finding.get("severity", "信息"), 99),
                self._finding_title(finding),
            ),
        )

    def _set_cell_text(self, cell, text: str) -> None:
        cell.text = str(text)

    def _set_merged_row_content(self, table, row_idx: int, text: str) -> None:
        row = table.rows[row_idx]
        self._set_cell_text(row.cells[1], text)

    def _clear_cell(self, cell) -> None:
        cell.text = ""

    def _append_text_to_cell(self, cell, text: str) -> None:
        self._clear_cell(cell)
        lines = [line for line in str(text).splitlines()] or [""]
        for idx, line in enumerate(lines):
            paragraph = cell.paragraphs[0] if idx == 0 else cell.add_paragraph()
            paragraph.add_run(line)

    def _append_image_to_cell(self, cell, image_path: str, width_inches: float = 5.5) -> None:
        from docx.shared import Inches

        paragraph = cell.add_paragraph()
        run = paragraph.add_run()
        run.add_picture(image_path, width=Inches(width_inches))

    def _prune_template_sample_findings(self, doc) -> None:
        for paragraph in list(doc.paragraphs):
            if getattr(paragraph.style, "name", "") == "Heading 4":
                p = paragraph._element
                p.getparent().remove(p)
        for table in list(doc.tables[5:]):
            tbl = table._element
            tbl.getparent().remove(tbl)

    def _populate_template_front_matter(self, doc, target: str, findings: List[Dict]) -> None:
        now = datetime.now()
        run_metadata = self._read_run_metadata()
        created_at = run_metadata.get("created_at", "")
        start_time = created_at.replace("T", " ").split("+")[0] if created_at else now.strftime("%Y-%m-%d %H:%M:%S")
        end_time = now.strftime("%Y-%m-%d %H:%M:%S")
        severity_counts = self._count_severities(findings)

        if doc.tables:
            summary_table = doc.tables[0]
            severity_rows = {"高危问题": "高危", "中危问题": "中危", "低危问题": "低危"}
            findings_by_severity = {"高危": [], "中危": [], "低危": []}
            for finding in findings:
                sev = finding.get("severity", "信息")
                if sev in findings_by_severity:
                    findings_by_severity[sev].append(self._finding_title(finding))
            for row in summary_table.rows[1:]:
                key = row.cells[0].text.strip()
                sev = severity_rows.get(key)
                if not sev:
                    continue
                self._set_cell_text(row.cells[1], f"{severity_counts[sev]}个")
                self._set_cell_text(row.cells[2], "\n".join(findings_by_severity[sev]))

        if len(doc.tables) > 1:
            total_table = doc.tables[1]
            self._set_cell_text(total_table.rows[1].cells[0], f"高危：{severity_counts['高危']}个")
            self._set_cell_text(total_table.rows[1].cells[1], f"中危：{severity_counts['中危']}个")
            self._set_cell_text(total_table.rows[1].cells[2], f"低危：{severity_counts['低危']}个")
            self._set_cell_text(total_table.rows[1].cells[3], f"{len(findings)}个")

        if len(doc.tables) > 2:
            system_table = doc.tables[2]
            self._set_cell_text(system_table.rows[1].cells[0], target)
            self._set_cell_text(system_table.rows[1].cells[1], "授权 Web 应用渗透测试")

        if len(doc.tables) > 3:
            time_table = doc.tables[3]
            self._set_cell_text(time_table.rows[1].cells[1], start_time)
            self._set_cell_text(time_table.rows[1].cells[3], end_time)

        if len(doc.tables) > 4:
            staff_table = doc.tables[4]
            self._set_cell_text(staff_table.rows[1].cells[1], "YuPentestPilot")
            self._set_cell_text(staff_table.rows[1].cells[3], "安全测试运行时")
            self._set_cell_text(staff_table.rows[1].cells[5], "N/A")

    def _append_template_finding(self, doc, table_template, index: int, finding: Dict, heading_style: str) -> None:
        title = self._finding_title(finding)
        heading = doc.add_paragraph(style=heading_style)
        heading.add_run(f" {title}")

        new_tbl = deepcopy(table_template._tbl)
        doc._body._element.insert(-1, new_tbl)
        table = doc.tables[-1]

        control_point = finding.get("control_point") or "待补充"
        evaluation_unit = finding.get("evaluation_unit") or "待补充"
        severity = finding.get("severity", "信息")
        vuln_code = finding.get("vuln_code") or f"VUL-AUTO-{index:02d}"
        evidence = finding.get("test_process") or finding.get("evidence_summary") or "待补充"
        risk = finding.get("risk_analysis") or "待补充"
        description = finding.get("description") or finding.get("summary") or "待补充"
        remediation = finding.get("remediation") or "待补充"
        screenshot_path = finding.get("screenshot_path", "")

        self._set_cell_text(table.rows[1].cells[0], vuln_code)
        self._set_cell_text(table.rows[1].cells[1], title)
        self._set_cell_text(table.rows[1].cells[2], control_point)
        self._set_cell_text(table.rows[1].cells[3], evaluation_unit)
        self._set_cell_text(table.rows[1].cells[4], severity)

        self._set_merged_row_content(table, 2, description)
        self._set_merged_row_content(table, 3, finding.get("vuln_url", finding.get("url", target if (target := finding.get("target")) else "")))

        process_cell = table.rows[4].cells[1]
        process_text = evidence or "已完成漏洞验证，详见截图与相关证据。"
        self._append_text_to_cell(process_cell, process_text)
        if screenshot_path and os.path.exists(screenshot_path):
            try:
                self._append_image_to_cell(process_cell, screenshot_path)
            except Exception as e:
                process_cell.add_paragraph(f"[截图插入失败: {e}]")
        elif screenshot_path:
            process_cell.add_paragraph(f"[截图文件不存在: {screenshot_path}]")

        self._set_merged_row_content(table, 5, risk)
        self._set_merged_row_content(table, 6, remediation)
        doc.add_paragraph()

    @tool()
    async def add_screenshot(
        self,
        name: Annotated[str, "截图名称，用于生成文件名"],
        full_page: Annotated[bool, "是否截取整页，默认是"] = True,
    ) -> str:
        """
        Capture a screenshot from the current browser page and save it into the workspace screenshots directory.
        """
        from toolset.browser import browser as browser_tool

        os.makedirs(self.screenshots_dir, exist_ok=True)
        context = await browser_tool.get_context()
        page = context.pages[0] if context.pages else await context.new_page()
        filename = f"{self._safe_filename(name)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        screenshot_path = os.path.join(self.screenshots_dir, filename)
        await page.screenshot(path=screenshot_path, full_page=full_page)
        return screenshot_path

    @tool()
    def generate_word_report(
        self,
        target: Annotated[str, "测试目标 URL"],
        findings: Annotated[List[Dict], "漏洞发现列表，每个漏洞包含 name, severity, description, evidence, remediation, screenshot_path"],
        report_title: Annotated[str, "报告标题"] = "Web应用渗透测试报告",
    ) -> str:
        """
        生成包含漏洞详情和截图的 Word 报告 (.docx)
        """
        try:
            from docx import Document
        except ImportError:
            return "[ERROR] python-docx 未安装，请运行: pip install python-docx"
        if not findings:
            findings = self._read_verified_findings_artifact()
        screenshot_index = self._candidate_screenshot_index()
        findings = self._sort_findings([self._coerce_finding(finding, screenshot_index) for finding in findings])
        if os.path.exists(self.template_path):
            doc = Document(self.template_path)
            table_template = doc.tables[5]
            heading_style = "Heading 4"
            self._populate_template_front_matter(doc, target, findings)
            self._prune_template_sample_findings(doc)
            for idx, finding in enumerate(findings, 1):
                enriched = {"target": target, **finding}
                self._append_template_finding(doc, table_template, idx, enriched, heading_style)
        else:
            return "[ERROR] Pentest report template not found in workspace metadata."

        filename = f"Pentest_Report_{self._safe_filename(target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        report_path = os.path.join(self.workspace, filename)
        doc.save(report_path)
        self._write_final_report_reference(report_path, "docx", target, len(findings))
        return report_path

    @tool()
    def generate_report(
        self,
        target: Annotated[str, "测试目标 URL"],
        findings: Annotated[List[Dict], "漏洞发现列表；若传空列表则自动从 verified_findings artifact 读取"],
        report_title: Annotated[str, "报告标题"] = "Web应用渗透测试报告",
        format: Annotated[str, "报告格式，仅支持 docx"] = "docx",
    ) -> str:
        """
        生成报告。Phase 1 仅保留 Word 主路径。
        """
        if format.lower() != "docx":
            return "[ERROR] Only docx reports are supported in Phase 1."
        return self.generate_word_report(target, findings, report_title)

    @tool()
    def generate_word_report_from_artifacts(
        self,
        target: Annotated[str, "测试目标 URL"],
        report_title: Annotated[str, "报告标题"] = "Web应用渗透测试报告",
    ) -> str:
        """
        从 verified_findings artifact 自动生成基于模板的 Word 报告。
        """
        return self.generate_word_report(target=target, findings=[], report_title=report_title)

    @tool()
    def add_finding_with_screenshot(
        self,
        findings_list: Annotated[List, "漏洞列表（会被修改添加新漏洞）"],
        name: Annotated[str, "漏洞名称"],
        severity: Annotated[str, "严重程度: 严重/高危/中危/低危/信息"],
        description: Annotated[str, "漏洞描述"],
        evidence: Annotated[str, "证据/Payload"],
        remediation: Annotated[str, "修复建议"],
        screenshot_path: Annotated[Optional[str], "截图文件路径"] = None,
    ) -> List:
        """
        添加一个带截图的漏洞发现到列表
        """
        finding = {
            "name": name,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "impact": evidence,
            "remediation": remediation,
            "screenshot_path": screenshot_path,
            "type": self._guess_vuln_type(name),
        }
        findings_list.append(finding)
        return findings_list

    def _guess_vuln_type(self, name: str) -> str:
        """根据漏洞名称猜测类型"""
        name_lower = name.lower()
        type_keywords = {
            "sql": "SQL注入",
            "注入": "注入漏洞",
            "xss": "跨站脚本",
            "跨站": "跨站脚本",
            "上传": "文件上传",
            "下载": "任意文件下载",
            "遍历": "目录遍历",
            "包含": "文件包含",
            "rce": "远程代码执行",
            "命令": "命令执行",
            "越权": "权限绕过",
            "泄露": "信息泄露",
            "枚举": "信息泄露",
            "头部": "安全配置",
            "配置": "安全配置",
        }
        for keyword, vuln_type in type_keywords.items():
            if keyword in name_lower:
                return vuln_type
        return "其他"

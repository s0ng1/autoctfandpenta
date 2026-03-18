"""
报告生成模块 - 支持生成包含截图的 HTML/Word 报告
"""

import os
import base64
from datetime import datetime
from typing import Annotated, List, Dict, Optional
from pathlib import Path

from core import tool, toolset, namespace

namespace()


@toolset()
class ReportGenerator:
    """生成包含漏洞详情和截图的渗透测试报告"""
    
    def __init__(self, workspace: str = "/home/ubuntu/Workspace"):
        self.workspace = workspace
        self.screenshots_dir = os.path.join(workspace, "screenshots")
        
    def _image_to_base64(self, image_path: str) -> str:
        """将图片转换为 base64 编码"""
        try:
            with open(image_path, "rb") as f:
                return base64.b64encode(f.read()).decode('utf-8')
        except Exception as e:
            return f"[图片加载失败: {str(e)}]"
    
    def _get_image_mime_type(self, image_path: str) -> str:
        """获取图片的 MIME 类型"""
        ext = Path(image_path).suffix.lower()
        mime_types = {
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp'
        }
        return mime_types.get(ext, 'image/png')
    
    @tool()
    def generate_html_report(
        self,
        target: Annotated[str, "测试目标 URL"],
        findings: Annotated[List[Dict], "漏洞发现列表，每个漏洞包含 name, severity, description, evidence, remediation, screenshot_path"],
        report_title: Annotated[str, "报告标题"] = "Web应用渗透测试报告"
    ) -> str:
        """
        生成包含漏洞详情和截图的 HTML 报告
        
        Example:
            import toolset
            
            findings = [
                {
                    'name': 'SQL注入漏洞',
                    'severity': '高危',
                    'description': '登录接口存在SQL注入',
                    'evidence': 'Payload: admin\' OR \'1\'=\'1',
                    'remediation': '使用参数化查询',
                    'screenshot_path': '/home/ubuntu/Workspace/screenshots/sqli.png'
                }
            ]
            
            report_path = toolset.report.generate_html_report(
                target="http://target.com",
                findings=findings,
                report_title="渗透测试报告"
            )
        """
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 统计漏洞数量
        severity_counts = {"严重": 0, "高危": 0, "中危": 0, "低危": 0, "信息": 0}
        for finding in findings:
            severity = finding.get('severity', '信息')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # 生成 HTML
        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <style>
        body {{
            font-family: "Microsoft YaHei", "SimSun", sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 40px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d32f2f;
            border-bottom: 3px solid #d32f2f;
            padding-bottom: 10px;
            text-align: center;
        }}
        h2 {{
            color: #1976d2;
            border-left: 4px solid #1976d2;
            padding-left: 15px;
            margin-top: 30px;
        }}
        h3 {{
            color: #388e3c;
            margin-top: 25px;
        }}
        .info-box {{
            background-color: #e3f2fd;
            border-left: 4px solid #1976d2;
            padding: 15px;
            margin: 20px 0;
        }}
        .finding {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            background-color: #fafafa;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }}
        .finding-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #333;
        }}
        .severity {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .severity-critical {{ background-color: #d32f2f; color: white; }}
        .severity-high {{ background-color: #f57c00; color: white; }}
        .severity-medium {{ background-color: #fbc02d; color: black; }}
        .severity-low {{ background-color: #388e3c; color: white; }}
        .severity-info {{ background-color: #757575; color: white; }}
        .field {{
            margin: 15px 0;
        }}
        .field-label {{
            font-weight: bold;
            color: #555;
            display: inline-block;
            min-width: 100px;
        }}
        .field-content {{
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            margin-top: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .screenshot {{
            margin: 15px 0;
            text-align: center;
        }}
        .screenshot img {{
            max-width: 100%;
            border: 2px solid #ddd;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .screenshot-caption {{
            color: #666;
            font-size: 0.9em;
            margin-top: 8px;
        }}
        .summary-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .summary-table th, .summary-table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: center;
        }}
        .summary-table th {{
            background-color: #1976d2;
            color: white;
        }}
        .summary-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .disclaimer {{
            background-color: #fff3e0;
            border: 1px solid #ff9800;
            padding: 15px;
            margin-top: 30px;
            border-radius: 4px;
            font-size: 0.9em;
            color: #e65100;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{report_title}</h1>
        
        <div class="info-box">
            <p><strong>测试目标：</strong>{target}</p>
            <p><strong>测试时间：</strong>{timestamp}</p>
            <p><strong>评估方式：</strong>自动化安全测试</p>
        </div>
        
        <h2>执行摘要</h2>
        <p>本次安全评估共发现 <strong>{len(findings)} 个安全发现项</strong>。</p>
        
        <table class="summary-table">
            <tr>
                <th>严重程度</th>
                <th>数量</th>
            </tr>
            <tr><td style="color: #d32f2f; font-weight: bold;">严重</td><td>{severity_counts['严重']}</td></tr>
            <tr><td style="color: #f57c00; font-weight: bold;">高危</td><td>{severity_counts['高危']}</td></tr>
            <tr><td style="color: #fbc02d; font-weight: bold;">中危</td><td>{severity_counts['中危']}</td></tr>
            <tr><td style="color: #388e3c; font-weight: bold;">低危</td><td>{severity_counts['低危']}</td></tr>
            <tr><td style="color: #757575; font-weight: bold;">信息</td><td>{severity_counts['信息']}</td></tr>
        </table>
        
        <h2>详细发现</h2>
"""
        
        # 添加每个漏洞详情
        severity_class_map = {
            "严重": "severity-critical",
            "高危": "severity-high", 
            "中危": "severity-medium",
            "低危": "severity-low",
            "信息": "severity-info"
        }
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', '信息')
            severity_class = severity_class_map.get(severity, 'severity-info')
            screenshot_path = finding.get('screenshot_path', '')
            
            # 处理截图
            screenshot_html = ""
            if screenshot_path and os.path.exists(screenshot_path):
                img_base64 = self._image_to_base64(screenshot_path)
                mime_type = self._get_image_mime_type(screenshot_path)
                screenshot_html = f"""
        <div class="field">
            <span class="field-label">验证截图：</span>
            <div class="screenshot">
                <img src="data:{mime_type};base64,{img_base64}" alt="漏洞验证截图">
                <div class="screenshot-caption">{os.path.basename(screenshot_path)}</div>
            </div>
        </div>"""
            elif screenshot_path:
                screenshot_html = f"""
        <div class="field">
            <span class="field-label">验证截图：</span>
            <div class="field-content">截图路径: {screenshot_path} (文件不存在)</div>
        </div>"""
            
            html_content += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="finding-title">{i}. {finding.get('name', '未命名漏洞')}</span>
                <span class="severity {severity_class}">{severity}</span>
            </div>
            
            <div class="field">
                <span class="field-label">漏洞类型：</span>
                {finding.get('type', '未分类')}
            </div>
            
            <div class="field">
                <span class="field-label">漏洞描述：</span>
                <div class="field-content">{finding.get('description', '无描述')}</div>
            </div>
            
            <div class="field">
                <span class="field-label">影响描述：</span>
                <div class="field-content">{finding.get('impact', finding.get('evidence', '无影响描述'))}</div>
            </div>
            
            {screenshot_html}
            
            <div class="field">
                <span class="field-label">修复建议：</span>
                <div class="field-content">{finding.get('remediation', '暂无修复建议')}</div>
            </div>
        </div>
"""
        
        # 添加结尾
        html_content += """
        <h2>测试结论</h2>
        <p>本次安全评估已完成对所有测试项目的检查。建议根据上述发现项的严重程度，按照修复建议及时进行整改。</p>
        
        <div class="disclaimer">
            <strong>免责声明：</strong>本次安全评估以受控方式进行，旨在识别安全弱点。
            发现应用于改进应用的安全态势。未经许可对系统进行未授权测试是违法行为。
        </div>
        
        <p style="text-align: center; color: #666; margin-top: 30px;">
            <em>报告生成时间：""" + timestamp + """</em>
        </p>
    </div>
</body>
</html>"""
        
        # 保存报告
        filename = f"Pentest_Report_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(self.workspace, filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path

    @tool()
    def generate_word_report(
        self,
        target: Annotated[str, "测试目标 URL"],
        findings: Annotated[List[Dict], "漏洞发现列表，每个漏洞包含 name, severity, description, evidence, remediation, screenshot_path"],
        report_title: Annotated[str, "报告标题"] = "Web应用渗透测试报告"
    ) -> str:
        """
        生成包含漏洞详情和截图的 Word 报告 (.docx)
        
        Example:
            import toolset
            
            findings = [
                {
                    'name': 'SQL注入漏洞',
                    'severity': '高危',
                    'description': '登录接口存在SQL注入',
                    'evidence': 'Payload: admin\' OR \'1\'=\'1',
                    'remediation': '使用参数化查询',
                    'screenshot_path': '/home/ubuntu/Workspace/screenshots/sqli.png'
                }
            ]
            
            report_path = toolset.report.generate_word_report(
                target="http://target.com",
                findings=findings,
                report_title="渗透测试报告"
            )
        """
        try:
            from docx import Document
            from docx.shared import Inches, Pt, RGBColor
            from docx.enum.text import WD_ALIGN_PARAGRAPH
            from docx.oxml.ns import qn
        except ImportError:
            # 如果 python-docx 未安装，返回提示
            return "[ERROR] python-docx 未安装，请运行: pip install python-docx"
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 统计漏洞数量
        severity_counts = {"严重": 0, "高危": 0, "中危": 0, "低危": 0, "信息": 0}
        for finding in findings:
            severity = finding.get('severity', '信息')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # 创建 Word 文档
        doc = Document()
        
        # 设置默认字体
        style = doc.styles['Normal']
        style.font.name = 'Microsoft YaHei'
        style._element.rPr.rFonts.set(qn('w:eastAsia'), 'Microsoft YaHei')
        
        # 标题
        title = doc.add_heading(report_title, 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # 基本信息
        doc.add_heading('基本信息', level=1)
        info_table = doc.add_table(rows=3, cols=2)
        info_table.style = 'Light Grid Accent 1'
        info_data = [
            ('测试目标', target),
            ('测试时间', timestamp),
            ('评估方式', '自动化安全测试')
        ]
        for i, (key, value) in enumerate(info_data):
            info_table.rows[i].cells[0].text = key
            info_table.rows[i].cells[1].text = value
        
        doc.add_paragraph()
        
        # 执行摘要
        doc.add_heading('执行摘要', level=1)
        doc.add_paragraph(f'本次安全评估共发现 {len(findings)} 个安全发现项。')
        
        # 风险汇总表
        doc.add_heading('风险汇总', level=2)
        summary_table = doc.add_table(rows=6, cols=2)
        summary_table.style = 'Light Grid Accent 1'
        summary_data = [
            ('严重程度', '数量'),
            ('严重', str(severity_counts['严重'])),
            ('高危', str(severity_counts['高危'])),
            ('中危', str(severity_counts['中危'])),
            ('低危', str(severity_counts['低危'])),
            ('信息', str(severity_counts['信息']))
        ]
        for i, (key, value) in enumerate(summary_data):
            summary_table.rows[i].cells[0].text = key
            summary_table.rows[i].cells[1].text = value
            # 第一行加粗
            if i == 0:
                for cell in summary_table.rows[i].cells:
                    for paragraph in cell.paragraphs:
                        for run in paragraph.runs:
                            run.font.bold = True
        
        doc.add_paragraph()
        
        # 详细发现
        doc.add_heading('详细发现', level=1)
        
        for i, finding in enumerate(findings, 1):
            # 漏洞标题（带严重程度）
            severity = finding.get('severity', '信息')
            finding_heading = doc.add_heading(f'{i}. {finding.get("name", "未命名漏洞")} [{severity}]', level=2)
            
            # 漏洞信息表格
            finding_table = doc.add_table(rows=5, cols=2)
            finding_table.style = 'Light List Accent 1'
            
            # 填充表格数据
            rows_data = [
                ('漏洞类型', finding.get('type', '未分类')),
                ('严重程度', severity),
                ('漏洞描述', finding.get('description', '无描述')),
                ('影响描述', finding.get('impact', finding.get('evidence', '无影响描述'))),
                ('修复建议', finding.get('remediation', '暂无修复建议'))
            ]
            
            for row_idx, (label, content) in enumerate(rows_data):
                finding_table.rows[row_idx].cells[0].text = label
                finding_table.rows[row_idx].cells[1].text = content
                # 设置标签列加粗
                finding_table.rows[row_idx].cells[0].paragraphs[0].runs[0].font.bold = True
            
            # 添加截图（如果存在）
            screenshot_path = finding.get('screenshot_path', '')
            if screenshot_path and os.path.exists(screenshot_path):
                doc.add_paragraph()
                doc.add_heading('验证截图', level=3)
                try:
                    # 添加图片，限制宽度为 6 英寸
                    doc.add_picture(screenshot_path, width=Inches(6.0))
                    last_paragraph = doc.paragraphs[-1]
                    last_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                except Exception as e:
                    doc.add_paragraph(f'[截图添加失败: {str(e)}]')
            
            doc.add_paragraph()  # 漏洞之间空行
        
        # 测试结论
        doc.add_heading('测试结论', level=1)
        doc.add_paragraph('本次安全评估已完成对所有测试项目的检查。建议根据上述发现项的严重程度，按照修复建议及时进行整改。')
        
        # 免责声明
        doc.add_heading('免责声明', level=1)
        disclaimer = doc.add_paragraph(
            '本次安全评估以受控方式进行，旨在识别安全弱点。'
            '发现应用于改进应用的安全态势。未经许可对系统进行未授权测试是违法行为。'
        )
        disclaimer.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        
        # 页脚
        doc.add_paragraph()
        footer = doc.add_paragraph(f'报告生成时间：{timestamp}')
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        footer.runs[0].font.color.rgb = RGBColor(128, 128, 128)
        
        # 保存文档
        filename = f"Pentest_Report_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
        report_path = os.path.join(self.workspace, filename)
        doc.save(report_path)
        
        return report_path

    @tool()
    def generate_report(
        self,
        target: Annotated[str, "测试目标 URL"],
        findings: Annotated[List[Dict], "漏洞发现列表"],
        report_title: Annotated[str, "报告标题"] = "Web应用渗透测试报告",
        format: Annotated[str, "报告格式: html 或 docx"] = "html"
    ) -> str:
        """
        生成报告（自动选择格式）
        
        Example:
            import toolset
            
            # 生成 HTML 报告
            report_path = toolset.report.generate_report(
                target="http://target.com",
                findings=findings,
                format="html"
            )
            
            # 生成 Word 报告
            report_path = toolset.report.generate_report(
                target="http://target.com",
                findings=findings,
                format="docx"
            )
        """
        if format.lower() == "docx":
            return self.generate_word_report(target, findings, report_title)
        else:
            return self.generate_html_report(target, findings, report_title)

    @tool()
    def add_finding_with_screenshot(
        self,
        findings_list: Annotated[List, "漏洞列表（会被修改添加新漏洞）"],
        name: Annotated[str, "漏洞名称"],
        severity: Annotated[str, "严重程度: 严重/高危/中危/低危/信息"],
        description: Annotated[str, "漏洞描述"],
        evidence: Annotated[str, "证据/Payload"],
        remediation: Annotated[str, "修复建议"],
        screenshot_path: Annotated[Optional[str], "截图文件路径"] = None
    ) -> List:
        """
        添加一个带截图的漏洞发现到列表
        
        Example:
            import toolset
            
            findings = []
            toolset.report.add_finding_with_screenshot(
                findings_list=findings,
                name="SQL注入漏洞",
                severity="高危",
                description="登录接口存在SQL注入",
                evidence="Payload: admin' OR '1'='1",
                remediation="使用参数化查询",
                screenshot_path="/home/ubuntu/Workspace/screenshots/sqli.png"
            )
        """
        finding = {
            'name': name,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'impact': evidence,  # 兼容字段
            'remediation': remediation,
            'screenshot_path': screenshot_path,
            'type': self._guess_vuln_type(name)
        }
        findings_list.append(finding)
        return findings_list
    
    def _guess_vuln_type(self, name: str) -> str:
        """根据漏洞名称猜测类型"""
        name_lower = name.lower()
        type_keywords = {
            'SQL': 'SQL注入',
            '注入': '注入漏洞',
            'XSS': '跨站脚本',
            '跨站': '跨站脚本',
            '上传': '文件上传',
            '下载': '任意文件下载',
            '遍历': '目录遍历',
            '包含': '文件包含',
            'RCE': '远程代码执行',
            '命令': '命令执行',
            '越权': '权限绕过',
            '遍历': '目录遍历',
            '泄露': '信息泄露',
            '枚举': '信息泄露',
            '头部': '安全配置',
            '配置': '安全配置'
        }
        for keyword, vuln_type in type_keywords.items():
            if keyword in name_lower:
                return vuln_type
        return '其他'

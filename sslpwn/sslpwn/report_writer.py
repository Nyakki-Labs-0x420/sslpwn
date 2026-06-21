"""
Generate multi‑format reports for scan / exploit results.
"""
import os
from typing import List, Dict, Any
from datetime import datetime


class ReportWriter:
    def __init__(self, hostname: str, output_dir: str = "reports") -> None:
        self.hostname = hostname
        self.report_dir = os.path.join(output_dir, hostname)
        os.makedirs(self.report_dir, exist_ok=True)

    def write_reports(self, findings: List[Dict[str, Any]]) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md = self._build_markdown(findings, timestamp)
        txt = self._build_text(findings, timestamp)
        html = self._build_html(findings, timestamp)

        base = os.path.join(self.report_dir, "report")
        with open(base + ".md", "w", encoding="utf-8") as f:
            f.write(md)
        with open(base + ".txt", "w", encoding="utf-8") as f:
            f.write(txt)
        with open(base + ".html", "w", encoding="utf-8") as f:
            f.write(html)

    def _build_markdown(self, findings: List[Dict[str, Any]], timestamp: str) -> str:
        lines = [f"# sslpwn Scan Report for {self.hostname}", f"**Date:** {timestamp}\n", "## Findings\n"]
        for f in findings:
            lines.append(f"### {f['name']}")
            lines.append(f"- **Vulnerable:** {'Yes' if f['vulnerable'] else 'No'}")
            if f.get('exploit_success') is not None:
                lines.append(f"- **Exploit Success:** {'Yes' if f['exploit_success'] else 'No'}")
            if f.get('details'):
                lines.append(f"- **Details:** {f['details']}")
            lines.append("")
        return "\n".join(lines)

    def _build_text(self, findings: List[Dict[str, Any]], timestamp: str) -> str:
        lines = [f"sslpwn Scan Report for {self.hostname}", f"Date: {timestamp}\n", "Findings:"]
        for f in findings:
            lines.append(f"  {f['name']}")
            lines.append(f"    Vulnerable: {'Yes' if f['vulnerable'] else 'No'}")
            if f.get('exploit_success') is not None:
                lines.append(f"    Exploit Success: {'Yes' if f['exploit_success'] else 'No'}")
            if f.get('details'):
                lines.append(f"    Details: {f['details']}")
        return "\n".join(lines)

    def _build_html(self, findings: List[Dict[str, Any]], timestamp: str) -> str:
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>sslpwn Report - {self.hostname}</title>
<style>
body {{ font-family: sans-serif; margin: 2em; }}
h1 {{ color: #333; }}
h3 {{ margin-bottom: 0.3em; }}
</style>
</head>
<body>
<h1>sslpwn Scan Report for {self.hostname}</h1>
<p><strong>Date:</strong> {timestamp}</p>
<h2>Findings</h2>
<ul>
"""
        for f in findings:
            html += f"<li><strong>{f['name']}</strong> – Vulnerable: {'Yes' if f['vulnerable'] else 'No'}"
            if f.get('exploit_success') is not None:
                html += f", Exploit Success: {'Yes' if f['exploit_success'] else 'No'}"
            if f.get('details'):
                html += f"<br><small>Details: {f['details']}</small>"
            html += "</li>\n"
        html += "</ul>\n</body>\n</html>"
        return html
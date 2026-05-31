import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


class ReportGenerator:
    def __init__(self, vulnerability_log: str) -> None:
        self.log_path = Path(vulnerability_log)

    def generate_json_report(self, output_path: str) -> None:
        vulnerabilities = self._load_vulnerabilities()
        report = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities),
                'tool': 'Vulcan',
                'version': '0.1.0',
            },
            'summary': self._generate_summary(vulnerabilities),
            'vulnerabilities': vulnerabilities,
        }
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, 'w') as f:
            json.dump(report, f, indent=2)

    def generate_markdown_report(self, output_path: str) -> None:
        vulnerabilities = self._load_vulnerabilities()
        summary = self._generate_summary(vulnerabilities)

        lines: list[str] = []
        lines.append("# Vulcan Security Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Vulnerabilities:** {summary['total']}")
        lines.append(f"- **Critical:** {summary['by_risk'].get('Critical', 0)}")
        lines.append(f"- **High:** {summary['by_risk'].get('High', 0)}")
        lines.append(f"- **Medium:** {summary['by_risk'].get('Medium', 0)}")
        lines.append(f"- **Low:** {summary['by_risk'].get('Low', 0)}")
        lines.append("")
        lines.append("## Vulnerability Breakdown")
        lines.append("")

        for i, vuln in enumerate(vulnerabilities, 1):
            lines.append(f"### {i}. {vuln.get('vulnerability_type', 'Unknown')}")
            lines.append("")
            lines.append(f"- **Risk Level:** {vuln.get('risk_level', 'Unknown')}")
            lines.append(f"- **Confidence:** {vuln.get('confidence_score', 0)}%")
            lines.append(f"- **URL:** `{vuln.get('url', 'N/A')}`")
            lines.append(f"- **Method:** `{vuln.get('method', 'N/A')}`")
            lines.append("")
            lines.append("**Reasoning:**")
            lines.append("")
            lines.append(str(vuln.get('reasoning', 'N/A')))
            lines.append("")
            lines.append("**Proof of Concept:**")
            lines.append("")
            lines.append("```")
            lines.append(str(vuln.get('proof_of_concept', 'N/A')))
            lines.append("```")
            lines.append("")
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(str(vuln.get('remediation_suggestion', 'N/A')))
            lines.append("")
            lines.append("---")
            lines.append("")

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(lines))

    async def generate_llm_markdown_report(self, output_path: str, config: Any) -> None:
        import openai

        vulnerabilities = self._load_vulnerabilities()
        summary = self._generate_summary(vulnerabilities)
        vulnerabilities_json = json.dumps(vulnerabilities, indent=2)

        prompt = (
            "You are a professional security consultant writing an executive security assessment report.\n\n"
            f"SCAN SUMMARY:\n- Total Vulnerabilities: {summary['total']}\n"
            f"- By Risk Level: {json.dumps(summary['by_risk'])}\n"
            f"- By Type: {json.dumps(summary['by_type'])}\n\n"
            f"VULNERABILITY DETAILS:\n{vulnerabilities_json}\n\n"
            "Generate a comprehensive, professional markdown security report with:\n"
            "1. Executive Summary (non-technical, 2-3 paragraphs)\n"
            "2. Scan Metadata (date, scope, methodology)\n"
            "3. Risk Assessment (overall posture, severity distribution)\n"
            "4. Detailed Findings: title, risk, description, impact, affected endpoints, "
            "PoC, remediation, business impact\n"
            "5. Remediation Roadmap (prioritized action plan)\n"
            "6. Conclusion (key takeaways, next steps)\n\n"
            "Use professional security terminology and clear formatting."
        )

        if config.provider == 'gemini':
            client = openai.AsyncOpenAI(
                base_url=config.gemini_base_url,
                api_key=os.getenv('GOOGLE_API_KEY') or os.getenv('GEMINI_API_KEY'),
            )
            llm_model = config.gemini_model
        else:
            client = openai.AsyncOpenAI(api_key=os.getenv('OPENAI_API_KEY'))
            llm_model = config.openai_model

        response = await client.chat.completions.create(
            model=llm_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )

        content = response.choices[0].message.content or ""

        if "```markdown" in content:
            content = content.split("```markdown", 1)[1].split("```", 1)[0].strip()
        elif "```" in content:
            content = content.split("```", 1)[1].split("```", 1)[0].strip()

        header = (
            "<!--\n"
            "Vulcan Security Report\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            "Report Type: LLM-Enhanced Analysis\n"
            f"Provider: {config.provider}\n"
            f"Model: {llm_model}\n"
            "-->\n\n"
        )

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(header + content)

    def _load_vulnerabilities(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        vulnerabilities: list[dict[str, Any]] = []
        with open(self.log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    vulnerabilities.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return vulnerabilities

    def _generate_summary(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
        summary: dict[str, Any] = {'total': len(vulnerabilities), 'by_type': {}, 'by_risk': {}}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            risk = vuln.get('risk_level', 'Unknown')
            summary['by_risk'][risk] = summary['by_risk'].get(risk, 0) + 1
        return summary

"""Prompt builder for constructing effective LLM prompts."""
from typing import Dict, List, Any, Optional
import json
from datetime import datetime

from ..core.logger import LoggerMixin

class PromptBuilder(LoggerMixin):
    """Builds specialized prompts for security analysis tasks."""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Load prompt templates."""
        return {
            'vulnerability_analysis': """
You are a security expert analyzing vulnerability scan results.

Target: {target}
Scan Date: {date}

Findings:
{findings}

Please analyze these findings and provide:
1. A brief executive summary of the security posture
2. The most critical vulnerabilities (top 3)
3. Specific remediation steps for each critical finding
4. General recommendations for improving security

Format your response with clear sections and bullet points.
""",
            'planning': """
You are a security assessment planner creating an efficient scanning strategy.

Target: {target}
Assessment Type: {scan_type}
Previous Findings: {previous_findings}

Available Tools:
{tools_list}

Context from similar targets:
{similar_targets}

Please create an optimized scanning plan that:
1. Prioritizes the most critical areas first
2. Avoids redundant scans
3. Considers tool dependencies
4. Estimates time requirements

Return the plan as a structured list of phases with specific tools for each.
""",
            'remediation': """
You are a security consultant providing remediation guidance.

Vulnerability: {vulnerability_name}
Severity: {severity}
Description: {description}
Affected System: {system}
Evidence: {evidence}

Please provide:
1. Immediate steps to mitigate the risk
2. Long-term fix recommendations
3. Verification steps to ensure the fix works
4. Potential impact of the remediation

Make recommendations practical and actionable.
""",
            'executive_summary': """
You are preparing an executive summary for a security assessment.

Target: {target}
Assessment Period: {period}
Key Statistics:
- Total Findings: {total_findings}
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

Top Findings:
{top_findings}

Write a concise executive summary that:
1. Provides an overall risk rating
2. Highlights the most important findings
3. Gives high-level recommendations
4. Uses non-technical language

Keep it to 3-4 paragraphs maximum.
""",
            'tool_selection': """
You are selecting security tools for a penetration test.

Target Context:
- Domain/IP: {target}
- Open Ports: {open_ports}
- Detected Services: {services}
- Web Technologies: {web_tech}
- Known Vulnerabilities: {known_vulns}

Available Tools and Their Purposes:
{tools_with_purposes}

Already Run: {executed_tools}

Select the most appropriate next tools to run. Consider:
1. Coverage of remaining attack surface
2. Tool efficiency and speed
3. Complementary capabilities
4. Resource constraints

Return the top 3-5 tools with specific parameters for each.
"""
        }
    
    def build_analysis_prompt(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build a prompt for vulnerability analysis."""
        context = context or {}
        
        # Format findings
        findings_text = ""
        for i, finding in enumerate(findings, 1):
            findings_text += f"\n{i}. {finding.get('name', 'Unknown')}\n"
            findings_text += f"   Severity: {finding.get('severity', 'Unknown')}\n"
            findings_text += f"   Description: {finding.get('description', 'N/A')}\n"
            findings_text += f"   Evidence: {finding.get('evidence', 'N/A')}\n"
        
        return self.templates['vulnerability_analysis'].format(
            target=target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            findings=findings_text
        )
    
    def build_planning_prompt(
        self,
        target: str,
        scan_type: str,
        phases: List[Dict[str, Any]],
        similar_targets: List[str]
    ) -> str:
        """Build a prompt for scan planning."""
        
        # Format tools list
        tools_list = ""
        all_tools = set()
        for phase in phases:
            for task in phase.get('tasks', []):
                if task.get('tool') not in all_tools:
                    all_tools.add(task.get('tool'))
                    tools_list += f"- {task.get('tool')}: {task.get('description', 'No description')}\n"
        
        # Format similar targets
        similar_text = "\n".join([f"- {t}" for t in similar_targets]) if similar_targets else "None"
        
        # Format previous findings
        previous_findings = "No previous findings available"
        
        return self.templates['planning'].format(
            target=target,
            scan_type=scan_type,
            previous_findings=previous_findings,
            tools_list=tools_list,
            similar_targets=similar_text
        )
    
    def build_remediation_prompt(
        self,
        vulnerability: Dict[str, Any]
    ) -> str:
        """Build a prompt for remediation guidance."""
        return self.templates['remediation'].format(
            vulnerability_name=vulnerability.get('name', 'Unknown'),
            severity=vulnerability.get('severity', 'Unknown'),
            description=vulnerability.get('description', 'N/A'),
            system=vulnerability.get('affected_system', 'Unknown'),
            evidence=vulnerability.get('evidence', 'N/A')
        )
    
    def build_executive_summary_prompt(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        scan_duration: str
    ) -> str:
        """Build a prompt for executive summary."""
        
        # Count findings by severity
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'Info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Get top findings
        top_findings = sorted(
            findings,
            key=lambda x: {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}.get(x.get('severity', 'Info'), 0),
            reverse=True
        )[:3]
        
        top_findings_text = ""
        for finding in top_findings:
            top_findings_text += f"- {finding.get('name')} ({finding.get('severity')})\n"
        
        return self.templates['executive_summary'].format(
            target=target,
            period=scan_duration,
            total_findings=len(findings),
            critical_count=severity_counts['Critical'],
            high_count=severity_counts['High'],
            medium_count=severity_counts['Medium'],
            low_count=severity_counts['Low'],
            top_findings=top_findings_text
        )
    
    def build_tool_selection_prompt(
        self,
        target: str,
        context: Dict[str, Any],
        executed_tools: List[str]
    ) -> str:
        """Build a prompt for tool selection."""
        
        # Format tools with purposes
        tools_with_purposes = {
            'nmap': 'Network mapping and service detection',
            'amass': 'Subdomain enumeration',
            'sublist3r': 'Subdomain discovery',
            'theharvester': 'OSINT and email harvesting',
            'gobuster': 'Directory and file bruteforcing',
            'dirsearch': 'Web path discovery',
            'ffuf': 'Web fuzzing',
            'whatweb': 'Web technology identification',
            'nikto': 'Web server vulnerability scanning',
            'sqlmap': 'SQL injection testing',
            'wpscan': 'WordPress vulnerability scanning',
            'nuclei': 'Template-based vulnerability scanning',
            'searchsploit': 'Exploit lookup'
        }
        
        tools_text = ""
        for tool, purpose in tools_with_purposes.items():
            tools_text += f"- {tool}: {purpose}\n"
        
        return self.templates['tool_selection'].format(
            target=target,
            open_ports=context.get('open_ports', 'Unknown'),
            services=context.get('services', 'Unknown'),
            web_tech=context.get('web_technologies', 'Unknown'),
            known_vulns=context.get('known_vulnerabilities', 'None'),
            tools_with_purposes=tools_text,
            executed_tools=", ".join(executed_tools) if executed_tools else "None"
        )
    
    def build_custom_prompt(
        self,
        template_name: str,
        **kwargs
    ) -> str:
        """Build a prompt from a custom template."""
        if template_name not in self.templates:
            self.log_error(f"Template not found: {template_name}")
            return ""
        
        return self.templates[template_name].format(**kwargs)
    
    def add_context(self, prompt: str, context: Dict[str, Any]) -> str:
        """Add context information to an existing prompt."""
        context_str = "\n\nAdditional Context:\n"
        for key, value in context.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2)
            context_str += f"{key}: {value}\n"
        
        return prompt + context_str
    
    def create_few_shot_prompt(
        self,
        examples: List[Dict[str, str]],
        query: str
    ) -> str:
        """Create a few-shot learning prompt with examples."""
        prompt = "Here are some examples:\n\n"
        
        for i, example in enumerate(examples, 1):
            prompt += f"Example {i}:\n"
            prompt += f"Input: {example.get('input', '')}\n"
            prompt += f"Output: {example.get('output', '')}\n\n"
        
        prompt += f"Now, please handle this query:\nInput: {query}\nOutput:"
        
        return prompt
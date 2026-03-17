"""Analysis engine for processing scan results with LLM."""
from typing import Dict, List, Any, Optional
import json
from datetime import datetime
import re

from ..core.logger import LoggerMixin
from .llm_interface import LLMInterface
from .prompt_builder import PromptBuilder

class AnalysisEngine(LoggerMixin):
    """Engine for analyzing security scan results using LLM."""
    
    def __init__(self, llm: LLMInterface):
        self.llm = llm
        self.prompt_builder = PromptBuilder()
        self.severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
    
    async def analyze_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze complete scan results.
        
        Args:
            scan_results: Dictionary containing all scan results
        
        Returns:
            Analysis results with findings and recommendations
        """
        self.log_info("Starting comprehensive scan analysis")
        
        # Extract findings from scan results
        findings = self._extract_findings(scan_results)
        
        # Categorize findings
        categorized = self._categorize_findings(findings)
        
        # Get LLM analysis for each category
        analysis = {
            'summary': await self._generate_summary(scan_results, findings),
            'vulnerabilities': await self._analyze_vulnerabilities(categorized.get('vulnerabilities', [])),
            'exposures': await self._analyze_exposures(categorized.get('exposures', [])),
            'misconfigurations': await self._analyze_misconfigurations(categorized.get('misconfigurations', [])),
            'recommendations': await self._generate_recommendations(findings),
            'risk_score': self._calculate_risk_score(findings),
            'timestamp': datetime.now().isoformat()
        }
        
        return analysis
    
    def _extract_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract structured findings from scan results."""
        findings = []
        
        # Extract from execution phases
        if 'execution' in scan_results:
            for phase in scan_results['execution'].get('phases', []):
                for task in phase.get('tasks', []):
                    if task['status'] == 'completed' and task.get('result'):
                        tool_findings = self._parse_tool_output(
                            task['name'],
                            task['result']
                        )
                        findings.extend(tool_findings)
        
        return findings
    
    def _parse_tool_output(self, tool_name: str, output: Any) -> List[Dict[str, Any]]:
        """Parse tool-specific output into structured findings."""
        findings = []
        
        if tool_name == 'nmap':
            findings = self._parse_nmap_output(output)
        elif tool_name == 'nikto':
            findings = self._parse_nikto_output(output)
        elif tool_name == 'nuclei':
            findings = self._parse_nuclei_output(output)
        elif tool_name == 'wpscan':
            findings = self._parse_wpscan_output(output)
        elif tool_name == 'sqlmap':
            findings = self._parse_sqlmap_output(output)
        
        return findings
    
    def _parse_nmap_output(self, output: Any) -> List[Dict[str, Any]]:
        """Parse nmap output into findings."""
        findings = []
        
        if isinstance(output, str):
            # Parse open ports
            port_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)'
            for line in output.split('\n'):
                match = re.search(port_pattern, line)
                if match:
                    port, service, version = match.groups()
                    findings.append({
                        'type': 'open_port',
                        'name': f'Open Port: {port}/tcp',
                        'severity': 'Info',
                        'description': f'Port {port} is open running {service}',
                        'evidence': line.strip(),
                        'affected_system': f'port:{port}',
                        'service': service,
                        'version': version.strip()
                    })
        
        return findings
    
    def _parse_nikto_output(self, output: Any) -> List[Dict[str, Any]]:
        """Parse nikto output into findings."""
        findings = []
        
        if isinstance(output, str):
            # Parse vulnerabilities
            vuln_pattern = r'\+ (.+?): (.+)'
            for line in output.split('\n'):
                if line.startswith('+ '):
                    match = re.search(vuln_pattern, line)
                    if match:
                        vuln_type, details = match.groups()
                        findings.append({
                            'type': 'web_vulnerability',
                            'name': vuln_type,
                            'severity': self._estimate_severity(vuln_type),
                            'description': details,
                            'evidence': line.strip(),
                            'affected_system': 'web_server'
                        })
        
        return findings
    
    def _parse_nuclei_output(self, output: Any) -> List[Dict[str, Any]]:
        """Parse nuclei output into findings."""
        findings = []
        
        if isinstance(output, str):
            # Try to parse JSON lines
            for line in output.split('\n'):
                if line.strip() and line.startswith('{'):
                    try:
                        data = json.loads(line)
                        findings.append({
                            'type': 'vulnerability',
                            'name': data.get('info', {}).get('name', 'Unknown'),
                            'severity': data.get('info', {}).get('severity', 'info').capitalize(),
                            'description': data.get('info', {}).get('description', ''),
                            'evidence': data.get('matched', ''),
                            'affected_system': data.get('host', ''),
                            'cve': data.get('info', {}).get('classification', {}).get('cve_id', [])
                        })
                    except json.JSONDecodeError:
                        pass
        
        return findings
    
    def _parse_wpscan_output(self, output: Any) -> List[Dict[str, Any]]:
        """Parse wpscan output into findings."""
        findings = []
        
        if isinstance(output, str):
            # Parse vulnerabilities
            if '[!]' in output:
                sections = output.split('[!]')
                for section in sections[1:]:
                    lines = section.strip().split('\n')
                    if lines:
                        vuln_name = lines[0].strip()
                        findings.append({
                            'type': 'wordpress_vulnerability',
                            'name': vuln_name,
                            'severity': 'High',  # Default for WordPress vulns
                            'description': ' '.join(lines[1:]) if len(lines) > 1 else '',
                            'evidence': section.strip(),
                            'affected_system': 'wordpress'
                        })
        
        return findings
    
    def _parse_sqlmap_output(self, output: Any) -> List[Dict[str, Any]]:
        """Parse sqlmap output into findings."""
        findings = []
        
        if isinstance(output, str):
            # Parse successful injections
            if 'vulnerable' in output.lower():
                findings.append({
                    'type': 'sql_injection',
                    'name': 'SQL Injection Vulnerability',
                    'severity': 'Critical',
                    'description': 'SQL injection vulnerability detected',
                    'evidence': output[:500] + '...' if len(output) > 500 else output,
                    'affected_system': 'database'
                })
        
        return findings
    
    def _estimate_severity(self, text: str) -> str:
        """Estimate severity based on text content."""
        text_lower = text.lower()
        
        critical_indicators = ['critical', 'remote code execution', 'rce', 'sql injection']
        high_indicators = ['high', 'xss', 'cross-site', 'path traversal']
        medium_indicators = ['medium', 'information disclosure', 'dos']
        
        for indicator in critical_indicators:
            if indicator in text_lower:
                return 'Critical'
        
        for indicator in high_indicators:
            if indicator in text_lower:
                return 'High'
        
        for indicator in medium_indicators:
            if indicator in text_lower:
                return 'Medium'
        
        return 'Info'
    
    def _categorize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize findings by type."""
        categorized = {
            'vulnerabilities': [],
            'exposures': [],
            'misconfigurations': [],
            'informational': []
        }
        
        for finding in findings:
            finding_type = finding.get('type', '')
            severity = finding.get('severity', 'Info')
            
            if severity in ['Critical', 'High']:
                categorized['vulnerabilities'].append(finding)
            elif 'exposure' in finding_type.lower():
                categorized['exposures'].append(finding)
            elif 'config' in finding_type.lower():
                categorized['misconfigurations'].append(finding)
            else:
                categorized['informational'].append(finding)
        
        return categorized
    
    async def _generate_summary(
        self,
        scan_results: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> str:
        """Generate executive summary of findings."""
        
        # Build prompt
        target = scan_results.get('target', 'Unknown')
        prompt = self.prompt_builder.build_executive_summary_prompt(
            target=target,
            findings=findings,
            scan_duration="N/A"  # TODO: Calculate duration
        )
        
        # Get LLM response
        response = await self.llm.ask_async(prompt)
        
        return response
    
    async def _analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities with LLM."""
        if not vulnerabilities:
            return []
        
        analyzed = []
        
        for vuln in vulnerabilities:
            # Get remediation advice
            prompt = self.prompt_builder.build_remediation_prompt(vuln)
            remediation = await self.llm.ask_async(prompt)
            
            # Add analysis to vulnerability
            vuln['analysis'] = {
                'remediation': remediation,
                'impact': self._estimate_impact(vuln),
                'exploitability': self._estimate_exploitability(vuln)
            }
            
            analyzed.append(vuln)
        
        return analyzed
    
    async def _analyze_exposures(
        self,
        exposures: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze exposures."""
        # Similar to vulnerability analysis but for exposures
        return exposures
    
    async def _analyze_misconfigurations(
        self,
        misconfigurations: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze misconfigurations."""
        # Similar to vulnerability analysis but for misconfigurations
        return misconfigurations
    
    async def _generate_recommendations(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate prioritized recommendations."""
        
        # Sort findings by severity
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get('severity', 'Info'), 0),
            reverse=True
        )[:5]  # Top 5 most severe
        
        recommendations = []
        
        for finding in sorted_findings:
            prompt = f"""
            Based on this finding:
            - Name: {finding.get('name')}
            - Severity: {finding.get('severity')}
            - Description: {finding.get('description')}
            
            Provide ONE specific, actionable recommendation to address this issue.
            Keep it concise (1-2 sentences).
            """
            
            rec = await self.llm.ask_async(prompt)
            if rec and not rec.startswith('Error'):
                recommendations.append(rec)
        
        return recommendations
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score (0-10)."""
        if not findings:
            return 0.0
        
        # Weight by severity
        weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 5,
            'Low': 2,
            'Info': 0
        }
        
        total_weight = sum(weights.get(f.get('severity', 'Info'), 0) for f in findings)
        max_possible = len(findings) * 10
        
        if max_possible == 0:
            return 0.0
        
        score = (total_weight / max_possible) * 10
        return round(score, 1)
    
    def _estimate_impact(self, vulnerability: Dict[str, Any]) -> str:
        """Estimate the potential impact of a vulnerability."""
        severity = vulnerability.get('severity', 'Info')
        
        impact_map = {
            'Critical': 'Could lead to complete system compromise',
            'High': 'Could lead to significant data breach or service disruption',
            'Medium': 'Could lead to limited information disclosure',
            'Low': 'Minor impact, requires other conditions',
            'Info': 'Informational, no direct impact'
        }
        
        return impact_map.get(severity, 'Unknown impact')
    
    def _estimate_exploitability(self, vulnerability: Dict[str, Any]) -> str:
        """Estimate how easily a vulnerability can be exploited."""
        severity = vulnerability.get('severity', 'Info')
        
        exploitability_map = {
            'Critical': 'Trivial to exploit, public exploits available',
            'High': 'Moderately complex, exploits may exist',
            'Medium': 'Requires specific conditions',
            'Low': 'Difficult to exploit',
            'Info': 'Not applicable'
        }
        
        return exploitability_map.get(severity, 'Unknown')
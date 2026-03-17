"""Report builder for generating security assessment reports."""
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

from ..core.logger import LoggerMixin
from ..core.config import Config
from .html_report import HTMLReport
from .pdf_report import PDFReport
from .charts import ChartGenerator

class ReportBuilder(LoggerMixin):
    """Builds comprehensive security assessment reports."""
    
    def __init__(self):
        self.config = Config()
        self.html_report = HTMLReport()
        self.pdf_report = PDFReport()
        self.charts = ChartGenerator()
    
    async def build_report(
        self,
        scan_results: Dict[str, Any],
        report_format: str = 'html'
    ) -> str:
        """
        Build a comprehensive security report.
        
        Args:
            scan_results: Complete scan results
            report_format: Output format (html, pdf, json)
        
        Returns:
            Report as string
        """
        self.log_info(f"Building {report_format} report")
        
        # Extract key information
        report_data = self._extract_report_data(scan_results)
        
        # Generate charts
        charts = await self.charts.generate_all(report_data)
        
        # Add charts to report data
        report_data['charts'] = charts
        
        if report_format == 'html':
            return self.html_report.generate(report_data)
        elif report_format == 'pdf':
            return self.pdf_report.generate(report_data)
        else:
            return json.dumps(report_data, indent=2)
    
    def _extract_report_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract structured data for report generation."""
        
        report_data = {
            'report_id': f"SEC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'company_name': self.config.company_name,
            'author': self.config.report_author,
            'target': scan_results.get('target', 'Unknown'),
            'scan_type': scan_results.get('scan_type', 'Unknown'),
            'scan_started': scan_results.get('started_at', ''),
            'scan_completed': scan_results.get('completed_at', ''),
            'executive_summary': '',
            'scope': {},
            'methodology': [],
            'tools_used': [],
            'attack_surface': {},
            'open_ports': [],
            'technologies': [],
            'findings': [],
            'risk_distribution': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0
            },
            'recommendations': [],
            'timeline': []
        }
        
        # Extract from analysis
        analysis = scan_results.get('analysis', {})
        report_data['executive_summary'] = analysis.get('summary', '')
        report_data['recommendations'] = analysis.get('recommendations', [])
        
        # Extract findings
        vulnerabilities = analysis.get('vulnerabilities', [])
        exposures = analysis.get('exposures', [])
        misconfigurations = analysis.get('misconfigurations', [])
        
        all_findings = vulnerabilities + exposures + misconfigurations
        
        for finding in all_findings:
            severity = finding.get('severity', 'Info')
            report_data['risk_distribution'][severity] = report_data['risk_distribution'].get(severity, 0) + 1
            
            report_data['findings'].append({
                'name': finding.get('name', 'Unknown'),
                'severity': severity,
                'description': finding.get('description', ''),
                'affected_system': finding.get('affected_system', ''),
                'evidence': finding.get('evidence', ''),
                'remediation': finding.get('analysis', {}).get('remediation', ''),
                'impact': finding.get('analysis', {}).get('impact', ''),
                'cves': finding.get('cves', [])
            })
        
        # Extract tools used
        execution = scan_results.get('execution', {})
        for phase in execution.get('phases', []):
            for task in phase.get('tasks', []):
                tool_name = task.get('name', '').split('_')[0] if '_' in task.get('name', '') else task.get('name', '')
                if tool_name and tool_name not in report_data['tools_used']:
                    report_data['tools_used'].append(tool_name)
        
        # Extract open ports
        for phase in execution.get('phases', []):
            for task in phase.get('tasks', []):
                if task.get('name', '').startswith('nmap') and task.get('result'):
                    result = task['result']
                    if isinstance(result, dict):
                        report_data['open_ports'] = result.get('ports', [])
                        break
        
        # Extract technologies
        for phase in execution.get('phases', []):
            for task in phase.get('tasks', []):
                if task.get('name', '') == 'whatweb' and task.get('result'):
                    result = task['result']
                    if isinstance(result, dict):
                        report_data['technologies'] = result.get('technologies', [])
                        break
        
        # Create timeline
        report_data['timeline'] = self._build_timeline(execution)
        
        # Build scope
        report_data['scope'] = {
            'target': scan_results.get('target', ''),
            'scan_type': scan_results.get('scan_type', ''),
            'included': [scan_results.get('target', '')],
            'excluded': []
        }
        
        # Build methodology
        report_data['methodology'] = [
            'Initial reconnaissance and port scanning',
            'Service enumeration and technology identification',
            'Vulnerability scanning and assessment',
            'Manual verification of critical findings',
            'Risk analysis and prioritization',
            'Remediation recommendations'
        ]
        
        return report_data
    
    def _build_timeline(self, execution: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build scan timeline from execution data."""
        timeline = []
        
        for phase in execution.get('phases', []):
            phase_start = phase.get('started_at')
            phase_end = phase.get('completed_at')
            
            timeline.append({
                'phase': phase.get('name'),
                'start': phase_start,
                'end': phase_end,
                'duration': self._calculate_duration(phase_start, phase_end)
            })
            
            for task in phase.get('tasks', []):
                task_start = task.get('started_at')
                task_end = task.get('completed_at')
                
                if task_start and task_end:
                    timeline.append({
                        'phase': f"  - {task.get('name')}",
                        'start': task_start,
                        'end': task_end,
                        'duration': self._calculate_duration(task_start, task_end)
                    })
        
        return timeline
    
    def _calculate_duration(self, start: Optional[str], end: Optional[str]) -> str:
        """Calculate duration between two timestamps."""
        if not start or not end:
            return "Unknown"
        
        try:
            start_dt = datetime.fromisoformat(start)
            end_dt = datetime.fromisoformat(end)
            duration = end_dt - start_dt
            
            minutes = duration.total_seconds() / 60
            if minutes < 1:
                return f"{duration.total_seconds():.0f} seconds"
            elif minutes < 60:
                return f"{minutes:.1f} minutes"
            else:
                hours = minutes / 60
                return f"{hours:.1f} hours"
        except:
            return "Unknown"
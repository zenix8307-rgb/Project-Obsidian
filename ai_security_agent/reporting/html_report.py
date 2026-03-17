"""HTML report generator."""
from typing import Dict, List, Any
from datetime import datetime
import base64

class HTMLReport:
    """Generates professional HTML security reports."""
    
    def generate(self, data: Dict[str, Any]) -> str:
        """
        Generate HTML report from data.
        
        Args:
            data: Report data dictionary
        
        Returns:
            HTML string
        """
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {data['target']}</title>
    <style>
        :root {{
            --bg-primary: #0a0c10;
            --bg-secondary: #161b22;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent: #2f81f7;
            --critical: #ff7b72;
            --high: #f0883e;
            --medium: #d29922;
            --low: #3fb950;
            --info: #8b949e;
            --border: #30363d;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .header {{
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            color: var(--accent);
        }}
        
        .header .meta {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
        }}
        
        .card h2 {{
            font-size: 1.2rem;
            margin-bottom: 1rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background-color: rgba(255, 123, 114, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .severity-high {{ background-color: rgba(240, 136, 62, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .severity-medium {{ background-color: rgba(210, 153, 34, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .severity-low {{ background-color: rgba(63, 185, 80, 0.2); color: var(--low); border: 1px solid var(--low); }}
        .severity-info {{ background-color: rgba(139, 148, 158, 0.2); color: var(--info); border: 1px solid var(--info); }}
        
        .table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .table th,
        .table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        
        .table th {{
            color: var(--text-secondary);
            font-weight: normal;
            font-size: 0.9rem;
        }}
        
        .finding-details {{
            margin-top: 1rem;
            padding: 1rem;
            background-color: var(--bg-primary);
            border-radius: 8px;
            font-size: 0.9rem;
        }}
        
        .finding-details pre {{
            background-color: var(--bg-secondary);
            padding: 0.5rem;
            border-radius: 4px;
            overflow-x: auto;
            margin: 0.5rem 0;
        }}
        
        .remediation {{
            margin-top: 1rem;
            padding: 1rem;
            background-color: rgba(47, 129, 247, 0.1);
            border-left: 4px solid var(--accent);
            border-radius: 4px;
        }}
        
        .remediation h4 {{
            color: var(--accent);
            margin-bottom: 0.5rem;
        }}
        
        .tool-tag {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            background-color: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 0.25rem;
        }}
        
        .chart-container {{
            height: 300px;
            margin-bottom: 2rem;
        }}
        
        .footer {{
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="meta">
                <p><strong>Report ID:</strong> {data['report_id']}</p>
                <p><strong>Generated:</strong> {self._format_date(data['generated_at'])}</p>
                <p><strong>Target:</strong> {data['target']}</p>
                <p><strong>Scan Type:</strong> {data['scan_type']}</p>
                <p><strong>Scan Period:</strong> {self._format_date(data['scan_started'])} - {self._format_date(data['scan_completed'])}</p>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="card" style="margin-bottom: 2rem;">
            <h2>Executive Summary</h2>
            <p>{data['executive_summary']}</p>
        </div>
        
        <!-- Key Statistics -->
        <div class="grid">
            <div class="card">
                <h2>Total Findings</h2>
                <div class="stat-value">{len(data['findings'])}</div>
            </div>
            <div class="card">
                <h2>Critical</h2>
                <div class="stat-value" style="color: var(--critical);">{data['risk_distribution']['Critical']}</div>
            </div>
            <div class="card">
                <h2>High</h2>
                <div class="stat-value" style="color: var(--high);">{data['risk_distribution']['High']}</div>
            </div>
            <div class="card">
                <h2>Medium</h2>
                <div class="stat-value" style="color: var(--medium);">{data['risk_distribution']['Medium']}</div>
            </div>
            <div class="card">
                <h2>Low</h2>
                <div class="stat-value" style="color: var(--low);">{data['risk_distribution']['Low']}</div>
            </div>
            <div class="card">
                <h2>Info</h2>
                <div class="stat-value" style="color: var(--info);">{data['risk_distribution']['Info']}</div>
            </div>
        </div>
        
        <!-- Risk Distribution Chart -->
        <div class="card">
            <h2>Risk Distribution</h2>
            <div class="chart-container">
                {self._generate_risk_chart(data['risk_distribution'])}
            </div>
        </div>
        
        <!-- Tools Used -->
        <div class="card" style="margin-top: 2rem;">
            <h2>Tools Used</h2>
            <div>
                {''.join([f'<span class="tool-tag">{tool}</span>' for tool in data['tools_used']])}
            </div>
        </div>
        
        <!-- Attack Surface -->
        <div class="grid" style="margin-top: 2rem;">
            <div class="card">
                <h2>Open Ports</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_port_rows(data['open_ports'])}
                    </tbody>
                </table>
            </div>
            
            <div class="card">
                <h2>Technologies Detected</h2>
                <ul style="list-style: none;">
                    {''.join([f'<li style="margin-bottom: 0.5rem;">• {tech}</li>' for tech in data['technologies']])}
                </ul>
            </div>
        </div>
        
        <!-- Security Findings -->
        <div class="card" style="margin-top: 2rem;">
            <h2>Security Findings</h2>
            {self._generate_findings_table(data['findings'])}
        </div>
        
        <!-- Recommendations -->
        <div class="card" style="margin-top: 2rem;">
            <h2>Recommendations</h2>
            <ol style="margin-left: 1.5rem;">
                {''.join([f'<li style="margin-bottom: 0.5rem;">{rec}</li>' for rec in data['recommendations']])}
            </ol>
        </div>
        
        <!-- Methodology -->
        <div class="card" style="margin-top: 2rem;">
            <h2>Assessment Methodology</h2>
            <ol style="margin-left: 1.5rem;">
                {''.join([f'<li style="margin-bottom: 0.5rem;">{step}</li>' for step in data['methodology']])}
            </ol>
        </div>
        
        <!-- Timeline -->
        <div class="card" style="margin-top: 2rem;">
            <h2>Scan Timeline</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Phase</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_timeline_rows(data['timeline'])}
                </tbody>
            </table>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by {data['company_name']} | {data['author']}</p>
            <p>This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def _format_date(self, date_str: str) -> str:
        """Format ISO date string."""
        if not date_str:
            return "N/A"
        try:
            dt = datetime.fromisoformat(date_str)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return date_str
    
    def _generate_risk_chart(self, distribution: Dict[str, int]) -> str:
        """Generate a simple bar chart for risk distribution."""
        max_count = max(distribution.values()) if distribution.values() else 1
        
        bars = []
        colors = {
            'Critical': 'var(--critical)',
            'High': 'var(--high)',
            'Medium': 'var(--medium)',
            'Low': 'var(--low)',
            'Info': 'var(--info)'
        }
        
        for severity, count in distribution.items():
            percentage = (count / max_count * 100) if max_count > 0 else 0
            bar = f"""
            <div style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
                    <span>{severity}</span>
                    <span>{count}</span>
                </div>
                <div style="height: 20px; background-color: var(--bg-primary); border-radius: 10px; overflow: hidden;">
                    <div style="height: 100%; width: {percentage}%; background-color: {colors.get(severity, 'var(--info)')};"></div>
                </div>
            </div>
            """
            bars.append(bar)
        
        return ''.join(bars)
    
    def _generate_port_rows(self, ports: List[Dict[str, Any]]) -> str:
        """Generate HTML rows for open ports table."""
        if not ports:
            return '<tr><td colspan="3" style="text-align: center;">No open ports found</td></tr>'
        
        rows = []
        for port in ports[:10]:  # Limit to 10 ports
            rows.append(f"""
            <tr>
                <td>{port.get('port', '')}</td>
                <td>{port.get('service', '')}</td>
                <td>{port.get('version', '')}</td>
            </tr>
            """)
        
        if len(ports) > 10:
            rows.append(f'<tr><td colspan="3" style="text-align: center;">... and {len(ports) - 10} more ports</td></tr>')
        
        return ''.join(rows)
    
    def _generate_findings_table(self, findings: List[Dict[str, Any]]) -> str:
        """Generate HTML for findings table with details."""
        if not findings:
            return '<p style="text-align: center; padding: 2rem;">No findings to display</p>'
        
        html = ""
        for finding in findings:
            severity_class = f"severity-{finding['severity'].lower()}"
            
            html += f"""
            <div style="margin-bottom: 2rem; padding: 1rem; border: 1px solid var(--border); border-radius: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h3 style="color: var(--accent);">{finding['name']}</h3>
                    <span class="severity-badge {severity_class}">{finding['severity']}</span>
                </div>
                
                <p><strong>Affected System:</strong> {finding['affected_system']}</p>
                
                <div class="finding-details">
                    <p><strong>Description:</strong> {finding['description']}</p>
                    
                    <p><strong>Evidence:</strong></p>
                    <pre>{finding['evidence'][:500]}{'...' if len(finding['evidence']) > 500 else ''}</pre>
                    
                    <p><strong>Impact:</strong> {finding['impact']}</p>
                    
                    {self._format_cves(finding.get('cves', []))}
                </div>
                
                <div class="remediation">
                    <h4>Remediation</h4>
                    <p>{finding['remediation']}</p>
                </div>
            </div>
            """
        
        return html
    
    def _format_cves(self, cves: List[str]) -> str:
        """Format CVE references."""
        if not cves:
            return ""
        
        cve_links = []
        for cve in cves:
            cve_links.append(f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank" style="color: var(--accent);">{cve}</a>')
        
        return f"<p><strong>CVEs:</strong> {', '.join(cve_links)}</p>"
    
    def _generate_timeline_rows(self, timeline: List[Dict[str, Any]]) -> str:
        """Generate HTML rows for timeline table."""
        if not timeline:
            return '<tr><td colspan="2" style="text-align: center;">No timeline data available</td></tr>'
        
        rows = []
        for item in timeline:
            rows.append(f"""
            <tr>
                <td>{item.get('phase', '')}</td>
                <td>{item.get('duration', '')}</td>
            </tr>
            """)
        
        return ''.join(rows)
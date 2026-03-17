"""Vulnerability parser module."""
import re
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..core.logger import LoggerMixin

class VulnParser(LoggerMixin):
    """Parser for vulnerability scan outputs."""
    
    def __init__(self):
        self.severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
        self.cve_pattern = r'CVE-\d{4}-\d{4,7}'
    
    def parse_nuclei_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Nuclei JSON output.
        
        Args:
            output: Nuclei output as string (JSON lines)
        
        Returns:
            List of parsed vulnerabilities
        """
        vulnerabilities = []
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                vuln = {
                    'id': data.get('template-id', ''),
                    'name': data.get('info', {}).get('name', ''),
                    'severity': data.get('info', {}).get('severity', 'info').capitalize(),
                    'description': data.get('info', {}).get('description', ''),
                    'host': data.get('host', ''),
                    'matched': data.get('matched-at', ''),
                    'type': data.get('type', ''),
                    'cves': [],
                    'references': data.get('info', {}).get('reference', []),
                    'tags': data.get('info', {}).get('tags', []),
                    'timestamp': datetime.now().isoformat()
                }
                
                # Extract CVEs
                info_data = data.get('info', {})
                classification = info_data.get('classification', {})
                if classification.get('cve-id'):
                    vuln['cves'] = classification['cve-id']
                
                # Check for CVE in description
                cve_match = re.search(self.cve_pattern, vuln['description'])
                if cve_match:
                    vuln['cves'].append(cve_match.group(0))
                
                vulnerabilities.append(vuln)
                
            except json.JSONDecodeError as e:
                self.log_debug(f"Failed to parse JSON line: {e}")
        
        return vulnerabilities
    
    def parse_nmap_vuln_scripts(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Nmap vulnerability script output.
        
        Args:
            output: Nmap script output as string
        
        Returns:
            List of parsed vulnerabilities
        """
        vulnerabilities = []
        
        current_vuln = None
        
        for line in output.split('\n'):
            # Check for script start
            if line.startswith('|'):
                line = line[1:].strip()
                
                # New vulnerability section
                if line.startswith('VULNERABLE:'):
                    if current_vuln:
                        vulnerabilities.append(current_vuln)
                    
                    current_vuln = {
                        'name': line.replace('VULNERABLE:', '').strip(),
                        'severity': 'High',
                        'description': '',
                        'state': '',
                        'ids': [],
                        'references': []
                    }
                
                # State information
                elif current_vuln and 'State:' in line:
                    current_vuln['state'] = line.replace('State:', '').strip()
                
                # Description
                elif current_vuln and line and not line.startswith(' ') and not any(x in line for x in ['CVE-', 'https://']):
                    current_vuln['description'] += line + ' '
                
                # CVE IDs
                elif current_vuln and 'CVE-' in line:
                    cve_match = re.search(self.cve_pattern, line)
                    if cve_match:
                        current_vuln['ids'].append(cve_match.group(0))
                
                # References
                elif current_vuln and ('http://' in line or 'https://' in line):
                    current_vuln['references'].append(line.strip())
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return vulnerabilities
    
    def parse_searchsploit_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Searchsploit output.
        
        Args:
            output: Searchsploit output as string
        
        Returns:
            List of exploit information
        """
        exploits = []
        
        lines = output.split('\n')
        start_parsing = False
        
        for line in lines:
            if '----' in line:
                start_parsing = True
                continue
            
            if start_parsing and line.strip():
                # Parse exploit line
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 3:
                    exploit = {
                        'path': parts[0],
                        'title': parts[1],
                        'type': parts[2] if len(parts) > 2 else '',
                        'platform': None
                    }
                    
                    # Extract platform from title
                    platforms = ['windows', 'linux', 'macos', 'php', 'python', 'ruby', 'java']
                    for platform in platforms:
                        if platform in exploit['title'].lower():
                            exploit['platform'] = platform
                            break
                    
                    exploits.append(exploit)
        
        return exploits
    
    def parse_wpscan_output(self, output: str) -> Dict[str, Any]:
        """
        Parse WPScan output.
        
        Args:
            output: WPScan output as string
        
        Returns:
            Structured vulnerability information
        """
        results = {
            'version': None,
            'vulnerabilities': [],
            'plugins': [],
            'themes': [],
            'users': []
        }
        
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            # Version detection
            if 'WordPress version' in line:
                version_match = re.search(r'WordPress version (\S+)', line)
                if version_match:
                    results['version'] = version_match.group(1)
            
            # Vulnerabilities
            if '[!]' in line:
                vuln = {
                    'name': line.replace('[!]', '').strip(),
                    'severity': 'High'  # WPScan doesn't provide severity
                }
                
                # Check for CVE
                cve_match = re.search(self.cve_pattern, line)
                if cve_match:
                    vuln['cve'] = cve_match.group(0)
                
                results['vulnerabilities'].append(vuln)
            
            # Section detection
            if 'plugins' in line.lower() and 'found' in line.lower():
                current_section = 'plugins'
            elif 'themes' in line.lower() and 'found' in line.lower():
                current_section = 'themes'
            elif 'users' in line.lower() and 'found' in line.lower():
                current_section = 'users'
            
            # Parse section data
            if current_section and line.strip() and '|' in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2:
                    item = {
                        'name': parts[1],
                        'version': None,
                        'vulnerabilities': []
                    }
                    
                    # Check for version
                    if parts[1] and '(' in parts[1] and ')' in parts[1]:
                        name_parts = parts[1].split('(')
                        item['name'] = name_parts[0].strip()
                        version_part = name_parts[1].replace(')', '').strip()
                        if version_part and 'v' not in version_part.lower():
                            item['version'] = version_part
                    
                    if current_section == 'plugins':
                        results['plugins'].append(item)
                    elif current_section == 'themes':
                        results['themes'].append(item)
                    elif current_section == 'users':
                        results['users'].append({'username': parts[1]})
        
        return results
    
    def merge_vulnerabilities(self, vuln_lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Merge vulnerabilities from multiple sources.
        
        Args:
            vuln_lists: List of vulnerability lists from different tools
        
        Returns:
            Merged and deduplicated vulnerability list
        """
        merged = []
        seen = set()
        
        for vuln_list in vuln_lists:
            for vuln in vuln_list:
                # Create unique key
                vuln_key = f"{vuln.get('name', '')}_{vuln.get('host', '')}"
                
                if vuln_key not in seen:
                    seen.add(vuln_key)
                    
                    # Normalize severity
                    severity = vuln.get('severity', 'Info')
                    if severity not in self.severity_levels:
                        severity = 'Info'
                    
                    vuln['severity'] = severity
                    merged.append(vuln)
        
        # Sort by severity
        severity_order = {s: i for i, s in enumerate(self.severity_levels)}
        merged.sort(key=lambda x: severity_order.get(x.get('severity', 'Info'), 999))
        
        return merged
"""Nmap output parser module."""
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..core.logger import LoggerMixin

class NmapParser(LoggerMixin):
    """Parser for nmap scan outputs."""
    
    def __init__(self):
        self.port_states = ['open', 'filtered', 'closed']
        self.common_web_ports = [80, 443, 8080, 8443, 8000, 8888]
    
    def parse(self, output: str, output_format: str = 'normal') -> Dict[str, Any]:
        """
        Parse nmap output.
        
        Args:
            output: Nmap output as string
            output_format: Format of output (normal, xml, grepable)
        
        Returns:
            Structured parse results
        """
        if output_format == 'xml':
            return self._parse_xml(output)
        elif output_format == 'grepable':
            return self._parse_grepable(output)
        else:
            return self._parse_normal(output)
    
    def _parse_normal(self, output: str) -> Dict[str, Any]:
        """Parse normal nmap output."""
        results = {
            'hosts': [],
            'ports': [],
            'services': [],
            'os_matches': [],
            'scripts': []
        }
        
        current_host = None
        
        for line in output.split('\n'):
            # Host detection
            if line.startswith('Nmap scan report for'):
                if current_host:
                    results['hosts'].append(current_host)
                
                host_part = line.replace('Nmap scan report for', '').strip()
                current_host = {
                    'hostname': host_part.split(' ')[0],
                    'ip': None,
                    'ports': [],
                    'os': None
                }
                
                # Check for IP in parentheses
                if '(' in host_part and ')' in host_part:
                    ip_match = re.search(r'\(([^)]+)\)', host_part)
                    if ip_match:
                        current_host['ip'] = ip_match.group(1)
            
            # Port detection
            port_match = re.match(r'^(\d+)/tcp\s+(\w+)\s+(\S+)\s*(.*)$', line)
            if port_match and current_host:
                port, state, service, version = port_match.groups()
                
                port_info = {
                    'port': int(port),
                    'protocol': 'tcp',
                    'state': state,
                    'service': service,
                    'version': version.strip()
                }
                
                current_host['ports'].append(port_info)
                results['ports'].append(port_info)
                
                if service:
                    results['services'].append({
                        'port': int(port),
                        'service': service,
                        'version': version.strip()
                    })
            
            # OS detection
            if 'OS:' in line and current_host:
                current_host['os'] = line.replace('OS:', '').strip()
                results['os_matches'].append(current_host['os'])
            
            # Script output
            if line.startswith('|') and current_host:
                results['scripts'].append(line.strip())
        
        if current_host:
            results['hosts'].append(current_host)
        
        return results
    
    def _parse_xml(self, xml_content: str) -> Dict[str, Any]:
        """Parse nmap XML output."""
        results = {
            'hosts': [],
            'ports': [],
            'services': [],
            'os_matches': []
        }
        
        try:
            root = ET.fromstring(xml_content)
            
            for host in root.findall('.//host'):
                host_info = self._parse_xml_host(host)
                results['hosts'].append(host_info)
                
                # Collect all ports
                for port in host_info.get('ports', []):
                    results['ports'].append(port)
                    
                    if port.get('service'):
                        results['services'].append({
                            'port': port['port'],
                            'service': port['service'],
                            'version': port.get('version', '')
                        })
        
        except ET.ParseError as e:
            self.log_error(f"XML parse error: {e}")
        
        return results
    
    def _parse_xml_host(self, host_elem) -> Dict[str, Any]:
        """Parse a single host from XML."""
        host_info = {
            'ip': None,
            'hostname': None,
            'ports': [],
            'os': None,
            'status': None
        }
        
        # Get address
        address = host_elem.find('address')
        if address is not None:
            addr_type = address.get('addrtype')
            if addr_type == 'ipv4':
                host_info['ip'] = address.get('addr')
        
        # Get hostname
        hostname = host_elem.find('hostnames/hostname')
        if hostname is not None:
            host_info['hostname'] = hostname.get('name')
        
        # Get status
        status = host_elem.find('status')
        if status is not None:
            host_info['status'] = status.get('state')
        
        # Get ports
        for port_elem in host_elem.findall('.//port'):
            port_info = self._parse_xml_port(port_elem)
            if port_info:
                host_info['ports'].append(port_info)
        
        # Get OS
        os_elem = host_elem.find('.//osmatch')
        if os_elem is not None:
            host_info['os'] = os_elem.get('name')
        
        return host_info
    
    def _parse_xml_port(self, port_elem) -> Optional[Dict[str, Any]]:
        """Parse a single port from XML."""
        port_info = {
            'port': int(port_elem.get('portid')),
            'protocol': port_elem.get('protocol'),
            'state': None,
            'service': None,
            'version': None
        }
        
        # Get state
        state = port_elem.find('state')
        if state is not None:
            port_info['state'] = state.get('state')
        
        # Get service
        service = port_elem.find('service')
        if service is not None:
            port_info['service'] = service.get('name')
            port_info['version'] = service.get('version', '')
            port_info['product'] = service.get('product', '')
        
        return port_info
    
    def _parse_grepable(self, output: str) -> Dict[str, Any]:
        """Parse grepable nmap output."""
        results = {
            'ports': []
        }
        
        for line in output.split('\n'):
            if line.startswith('Ports:'):
                ports_part = line.replace('Ports:', '').strip()
                port_entries = ports_part.split(',')
                
                for entry in port_entries:
                    parts = entry.strip().split('/')
                    if len(parts) >= 3:
                        results['ports'].append({
                            'port': int(parts[0]),
                            'state': parts[1],
                            'protocol': parts[2],
                            'service': parts[4] if len(parts) > 4 else ''
                        })
        
        return results
    
    def get_web_ports(self, parsed_output: Dict[str, Any]) -> List[int]:
        """Extract web-related ports from parsed output."""
        web_ports = []
        
        for port in parsed_output.get('ports', []):
            if port.get('port') in self.common_web_ports:
                web_ports.append(port.get('port'))
            elif port.get('service') in ['http', 'https', 'http-alt']:
                web_ports.append(port.get('port'))
        
        return web_ports
    
    def get_service_versions(self, parsed_output: Dict[str, Any]) -> Dict[str, str]:
        """Extract service versions from parsed output."""
        versions = {}
        
        for service in parsed_output.get('services', []):
            if service.get('version'):
                versions[service['service']] = service['version']
        
        return versions
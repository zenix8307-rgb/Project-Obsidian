"""Web application output parser module."""
import re
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from ..core.logger import LoggerMixin

class WebParser(LoggerMixin):
    """Parser for web application scan outputs."""
    
    def __init__(self):
        self.cms_patterns = {
            'wordpress': [r'wp-content', r'wp-includes', r'xmlrpc\.php'],
            'drupal': [r'sites/all/', r'drupal.js', r'Drupal.settings'],
            'joomla': [r'index.php?option=', r'/media/system/js/'],
            'magento': [r'skin/frontend/', r'js/mage/'],
            'shopify': [r'cdn.shopify.com', r'myshopify.com']
        }
        
        self.tech_patterns = {
            'php': [r'\.php', r'PHPSESSID'],
            'asp.net': [r'\.asp', r'\.aspx', r'__VIEWSTATE'],
            'java': [r'\.jsp', r'JSESSIONID'],
            'python': [r'wsgi', r'django', r'flask'],
            'node.js': [r'express', r'node_modules']
        }
    
    def parse_whatweb_output(self, output: str) -> Dict[str, Any]:
        """
        Parse WhatWeb output.
        
        Args:
            output: WhatWeb output as string
        
        Returns:
            Structured technology information
        """
        results = {
            'url': None,
            'title': None,
            'status': None,
            'technologies': [],
            'cms': None,
            'server': None,
            'frameworks': []
        }
        
        # Extract URL
        url_match = re.search(r'(https?://[^\s]+)', output)
        if url_match:
            results['url'] = url_match.group(1)
        
        # Extract technologies
        if '[' in output and ']' in output:
            tech_part = output.split(']')[-1].strip()
            techs = [t.strip() for t in tech_part.split(',') if t.strip()]
            
            for tech in techs:
                results['technologies'].append(tech)
                
                # Identify CMS
                for cms, patterns in self.cms_patterns.items():
                    if cms.lower() in tech.lower():
                        results['cms'] = cms
                        break
                
                # Identify server
                if 'server' in tech.lower():
                    results['server'] = tech
                
                # Identify frameworks
                for framework, patterns in self.tech_patterns.items():
                    if framework.lower() in tech.lower():
                        results['frameworks'].append(framework)
        
        return results
    
    def parse_gobuster_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Gobuster output.
        
        Args:
            output: Gobuster output as string
        
        Returns:
            Structured directory information
        """
        results = {
            'directories': [],
            'files': [],
            'status_counts': {}
        }
        
        dir_pattern = r'/(\S+)\s+\(Status:\s*(\d+)\)'
        
        for line in output.split('\n'):
            match = re.search(dir_pattern, line)
            if match:
                path, status = match.groups()
                status_int = int(status)
                
                entry = {
                    'path': f"/{path}",
                    'status': status_int
                }
                
                # Track status counts
                results['status_counts'][status_int] = results['status_counts'].get(status_int, 0) + 1
                
                # Categorize by status
                if status_int == 200:
                    results['directories'].append(entry)
                elif status_int in [301, 302, 307]:
                    results['directories'].append(entry)
                elif '.' in path:  # Files usually have extensions
                    results['files'].append(entry)
                else:
                    results['directories'].append(entry)
        
        return results
    
    def parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Nikto output.
        
        Args:
            output: Nikto output as string
        
        Returns:
            Structured vulnerability information
        """
        results = {
            'vulnerabilities': [],
            'info': [],
            'warnings': []
        }
        
        for line in output.split('\n'):
            if line.startswith('+ '):
                vuln = line[2:].strip()
                
                # Categorize by severity
                if any(x in vuln.lower() for x in ['vulnerable', 'exploit', 'xss', 'sqli']):
                    results['vulnerabilities'].append(vuln)
                elif any(x in vuln.lower() for x in ['warning', 'caution']):
                    results['warnings'].append(vuln)
                else:
                    results['info'].append(vuln)
        
        return results
    
    def extract_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """
        Extract forms from HTML content.
        
        Args:
            html_content: HTML content as string
        
        Returns:
            List of form information
        """
        forms = []
        
        # Simple regex for form extraction (production would use BeautifulSoup)
        form_pattern = r'<form.*?>(.*?)</form>'
        input_pattern = r'<input.*?name=["\']([^"\']+)["\']'
        
        for form_match in re.finditer(form_pattern, html_content, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(1)
            
            # Extract form attributes
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_match.group(0), re.IGNORECASE)
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_match.group(0), re.IGNORECASE)
            
            # Extract inputs
            inputs = []
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                inputs.append(input_match.group(1))
            
            forms.append({
                'method': method_match.group(1).upper() if method_match else 'GET',
                'action': action_match.group(1) if action_match else '',
                'inputs': inputs
            })
        
        return forms
    
    def extract_links(self, html_content: str, base_url: str) -> List[str]:
        """
        Extract links from HTML content.
        
        Args:
            html_content: HTML content as string
            base_url: Base URL for resolving relative links
        
        Returns:
            List of extracted links
        """
        links = []
        
        # Extract href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        
        for match in re.finditer(href_pattern, html_content, re.IGNORECASE):
            link = match.group(1)
            
            # Resolve relative URLs
            if not link.startswith(('http://', 'https://', '//')):
                if link.startswith('/'):
                    parsed_base = urlparse(base_url)
                    link = f"{parsed_base.scheme}://{parsed_base.netloc}{link}"
                else:
                    link = base_url.rstrip('/') + '/' + link.lstrip('/')
            
            links.append(link)
        
        return list(set(links))  # Remove duplicates
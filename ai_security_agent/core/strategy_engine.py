"""Dynamic strategy engine for intelligent tool selection."""
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import re
from .logger import LoggerMixin
from ..llm.llm_interface import LLMInterface
from ..llm.prompt_builder import PromptBuilder

class StrategyEngine(LoggerMixin):
    """Intelligent engine for dynamically selecting security tools based on findings."""
    
    def __init__(self, llm: LLMInterface):
        self.llm = llm
        self.prompt_builder = PromptBuilder()
        self.tool_registry = self._initialize_tool_registry()
        self.strategy_history = []
    
    def _initialize_tool_registry(self) -> Dict[str, Dict[str, Any]]:
        """Initialize the registry of available tools and their capabilities."""
        return {
            'nmap': {
                'name': 'Nmap',
                'category': 'network_scanner',
                'capabilities': ['port_scanning', 'service_detection', 'os_detection', 'script_scan'],
                'dependencies': [],
                'triggers': ['initial_scan'],
                'output_types': ['xml', 'normal', 'grepable']
            },
            'amass': {
                'name': 'Amass',
                'category': 'subdomain_enum',
                'capabilities': ['subdomain_enumeration', 'dns_bruteforce', 'api_enumeration'],
                'dependencies': [],
                'triggers': ['subdomain_needed', 'domain_known'],
                'output_types': ['json', 'txt']
            },
            'sublist3r': {
                'name': 'Sublist3r',
                'category': 'subdomain_enum',
                'capabilities': ['subdomain_enumeration', 'search_engine_enum'],
                'dependencies': [],
                'triggers': ['subdomain_needed', 'domain_known'],
                'output_types': ['txt']
            },
            'theharvester': {
                'name': 'theHarvester',
                'category': 'osint',
                'capabilities': ['email_discovery', 'employee_names', 'subdomain_enum'],
                'dependencies': [],
                'triggers': ['osint_needed', 'domain_known'],
                'output_types': ['json', 'txt']
            },
            'gobuster': {
                'name': 'Gobuster',
                'category': 'directory_enum',
                'capabilities': ['directory_bruteforce', 'dns_bruteforce', 'vhost_enum'],
                'dependencies': ['web_services'],
                'triggers': ['web_ports_detected', 'directory_enum_needed'],
                'output_types': ['txt']
            },
            'dirsearch': {
                'name': 'Dirsearch',
                'category': 'directory_enum',
                'capabilities': ['directory_bruteforce', 'file_enumeration', 'extension_based'],
                'dependencies': ['web_services'],
                'triggers': ['web_ports_detected', 'directory_enum_needed'],
                'output_types': ['json', 'txt']
            },
            'ffuf': {
                'name': 'FFUF',
                'category': 'fuzzing',
                'capabilities': ['parameter_fuzzing', 'directory_fuzzing', 'vhost_fuzzing'],
                'dependencies': ['web_services'],
                'triggers': ['fuzzing_needed', 'parameter_enum_needed'],
                'output_types': ['json', 'txt']
            },
            'whatweb': {
                'name': 'WhatWeb',
                'category': 'web_identification',
                'capabilities': ['cms_detection', 'technology_detection', 'version_detection'],
                'dependencies': ['web_services'],
                'triggers': ['web_ports_detected', 'technology_identification_needed'],
                'output_types': ['json', 'txt']
            },
            'nikto': {
                'name': 'Nikto',
                'category': 'web_vuln_scanner',
                'capabilities': ['vulnerability_scanning', 'misconfiguration_detection'],
                'dependencies': ['web_services'],
                'triggers': ['web_ports_detected', 'web_vuln_scan_needed'],
                'output_types': ['json', 'txt', 'html']
            },
            'sqlmap': {
                'name': 'SQLmap',
                'category': 'sqli_tester',
                'capabilities': ['sql_injection_detection', 'database_enumeration'],
                'dependencies': ['web_parameters'],
                'triggers': ['parameters_detected', 'sqli_suspected'],
                'output_types': ['json', 'txt']
            },
            'wpscan': {
                'name': 'WPScan',
                'category': 'cms_scanner',
                'capabilities': ['wordpress_vuln_scan', 'plugin_enum', 'theme_enum', 'user_enum'],
                'dependencies': ['wordpress_detected'],
                'triggers': ['wordpress_detected'],
                'output_types': ['json', 'txt']
            },
            'nuclei': {
                'name': 'Nuclei',
                'category': 'vuln_scanner',
                'capabilities': ['template_based_scanning', 'cve_scanning'],
                'dependencies': ['web_services'],
                'triggers': ['vuln_scan_needed'],
                'output_types': ['json', 'txt']
            },
            'searchsploit': {
                'name': 'Searchsploit',
                'category': 'exploit_lookup',
                'capabilities': ['exploit_search', 'vulnerability_lookup'],
                'dependencies': ['service_versions'],
                'triggers': ['versions_known', 'exploit_research_needed'],
                'output_types': ['txt']
            }
        }
    
    async def determine_next_tools(
        self,
        current_findings: Dict[str, Any],
        executed_tools: Set[str],
        target_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Determine the next set of tools to run based on current findings.
        
        Args:
            current_findings: Dictionary of findings from completed scans
            executed_tools: Set of tools already executed
            target_info: Information about the target
        
        Returns:
            List of recommended tools with parameters
        """
        self.log_info("Determining next tools based on findings")
        
        recommended_tools = []
        
        # Analyze findings to determine context
        context = self._analyze_findings(current_findings, target_info)
        
        # Check each tool's triggers
        for tool_name, tool_info in self.tool_registry.items():
            if tool_name in executed_tools:
                continue
            
            # Check dependencies
            deps_satisfied = self._check_dependencies(tool_info['dependencies'], context)
            if not deps_satisfied:
                continue
            
            # Check triggers
            triggers_met = self._check_triggers(tool_info['triggers'], context)
            if not triggers_met:
                continue
            
            # Build parameters based on context
            params = self._build_parameters(tool_name, context)
            
            recommended_tools.append({
                'tool': tool_name,
                'priority': self._calculate_priority(tool_name, context),
                'params': params,
                'reason': f"Triggered by: {', '.join(tool_info['triggers'])}"
            })
        
        # Sort by priority
        recommended_tools.sort(key=lambda x: x['priority'], reverse=True)
        
        # Use LLM to refine selection if there are many options
        if len(recommended_tools) > 5:
            recommended_tools = await self._refine_with_llm(recommended_tools, context)
        
        self.log_info(f"Recommended {len(recommended_tools)} tools for next phase")
        return recommended_tools
    
    def _analyze_findings(
        self,
        findings: Dict[str, Any],
        target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze findings to extract context for tool selection."""
        context = {
            'web_services': False,
            'web_ports': [],
            'technologies': [],
            'wordpress_detected': False,
            'parameters_detected': False,
            'subdomains_found': False,
            'service_versions': {},
            'open_ports': [],
            'os_detected': None
        }
        
        # Parse nmap findings
        if 'nmap' in findings:
            nmap_data = findings['nmap']
            if isinstance(nmap_data, dict):
                # Check for web ports
                web_ports = [80, 443, 8080, 8443, 8000, 8888]
                for port in nmap_data.get('ports', []):
                    context['open_ports'].append(port)
                    if port in web_ports:
                        context['web_services'] = True
                        context['web_ports'].append(port)
                
                # Check for service versions
                for service in nmap_data.get('services', []):
                    if 'version' in service:
                        context['service_versions'][service['name']] = service['version']
        
        # Parse whatweb findings
        if 'whatweb' in findings:
            web_data = findings['whatweb']
            if isinstance(web_data, str):
                if 'WordPress' in web_data:
                    context['wordpress_detected'] = True
                    context['technologies'].append('WordPress')
                if 'Drupal' in web_data:
                    context['technologies'].append('Drupal')
                if 'Joomla' in web_data:
                    context['technologies'].append('Joomla')
        
        # Parse subdomain findings
        if 'amass' in findings or 'sublist3r' in findings:
            context['subdomains_found'] = True
        
        # Check for parameters in findings
        if 'gobuster' in findings or 'ffuf' in findings or 'dirsearch' in findings:
            context['parameters_detected'] = True
        
        # Add target info
        context.update(target_info)
        
        return context
    
    def _check_dependencies(self, dependencies: List[str], context: Dict[str, Any]) -> bool:
        """Check if tool dependencies are satisfied."""
        for dep in dependencies:
            if dep == 'web_services' and not context.get('web_services', False):
                return False
            elif dep == 'web_parameters' and not context.get('parameters_detected', False):
                return False
            elif dep == 'wordpress_detected' and not context.get('wordpress_detected', False):
                return False
            elif dep == 'service_versions' and not context.get('service_versions', {}):
                return False
        return True
    
    def _check_triggers(self, triggers: List[str], context: Dict[str, Any]) -> bool:
        """Check if any trigger conditions are met."""
        for trigger in triggers:
            if trigger == 'initial_scan':
                return True  # Always trigger initial scan
            elif trigger == 'web_ports_detected' and context.get('web_services', False):
                return True
            elif trigger == 'subdomain_needed' and not context.get('subdomains_found', False):
                return True
            elif trigger == 'directory_enum_needed' and context.get('web_services', False):
                return True
            elif trigger == 'parameters_detected' and context.get('parameters_detected', False):
                return True
            elif trigger == 'wordpress_detected' and context.get('wordpress_detected', False):
                return True
            elif trigger == 'versions_known' and context.get('service_versions', {}):
                return True
            elif trigger == 'vuln_scan_needed':
                return True
            elif trigger == 'fuzzing_needed' and context.get('web_services', False):
                return True
        return False
    
    def _build_parameters(self, tool_name: str, context: Dict[str, Any]) -> List[str]:
        """Build tool-specific parameters based on context."""
        params = []
        
        if tool_name == 'gobuster':
            params = ['dir', '-u', context.get('target_url', 'http://target.com')]
            params.extend(['-w', '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'])
            if context.get('web_ports'):
                # Add port-specific parameters
                pass
        
        elif tool_name == 'nikto':
            params = ['-h', context.get('target_url', 'http://target.com')]
            if 443 in context.get('web_ports', []):
                params.append('-ssl')
        
        elif tool_name == 'sqlmap':
            if context.get('target_url'):
                params = ['-u', f"{context['target_url']}?param=1", '--batch']
        
        elif tool_name == 'wpscan':
            params = ['--url', context.get('target_url', 'http://target.com'), '--enumerate', 'vp,ap,vt']
        
        elif tool_name == 'nuclei':
            params = ['-t', 'cves/', '-t', 'vulnerabilities/']
        
        return params
    
    def _calculate_priority(self, tool_name: str, context: Dict[str, Any]) -> int:
        """Calculate priority score for a tool (higher is more important)."""
        priority_scores = {
            'nmap': 100,
            'whatweb': 90,
            'gobuster': 85,
            'nikto': 80,
            'nuclei': 75,
            'wpscan': 70,
            'sqlmap': 65,
            'amass': 60,
            'sublist3r': 55,
            'ffuf': 50,
            'dirsearch': 50,
            'theharvester': 40,
            'searchsploit': 30
        }
        
        base_score = priority_scores.get(tool_name, 50)
        
        # Adjust based on context
        if tool_name == 'nmap' and not context.get('open_ports'):
            base_score += 20  # Priority if no port scan done yet
        
        if tool_name == 'wpscan' and context.get('wordpress_detected'):
            base_score += 30  # High priority if WordPress detected
        
        if tool_name == 'sqlmap' and context.get('parameters_detected'):
            base_score += 25  # Higher priority if parameters found
        
        return base_score
    
    async def _refine_with_llm(
        self,
        recommended_tools: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Use LLM to refine tool selection when there are many options."""
        
        # Build prompt for LLM
        tools_list = "\n".join([
            f"- {t['tool']} (priority: {t['priority']}, reason: {t['reason']})"
            for t in recommended_tools
        ])
        
        context_str = f"""
        Target Context:
        - Web Services: {context.get('web_services', False)}
        - WordPress: {context.get('wordpress_detected', False)}
        - Parameters Detected: {context.get('parameters_detected', False)}
        - Open Ports: {context.get('open_ports', [])}
        - Technologies: {context.get('technologies', [])}
        """
        
        prompt = f"""
        As a security expert, prioritize the following security tools for scanning a target.
        Consider efficiency and coverage. Select the TOP 5 tools that should run next.
        
        Context:
        {context_str}
        
        Available tools:
        {tools_list}
        
        Return a comma-separated list of the 5 most important tool names in order of priority.
        """
        
        # Get LLM recommendation
        response = await self.llm.ask_async(prompt)
        
        # Parse response
        selected_tools = []
        if response:
            # Extract tool names from response
            for line in response.split('\n'):
                for tool in self.tool_registry.keys():
                    if tool in line.lower() and tool not in selected_tools:
                        selected_tools.append(tool)
        
        # Filter recommended tools to only include selected ones
        if selected_tools:
            refined = [t for t in recommended_tools if t['tool'] in selected_tools]
            # Preserve order from LLM
            ordered = []
            for tool_name in selected_tools:
                for tool in refined:
                    if tool['tool'] == tool_name:
                        ordered.append(tool)
                        break
            return ordered
        
        return recommended_tools[:5]  # Fallback to top 5 by priority
    
    def get_next_strategy(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Get the complete next strategy based on findings."""
        
        # Determine which phase we're in
        phase = self._determine_phase(findings)
        
        # Get recommended tools
        tools = self.determine_next_tools(findings, set(), {})
        
        strategy = {
            'phase': phase,
            'recommended_tools': tools,
            'estimated_duration': self._estimate_duration(tools),
            'parallel_possible': self._check_parallel_possible(tools)
        }
        
        # Store in history
        self.strategy_history.append({
            'timestamp': datetime.now().isoformat(),
            'findings_summary': self._summarize_findings(findings),
            'strategy': strategy
        })
        
        return strategy
    
    def _determine_phase(self, findings: Dict[str, Any]) -> str:
        """Determine current phase of the security assessment."""
        
        if not findings:
            return 'initial_reconnaissance'
        
        if 'nmap' not in findings:
            return 'port_scanning'
        
        # Check if we have web services and need web scanning
        if self._has_web_services(findings) and not self._has_web_scan(findings):
            return 'web_application_scanning'
        
        # Check if we need vulnerability scanning
        if not self._has_vuln_scan(findings):
            return 'vulnerability_scanning'
        
        # Check if we need deeper exploitation
        if self._has_vulnerabilities(findings):
            return 'exploit_research'
        
        return 'reporting'
    
    def _has_web_services(self, findings: Dict[str, Any]) -> bool:
        """Check if findings indicate web services."""
        if 'nmap' in findings:
            nmap_data = findings['nmap']
            if isinstance(nmap_data, str):
                return any(str(p) in nmap_data for p in [80, 443, 8080, 8443])
        return False
    
    def _has_web_scan(self, findings: Dict[str, Any]) -> bool:
        """Check if web scanning has been performed."""
        web_tools = ['whatweb', 'nikto', 'gobuster', 'dirsearch', 'ffuf']
        return any(tool in findings for tool in web_tools)
    
    def _has_vuln_scan(self, findings: Dict[str, Any]) -> bool:
        """Check if vulnerability scanning has been performed."""
        vuln_tools = ['nuclei', 'nikto', 'wpscan', 'sqlmap']
        return any(tool in findings for tool in vuln_tools)
    
    def _has_vulnerabilities(self, findings: Dict[str, Any]) -> bool:
        """Check if vulnerabilities were found."""
        # This would parse findings for vulnerability indicators
        return False
    
    def _estimate_duration(self, tools: List[Dict[str, Any]]) -> int:
        """Estimate total duration in seconds for recommended tools."""
        duration_map = {
            'nmap': 300,
            'amass': 1800,
            'sublist3r': 600,
            'theharvester': 300,
            'gobuster': 600,
            'dirsearch': 600,
            'ffuf': 600,
            'whatweb': 120,
            'nikto': 900,
            'sqlmap': 1800,
            'wpscan': 900,
            'nuclei': 1200,
            'searchsploit': 60
        }
        
        total = sum(duration_map.get(t['tool'], 300) for t in tools)
        return total
    
    def _check_parallel_possible(self, tools: List[Dict[str, Any]]) -> bool:
        """Check if tools can be run in parallel."""
        # Some tools might interfere with each other
        conflicting_pairs = [
            ('gobuster', 'ffuf'),  # Both are directory busters
            ('amass', 'sublist3r'),  # Both do subdomain enumeration
        ]
        
        tool_names = [t['tool'] for t in tools]
        
        for t1, t2 in conflicting_pairs:
            if t1 in tool_names and t2 in tool_names:
                return False
        
        return True
    
    def _summarize_findings(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of findings for strategy history."""
        summary = {
            'tools_executed': list(findings.keys()),
            'web_services_found': self._has_web_services(findings),
            'vulnerabilities_found': self._has_vulnerabilities(findings)
        }
        return summary
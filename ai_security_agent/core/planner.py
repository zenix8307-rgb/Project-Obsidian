"""Planning module for orchestrating security scans."""
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid
from .logger import LoggerMixin
from .task_manager import TaskManager, Task, TaskPriority
from .memory import MemorySystem
from .config import Config
from ..llm.llm_interface import LLMInterface
from ..llm.prompt_builder import PromptBuilder

class ScanPlanner(LoggerMixin):
    """Plans and orchestrates security scans based on target and strategy."""
    
    def __init__(self, task_manager: TaskManager, memory: MemorySystem):
        self.task_manager = task_manager
        self.memory = memory
        self.config = Config()
        self.llm = LLMInterface()
        self.prompt_builder = PromptBuilder()
        self.current_plan = None
    
    async def create_scan_plan(
        self,
        target: str,
        scan_type: str = "full",
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create a comprehensive scan plan for a target.
        
        Args:
            target: Target domain or IP
            scan_type: Type of scan (quick, full, targeted)
            options: Additional options for the scan
        
        Returns:
            Scan plan dictionary
        """
        options = options or {}
        
        # Create plan ID
        plan_id = str(uuid.uuid4())[:8]
        
        # Check memory for similar targets
        similar_targets = self.memory.find_similar_targets(target)
        if similar_targets:
            self.log_info(f"Found {len(similar_targets)} similar targets in memory")
        
        # Get target info from memory if available
        target_history = self.memory.get_target_history(target)
        
        # Build initial plan structure
        plan = {
            'id': plan_id,
            'target': target,
            'type': scan_type,
            'created_at': datetime.now().isoformat(),
            'phases': [],
            'options': options,
            'similar_targets': similar_targets,
            'target_history': target_history
        }
        
        # Define scan phases based on type
        if scan_type == "quick":
            phases = self._create_quick_scan_phases(target)
        elif scan_type == "targeted":
            phases = self._create_targeted_scan_phases(target, options)
        else:  # full
            phases = await self._create_full_scan_phases(target, target_history)
        
        plan['phases'] = phases
        
        # Use LLM to optimize plan if needed
        if options.get('optimize', True):
            plan = await self._optimize_plan_with_llm(plan)
        
        self.current_plan = plan
        self.log_info(f"Created scan plan {plan_id} for {target}")
        
        return plan
    
    def _create_quick_scan_phases(self, target: str) -> List[Dict[str, Any]]:
        """Create phases for a quick scan."""
        return [
            {
                'name': 'reconnaissance',
                'description': 'Initial reconnaissance and port scanning',
                'tasks': [
                    {
                        'name': 'nmap_quick',
                        'tool': 'nmap',
                        'params': ['-F', '-sV', '--open'],
                        'priority': TaskPriority.HIGH
                    }
                ]
            },
            {
                'name': 'service_identification',
                'description': 'Identify services on open ports',
                'dependencies': ['reconnaissance'],
                'tasks': [
                    {
                        'name': 'whatweb',
                        'tool': 'whatweb',
                        'condition': 'web_services_detected',
                        'priority': TaskPriority.MEDIUM
                    }
                ]
            }
        ]
    
    def _create_targeted_scan_phases(
        self,
        target: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Create phases for a targeted scan."""
        phases = []
        
        if options.get('web_scan'):
            phases.append({
                'name': 'web_scan',
                'description': 'Targeted web application scanning',
                'tasks': [
                    {
                        'name': 'nikto',
                        'tool': 'nikto',
                        'params': ['-ssl' if options.get('ssl') else ''],
                        'priority': TaskPriority.HIGH
                    },
                    {
                        'name': 'gobuster',
                        'tool': 'gobuster',
                        'params': ['-w', '/usr/share/wordlists/dirb/common.txt'],
                        'priority': TaskPriority.HIGH
                    }
                ]
            })
        
        if options.get('vuln_scan'):
            phases.append({
                'name': 'vulnerability_scan',
                'description': 'Targeted vulnerability scanning',
                'tasks': [
                    {
                        'name': 'nuclei',
                        'tool': 'nuclei',
                        'params': ['-severity', 'critical,high'],
                        'priority': TaskPriority.HIGH
                    }
                ]
            })
        
        return phases
    
    async def _create_full_scan_phases(
        self,
        target: str,
        target_history: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Create phases for a full comprehensive scan."""
        
        # Base phases for full scan
        phases = [
            {
                'name': 'initial_recon',
                'description': 'Initial reconnaissance and network mapping',
                'tasks': [
                    {
                        'name': 'nmap_full',
                        'tool': 'nmap',
                        'params': ['-sS', '-sV', '-sC', '-O', '-p-', '--min-rate=1000'],
                        'priority': TaskPriority.CRITICAL
                    },
                    {
                        'name': 'theharvester',
                        'tool': 'theharvester',
                        'params': ['-d', target, '-b', 'all'],
                        'priority': TaskPriority.MEDIUM
                    }
                ]
            },
            {
                'name': 'subdomain_enum',
                'description': 'Subdomain enumeration',
                'dependencies': ['initial_recon'],
                'tasks': [
                    {
                        'name': 'amass',
                        'tool': 'amass',
                        'params': ['enum', '-d', target],
                        'priority': TaskPriority.HIGH
                    },
                    {
                        'name': 'sublist3r',
                        'tool': 'sublist3r',
                        'params': ['-d', target],
                        'priority': TaskPriority.HIGH
                    }
                ]
            }
        ]
        
        # Check if we have previous scan data
        if target_history and target_history.get('scans'):
            last_scan = target_history['scans'][-1] if target_history['scans'] else None
            if last_scan:
                # Add differential scanning phase
                phases.append({
                    'name': 'differential_scan',
                    'description': 'Scan for changes since last scan',
                    'dependencies': ['initial_recon'],
                    'tasks': [
                        {
                            'name': 'nmap_diff',
                            'tool': 'nmap',
                            'params': ['--resume', last_scan.get('results', {}).get('nmap_output')],
                            'priority': TaskPriority.MEDIUM
                        }
                    ]
                })
        
        # Add web application phases (conditional on web services)
        phases.append({
            'name': 'web_app_scan',
            'description': 'Web application scanning',
            'dependencies': ['initial_recon'],
            'condition': 'web_services_detected',
            'tasks': [
                {
                    'name': 'whatweb',
                    'tool': 'whatweb',
                    'params': ['-a', '3'],
                    'priority': TaskPriority.HIGH
                },
                {
                    'name': 'nikto',
                    'tool': 'nikto',
                    'params': ['-h', target, '-C', 'all'],
                    'priority': TaskPriority.HIGH
                },
                {
                    'name': 'dirsearch',
                    'tool': 'dirsearch',
                    'params': ['-u', target, '-e', 'php,html,txt'],
                    'priority': TaskPriority.MEDIUM
                },
                {
                    'name': 'ffuf',
                    'tool': 'ffuf',
                    'params': ['-u', f"{target}/FUZZ", '-w', '/usr/share/wordlists/dirb/common.txt'],
                    'priority': TaskPriority.MEDIUM
                }
            ]
        })
        
        # Add WordPress specific phase
        phases.append({
            'name': 'wordpress_scan',
            'description': 'WordPress specific scanning',
            'dependencies': ['web_app_scan'],
            'condition': 'wordpress_detected',
            'tasks': [
                {
                    'name': 'wpscan',
                    'tool': 'wpscan',
                    'params': ['--url', target, '--enumerate', 'vp,ap,vt'],
                    'priority': TaskPriority.HIGH
                }
            ]
        })
        
        # Add vulnerability scanning phase
        phases.append({
            'name': 'vulnerability_scan',
            'description': 'Comprehensive vulnerability scanning',
            'dependencies': ['web_app_scan', 'subdomain_enum'],
            'tasks': [
                {
                    'name': 'nuclei',
                    'tool': 'nuclei',
                    'params': ['-t', 'cves/', '-t', 'vulnerabilities/', '-severity', 'critical,high,medium'],
                    'priority': TaskPriority.HIGH
                },
                {
                    'name': 'searchsploit',
                    'tool': 'searchsploit',
                    'params': ['--nmap', 'nmap_output.xml'],
                    'priority': TaskPriority.LOW
                }
            ]
        })
        
        # Add SQL injection testing phase
        phases.append({
            'name': 'sqli_testing',
            'description': 'SQL injection testing',
            'dependencies': ['web_app_scan'],
            'condition': 'parameters_detected',
            'tasks': [
                {
                    'name': 'sqlmap',
                    'tool': 'sqlmap',
                    'params': ['-u', f"{target}?param=1", '--batch', '--level=3', '--risk=2'],
                    'priority': TaskPriority.MEDIUM
                }
            ]
        })
        
        return phases
    
    async def _optimize_plan_with_llm(
        self,
        plan: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Use LLM to optimize the scan plan."""
        
        # Build prompt for plan optimization
        prompt = self.prompt_builder.build_planning_prompt(
            target=plan['target'],
            scan_type=plan['type'],
            phases=plan['phases'],
            similar_targets=plan.get('similar_targets', [])
        )
        
        # Get LLM suggestions
        suggestions = await self.llm.ask_async(prompt)
        
        # Parse suggestions and adjust plan
        # This is a simplified version - in production, you'd parse the LLM response
        if suggestions and 'reorder' in suggestions.lower():
            # Reorder phases based on suggestions
            pass
        
        return plan
    
    async def execute_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a scan plan.
        
        Args:
            plan: Scan plan dictionary
        
        Returns:
            Execution results
        """
        self.log_info(f"Executing plan {plan['id']} for {plan['target']}")
        
        results = {
            'plan_id': plan['id'],
            'target': plan['target'],
            'started_at': datetime.now().isoformat(),
            'phases': [],
            'status': 'in_progress'
        }
        
        # Track completed phases for dependencies
        completed_phases = set()
        
        for phase in plan['phases']:
            # Check dependencies
            deps = phase.get('dependencies', [])
            if deps and not all(dep in completed_phases for dep in deps):
                self.log_info(f"Skipping phase {phase['name']} - dependencies not met")
                continue
            
            # Check conditions
            condition = phase.get('condition')
            if condition and not await self._check_condition(condition, results):
                self.log_info(f"Skipping phase {phase['name']} - condition not met")
                continue
            
            self.log_info(f"Starting phase: {phase['name']}")
            
            phase_result = await self._execute_phase(phase, plan['target'])
            results['phases'].append(phase_result)
            
            if phase_result['status'] == 'completed':
                completed_phases.add(phase['name'])
        
        results['status'] = 'completed'
        results['completed_at'] = datetime.now().isoformat()
        
        # Store results in memory
        self.memory.store_scan_result(
            plan['target'],
            plan['type'],
            results
        )
        
        return results
    
    async def _execute_phase(
        self,
        phase: Dict[str, Any],
        target: str
    ) -> Dict[str, Any]:
        """Execute a single phase of the scan plan."""
        
        phase_result = {
            'name': phase['name'],
            'started_at': datetime.now().isoformat(),
            'tasks': [],
            'status': 'in_progress'
        }
        
        # Create tasks for this phase
        for task_config in phase['tasks']:
            task_id = self.task_manager.create_task(
                name=task_config['name'],
                func=self._create_task_function(task_config, target),
                priority=task_config.get('priority', TaskPriority.MEDIUM),
                timeout=3600
            )
            
            # Wait for task completion
            task = self.task_manager.get_task(task_id)
            while task and task.status in ['pending', 'running']:
                await asyncio.sleep(1)
                task = self.task_manager.get_task(task_id)
            
            if task:
                phase_result['tasks'].append({
                    'name': task_config['name'],
                    'status': task.status.value,
                    'result': task.result,
                    'error': task.error
                })
        
        phase_result['status'] = 'completed'
        phase_result['completed_at'] = datetime.now().isoformat()
        
        return phase_result
    
    def _create_task_function(self, task_config: Dict[str, Any], target: str):
        """Create a task function for execution."""
        from ..execution.tool_runner import ToolRunner
        
        async def task_func():
            runner = ToolRunner()
            return await runner.run_tool(
                tool_name=task_config['tool'],
                target=target,
                params=task_config.get('params', [])
            )
        
        return task_func
    
    async def _check_condition(
        self,
        condition: str,
        results: Dict[str, Any]
    ) -> bool:
        """Check if a condition is met."""
        
        if condition == 'web_services_detected':
            # Check if web services were found in initial recon
            for phase in results.get('phases', []):
                if phase['name'] == 'initial_recon':
                    for task in phase.get('tasks', []):
                        if task['name'] == 'nmap_full' and task.get('result'):
                            # Parse nmap results for web ports
                            result = task['result']
                            if isinstance(result, str):
                                if '80/tcp' in result or '443/tcp' in result:
                                    return True
            return False
        
        elif condition == 'wordpress_detected':
            # Check if WordPress was detected
            for phase in results.get('phases', []):
                if phase['name'] == 'web_app_scan':
                    for task in phase.get('tasks', []):
                        if task['name'] == 'whatweb' and task.get('result'):
                            if 'WordPress' in str(task['result']):
                                return True
            return False
        
        elif condition == 'parameters_detected':
            # Check if URL parameters were found
            # This would require parsing web scanner results
            return False
        
        return True
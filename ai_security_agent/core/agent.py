"""Main security agent implementation."""
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import json

from .logger import LoggerMixin, setup_logging
from .config import Config
from .memory import MemorySystem
from .task_manager import TaskManager
from .planner import ScanPlanner
from .strategy_engine import StrategyEngine
from ..llm.llm_interface import LLMInterface
from ..llm.analysis_engine import AnalysisEngine
from ..execution.tool_runner import ToolRunner
from ..reporting.report_builder import ReportBuilder

class SecurityAgent(LoggerMixin):
    """Main security agent that orchestrates all components."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the security agent.
        
        Args:
            config: Optional configuration object
        """
        self.config = config or Config()
        
        # Setup logging
        self.logger = setup_logging(
            log_level="INFO",
            log_file=self.config.logs_dir / "agent.log"
        )
        
        self.log_info("Initializing Security Agent")
        
        # Initialize components
        self.memory = MemorySystem()
        self.task_manager = TaskManager(max_concurrent=self.config.max_concurrent_tools)
        self.llm = LLMInterface()
        self.strategy_engine = StrategyEngine(self.llm)
        self.planner = ScanPlanner(self.task_manager, self.memory)
        self.analysis_engine = AnalysisEngine(self.llm)
        self.tool_runner = ToolRunner()
        self.report_builder = ReportBuilder()
        
        # State
        self.current_scan = None
        self.scan_results = {}
        self.is_running = False
        
        self.log_info("Security Agent initialized successfully")
    
    async def start(self):
        """Start the security agent."""
        self.log_info("Starting Security Agent")
        self.is_running = True
        await self.task_manager.start()
        self.log_info("Security Agent started")
    
    async def stop(self):
        """Stop the security agent."""
        self.log_info("Stopping Security Agent")
        self.is_running = False
        await self.task_manager.stop()
        self.log_info("Security Agent stopped")
    
    async def run_scan(
        self,
        target: str,
        scan_type: str = "full",
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run a security scan on a target.
        
        Args:
            target: Target domain or IP address
            scan_type: Type of scan (quick, full, targeted)
            options: Additional scan options
        
        Returns:
            Scan results dictionary
        """
        options = options or {}
        
        self.log_info(f"Starting {scan_type} scan on target: {target}")
        
        # Store target info in memory
        self.memory.store_target_info(target, {
            'scan_type': scan_type,
            'started_at': datetime.now().isoformat()
        })
        
        # Create scan plan
        plan = await self.planner.create_scan_plan(target, scan_type, options)
        
        # Execute plan
        results = await self.planner.execute_plan(plan)
        
        # Analyze results with LLM
        analysis = await self.analysis_engine.analyze_scan_results(results)
        
        # Combine results
        final_results = {
            'target': target,
            'scan_type': scan_type,
            'started_at': results['started_at'],
            'completed_at': datetime.now().isoformat(),
            'plan': plan,
            'execution': results,
            'analysis': analysis
        }
        
        # Store results
        self.scan_results[target] = final_results
        self.memory.store_scan_result(target, scan_type, final_results)
        
        # Generate report
        report_path = await self.generate_report(target)
        final_results['report_path'] = str(report_path)
        
        self.log_info(f"Scan completed for {target}")
        
        return final_results
    
    async def run_full_audit(self, target: str) -> Dict[str, Any]:
        """
        Run a comprehensive full audit on a target.
        
        This includes multiple scan phases with dynamic tool selection.
        
        Args:
            target: Target domain or IP
        
        Returns:
            Complete audit results
        """
        self.log_info(f"Starting full audit on target: {target}")
        
        audit_results = {
            'target': target,
            'started_at': datetime.now().isoformat(),
            'phases': []
        }
        
        # Phase 1: Initial reconnaissance
        self.log_info("Phase 1: Initial reconnaissance")
        recon_results = await self.run_scan(target, scan_type="quick")
        audit_results['phases'].append({
            'name': 'reconnaissance',
            'results': recon_results
        })
        
        # Analyze results and determine next steps
        findings = self._extract_findings(recon_results)
        
        # Phase 2: Targeted scanning based on findings
        self.log_info("Phase 2: Targeted scanning")
        next_tools = await self.strategy_engine.determine_next_tools(
            findings,
            set(),
            {'target': target}
        )
        
        if next_tools:
            tool_results = await self._run_tools_in_parallel(target, next_tools)
            audit_results['phases'].append({
                'name': 'targeted_scanning',
                'tools_used': next_tools,
                'results': tool_results
            })
        
        # Phase 3: Vulnerability analysis
        self.log_info("Phase 3: Vulnerability analysis")
        analysis = await self.analysis_engine.analyze_scan_results(audit_results)
        audit_results['analysis'] = analysis
        
        # Phase 4: Reporting
        self.log_info("Phase 4: Report generation")
        report_path = await self.generate_report(target, audit_results)
        audit_results['report_path'] = str(report_path)
        
        audit_results['completed_at'] = datetime.now().isoformat()
        
        self.log_info(f"Full audit completed for {target}")
        
        return audit_results
    
    async def _run_tools_in_parallel(
        self,
        target: str,
        tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Run multiple tools in parallel where possible."""
        results = {}
        
        # Group tools by parallelism capability
        parallel_tools = []
        sequential_tools = []
        
        for tool in tools:
            if self._can_run_parallel(tool['tool']):
                parallel_tools.append(tool)
            else:
                sequential_tools.append(tool)
        
        # Run parallel tools
        if parallel_tools:
            tasks = []
            for tool in parallel_tools:
                task = self.tool_runner.run_tool(
                    tool_name=tool['tool'],
                    target=target,
                    params=tool.get('params', [])
                )
                tasks.append(task)
            
            parallel_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for tool, result in zip(parallel_tools, parallel_results):
                if isinstance(result, Exception):
                    results[tool['tool']] = {'error': str(result)}
                else:
                    results[tool['tool']] = result
        
        # Run sequential tools
        for tool in sequential_tools:
            result = await self.tool_runner.run_tool(
                tool_name=tool['tool'],
                target=target,
                params=tool.get('params', [])
            )
            results[tool['tool']] = result
        
        return results
    
    def _can_run_parallel(self, tool_name: str) -> bool:
        """Check if a tool can be run in parallel with others."""
        # Tools that shouldn't run in parallel
        sequential_tools = ['sqlmap', 'nikto', 'wpscan']  # Resource intensive
        return tool_name not in sequential_tools
    
    def _extract_findings(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract structured findings from scan results."""
        findings = {}
        
        # Extract from execution phases
        if 'execution' in scan_results:
            for phase in scan_results['execution'].get('phases', []):
                for task in phase.get('tasks', []):
                    if task['status'] == 'completed' and task.get('result'):
                        findings[task['name']] = task['result']
        
        return findings
    
    async def generate_report(
        self,
        target: str,
        results: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Generate a professional security report.
        
        Args:
            target: Target domain or IP
            results: Optional scan results (uses stored results if not provided)
        
        Returns:
            Path to generated report
        """
        if results is None:
            results = self.scan_results.get(target)
        
        if not results:
            raise ValueError(f"No results found for target: {target}")
        
        self.log_info(f"Generating report for {target}")
        
        # Build report
        report = await self.report_builder.build_report(results)
        
        # Save report
        report_path = self.config.reports_dir / f"{target}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_path, 'w') as f:
            f.write(report)
        
        self.log_info(f"Report saved to {report_path}")
        
        return report_path
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            'is_running': self.is_running,
            'task_manager_status': self.task_manager.get_status(),
            'current_scan': self.current_scan,
            'scans_completed': len(self.scan_results),
            'memory_stats': {
                'targets': len(self.memory.memory.get('targets', {})),
                'scans': len(self.memory.memory.get('scans', {}))
            }
        }
    
    def get_scan_history(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get scan history for a target or all targets."""
        if target:
            history = self.memory.get_target_history(target)
            return [history]
        else:
            # Return history for all targets
            histories = []
            for target_key, target_data in self.memory.memory.get('targets', {}).items():
                histories.append({
                    'target': target_data['target'],
                    'first_seen': target_data.get('first_seen'),
                    'last_seen': target_data.get('last_seen'),
                    'scan_count': len(target_data.get('scans', []))
                })
            return histories
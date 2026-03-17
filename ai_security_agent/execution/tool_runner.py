"""Tool runner for executing security tools."""
import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
from datetime import datetime

from ..core.logger import LoggerMixin
from ..core.config import Config
from .command_executor import CommandExecutor
from ..tools import (
    nmap_scan, amass_scan, sublist3r_scan, harvester_scan,
    gobuster_scan, dirsearch_scan, ffuf_scan, whatweb_scan,
    nikto_scan, sqlmap_scan, wpscan_scan, nuclei_scan,
    searchsploit_lookup
)

class ToolRunner(LoggerMixin):
    """Runs security tools and manages their execution."""
    
    def __init__(self):
        self.config = Config()
        self.executor = CommandExecutor()
        self.tool_modules = self._load_tool_modules()
        self.running_tools = {}
    
    def _load_tool_modules(self) -> Dict[str, Any]:
        """Load all tool modules."""
        return {
            'nmap': nmap_scan,
            'amass': amass_scan,
            'sublist3r': sublist3r_scan,
            'theharvester': harvester_scan,
            'gobuster': gobuster_scan,
            'dirsearch': dirsearch_scan,
            'ffuf': ffuf_scan,
            'whatweb': whatweb_scan,
            'nikto': nikto_scan,
            'sqlmap': sqlmap_scan,
            'wpscan': wpscan_scan,
            'nuclei': nuclei_scan,
            'searchsploit': searchsploit_lookup
        }
    
    async def run_tool(
        self,
        tool_name: str,
        target: str,
        params: Optional[List[str]] = None,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Run a security tool.
        
        Args:
            tool_name: Name of the tool to run
            target: Target domain or IP
            params: Additional parameters for the tool
            timeout: Timeout in seconds
        
        Returns:
            Tool execution results
        """
        params = params or []
        timeout = timeout or self.config.tool_timeout
        
        self.log_info(f"Running tool: {tool_name} against {target}")
        
        # Generate output filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.config.scans_dir / f"{tool_name}_{target}_{timestamp}.txt"
        
        # Check if tool module exists
        if tool_name in self.tool_modules:
            module = self.tool_modules[tool_name]
            try:
                # Use tool's module function
                result = await module.scan(
                    target=target,
                    executor=self.executor,
                    output_file=output_file,
                    params=params
                )
                
                # Save output
                with open(output_file, 'w') as f:
                    if isinstance(result, dict):
                        json.dump(result, f, indent=2)
                    else:
                        f.write(str(result))
                
                self.log_info(f"Tool {tool_name} completed, output saved to {output_file}")
                
                return {
                    'tool': tool_name,
                    'target': target,
                    'output_file': str(output_file),
                    'results': result,
                    'status': 'success'
                }
                
            except Exception as e:
                self.log_error(f"Tool {tool_name} failed: {e}")
                return {
                    'tool': tool_name,
                    'target': target,
                    'error': str(e),
                    'status': 'failed'
                }
        else:
            # Fallback to generic command execution
            return await self._run_generic_tool(tool_name, target, params, output_file, timeout)
    
    async def _run_generic_tool(
        self,
        tool_name: str,
        target: str,
        params: List[str],
        output_file: Path,
        timeout: int
    ) -> Dict[str, Any]:
        """Run a tool using generic command execution."""
        
        # Build command
        command = [tool_name]
        command.extend(params)
        
        # Add target if not already in params
        if target not in command:
            command.append(target)
        
        # Execute
        returncode, stdout, stderr = await self.executor.execute(
            command,
            timeout=timeout
        )
        
        # Save output
        with open(output_file, 'w') as f:
            f.write(f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}")
        
        if returncode == 0:
            return {
                'tool': tool_name,
                'target': target,
                'output_file': str(output_file),
                'stdout': stdout,
                'stderr': stderr,
                'status': 'success'
            }
        else:
            return {
                'tool': tool_name,
                'target': target,
                'output_file': str(output_file),
                'error': stderr,
                'status': 'failed',
                'returncode': returncode
            }
    
    async def run_tools_parallel(
        self,
        tools: List[Dict[str, Any]],
        target: str
    ) -> Dict[str, Any]:
        """Run multiple tools in parallel."""
        tasks = []
        
        for tool_config in tools:
            tool_name = tool_config['tool']
            params = tool_config.get('params', [])
            
            task = self.run_tool(tool_name, target, params)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        tool_results = {}
        for tool_config, result in zip(tools, results):
            tool_name = tool_config['tool']
            
            if isinstance(result, Exception):
                tool_results[tool_name] = {
                    'error': str(result),
                    'status': 'failed'
                }
            else:
                tool_results[tool_name] = result
        
        return tool_results
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available on the system."""
        import shutil
        
        # Check if tool module exists
        if tool_name in self.tool_modules:
            return True
        
        # Check if executable exists in PATH
        return shutil.which(tool_name) is not None
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools."""
        available = []
        
        for tool_name in self.tool_modules.keys():
            if self.is_tool_available(tool_name):
                available.append(tool_name)
        
        return available
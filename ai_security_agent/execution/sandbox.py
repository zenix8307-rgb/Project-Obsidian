"""Sandbox environment for safe tool execution."""
import os
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Any
import resource
import subprocess

from ..core.logger import LoggerMixin
from ..core.config import Config

class Sandbox(LoggerMixin):
    """Sandbox environment for executing tools in isolation."""
    
    def __init__(self, sandbox_dir: Optional[Path] = None):
        self.config = Config()
        self.sandbox_dir = sandbox_dir or (self.config.data_dir / 'sandbox')
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.active_sandboxes = {}
    
    def create_sandbox(self, name: str) -> Path:
        """
        Create a new sandbox environment.
        
        Args:
            name: Name of the sandbox
        
        Returns:
            Path to the sandbox directory
        """
        sandbox_path = self.sandbox_dir / name
        sandbox_path.mkdir(parents=True, exist_ok=True)
        
        # Create standard directories
        (sandbox_path / 'input').mkdir(exist_ok=True)
        (sandbox_path / 'output').mkdir(exist_ok=True)
        (sandbox_path / 'temp').mkdir(exist_ok=True)
        (sandbox_path / 'logs').mkdir(exist_ok=True)
        
        self.active_sandboxes[name] = {
            'path': sandbox_path,
            'created_at': None,  # Would use datetime in production
            'resources': {}
        }
        
        self.log_info(f"Created sandbox: {name} at {sandbox_path}")
        return sandbox_path
    
    def destroy_sandbox(self, name: str):
        """Destroy a sandbox environment."""
        if name in self.active_sandboxes:
            sandbox_path = self.active_sandboxes[name]['path']
            try:
                shutil.rmtree(sandbox_path)
                del self.active_sandboxes[name]
                self.log_info(f"Destroyed sandbox: {name}")
            except Exception as e:
                self.log_error(f"Failed to destroy sandbox {name}: {e}")
    
    def execute_in_sandbox(
        self,
        sandbox_name: str,
        command: List[str],
        timeout: int = 300,
        memory_limit: Optional[int] = None,
        cpu_limit: Optional[int] = None
    ) -> subprocess.CompletedProcess:
        """
        Execute a command within a sandbox with resource limits.
        
        Args:
            sandbox_name: Name of the sandbox
            command: Command to execute
            timeout: Timeout in seconds
            memory_limit: Memory limit in MB
            cpu_limit: CPU time limit in seconds
        
        Returns:
            CompletedProcess result
        """
        if sandbox_name not in self.active_sandboxes:
            raise ValueError(f"Sandbox {sandbox_name} not found")
        
        sandbox_path = self.active_sandboxes[sandbox_name]['path']
        
        # Set resource limits
        def set_limits():
            if memory_limit:
                # Convert MB to bytes
                memory_bytes = memory_limit * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            
            if cpu_limit:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
        
        try:
            result = subprocess.run(
                command,
                cwd=sandbox_path / 'temp',
                timeout=timeout,
                check=False,
                capture_output=True,
                text=True,
                preexec_fn=set_limits
            )
            
            # Save output
            with open(sandbox_path / 'logs' / 'command_output.log', 'w') as f:
                f.write(f"Command: {' '.join(command)}\n")
                f.write(f"Return code: {result.returncode}\n")
                f.write(f"STDOUT:\n{result.stdout}\n")
                f.write(f"STDERR:\n{result.stderr}\n")
            
            return result
            
        except subprocess.TimeoutExpired:
            self.log_error(f"Command timed out in sandbox {sandbox_name}")
            raise
        except Exception as e:
            self.log_error(f"Command failed in sandbox {sandbox_name}: {e}")
            raise
    
    def copy_to_sandbox(self, sandbox_name: str, source_path: Path, dest_name: Optional[str] = None):
        """Copy a file into the sandbox."""
        if sandbox_name not in self.active_sandboxes:
            raise ValueError(f"Sandbox {sandbox_name} not found")
        
        sandbox_path = self.active_sandboxes[sandbox_name]['path']
        dest = sandbox_path / 'input' / (dest_name or source_path.name)
        
        shutil.copy2(source_path, dest)
        self.log_debug(f"Copied {source_path} to {dest}")
        
        return dest
    
    def copy_from_sandbox(self, sandbox_name: str, file_name: str, dest_path: Path):
        """Copy a file from the sandbox."""
        if sandbox_name not in self.active_sandboxes:
            raise ValueError(f"Sandbox {sandbox_name} not found")
        
        sandbox_path = self.active_sandboxes[sandbox_name]['path']
        source = sandbox_path / 'output' / file_name
        
        if source.exists():
            shutil.copy2(source, dest_path)
            self.log_debug(f"Copied {source} to {dest_path}")
            return True
        
        return False
    
    def get_sandbox_status(self, sandbox_name: str) -> Dict[str, Any]:
        """Get status of a sandbox."""
        if sandbox_name not in self.active_sandboxes:
            return {'error': 'Sandbox not found'}
        
        sandbox = self.active_sandboxes[sandbox_name]
        path = sandbox['path']
        
        # Calculate size
        total_size = 0
        for item in path.rglob('*'):
            if item.is_file():
                total_size += item.stat().st_size
        
        return {
            'name': sandbox_name,
            'path': str(path),
            'created_at': sandbox['created_at'],
            'size_bytes': total_size,
            'files': len(list(path.rglob('*'))),
            'active': True
        }
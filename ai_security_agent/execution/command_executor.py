"""Command execution module with security controls."""
import subprocess
import shlex
import asyncio
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path
import signal
import os

from ..core.logger import LoggerMixin
from ..core.config import Config

class CommandExecutor(LoggerMixin):
    """Secure command execution with timeout and output capture."""
    
    def __init__(self):
        self.config = Config()
        self.allowed_commands = self._get_allowed_commands()
        self.blocked_commands = self._get_blocked_commands()
    
    def _get_allowed_commands(self) -> List[str]:
        """Get list of allowed security tools."""
        return [
            'nmap', 'amass', 'sublist3r', 'theharvester',
            'gobuster', 'dirsearch', 'ffuf', 'whatweb',
            'nikto', 'sqlmap', 'wpscan', 'nuclei', 'searchsploit',
            'curl', 'wget', 'dig', 'nslookup', 'host'
        ]
    
    def _get_blocked_commands(self) -> List[str]:
        """Get list of blocked/dangerous commands."""
        return [
            'rm', 'dd', 'mkfs', 'format', 'del', 'rd',
            'shutdown', 'reboot', 'init', 'kill', 'pkill'
        ]
    
    def validate_command(self, command: List[str]) -> bool:
        """
        Validate that a command is safe to execute.
        
        Args:
            command: Command as list of arguments
        
        Returns:
            True if command is safe, False otherwise
        """
        if not command:
            return False
        
        cmd_name = Path(command[0]).name
        
        # Check if command is explicitly blocked
        if cmd_name in self.blocked_commands:
            self.log_warning(f"Blocked command: {cmd_name}")
            return False
        
        # Check if command is in allowed list (for base tools)
        if cmd_name in self.allowed_commands:
            return True
        
        # Check for dangerous patterns in arguments
        dangerous_patterns = [';', '&&', '||', '|', '`', '$(']
        for arg in command:
            for pattern in dangerous_patterns:
                if pattern in arg:
                    self.log_warning(f"Dangerous pattern in command: {pattern}")
                    return False
        
        # Allow other commands but log them
        self.log_info(f"Executing non-standard command: {cmd_name}")
        return True
    
    async def execute(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None
    ) -> Tuple[int, str, str]:
        """
        Execute a command asynchronously.
        
        Args:
            command: Command as list of arguments
            timeout: Timeout in seconds
            cwd: Working directory
            env: Environment variables
        
        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        if not self.validate_command(command):
            raise ValueError(f"Command validation failed: {command}")
        
        timeout = timeout or self.config.tool_timeout
        
        self.log_debug(f"Executing: {' '.join(command)}")
        
        try:
            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                preexec_fn=os.setsid  # Create new process group
            )
            
            try:
                # Wait with timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                stdout_str = stdout.decode('utf-8', errors='ignore')
                stderr_str = stderr.decode('utf-8', errors='ignore')
                
                self.log_debug(f"Command completed with return code: {process.returncode}")
                return process.returncode, stdout_str, stderr_str
                
            except asyncio.TimeoutError:
                # Kill the entire process group
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    await asyncio.sleep(1)
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except:
                    pass
                
                self.log_warning(f"Command timed out after {timeout}s: {' '.join(command)}")
                return -1, "", f"Timeout after {timeout} seconds"
                
        except Exception as e:
            self.log_error(f"Command execution failed: {e}")
            return -1, "", str(e)
    
    def execute_sync(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None
    ) -> Tuple[int, str, str]:
        """
        Execute a command synchronously.
        
        Args:
            command: Command as list of arguments
            timeout: Timeout in seconds
            cwd: Working directory
        
        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        if not self.validate_command(command):
            raise ValueError(f"Command validation failed: {command}")
        
        timeout = timeout or self.config.tool_timeout
        
        self.log_debug(f"Executing sync: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                check=False
            )
            
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            self.log_warning(f"Command timed out after {timeout}s: {' '.join(command)}")
            return -1, "", f"Timeout after {timeout} seconds"
        except Exception as e:
            self.log_error(f"Command execution failed: {e}")
            return -1, "", str(e)
    
    async def execute_piped(
        self,
        commands: List[List[str]],
        timeout: Optional[int] = None
    ) -> Tuple[int, str, str]:
        """
        Execute piped commands.
        
        Args:
            commands: List of commands, each as list of arguments
            timeout: Total timeout in seconds
        
        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        if not commands:
            return -1, "", "No commands provided"
        
        # Validate all commands
        for cmd in commands:
            if not self.validate_command(cmd):
                raise ValueError(f"Command validation failed: {cmd}")
        
        # Build pipeline
        processes = []
        prev_stdout = None
        
        try:
            for i, cmd in enumerate(commands):
                if i == 0:
                    # First command
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                elif i == len(commands) - 1:
                    # Last command
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdin=prev_stdout,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                else:
                    # Middle command
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdin=prev_stdout,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                
                processes.append(process)
                prev_stdout = process.stdout
            
            # Wait for last process
            if processes:
                last_process = processes[-1]
                try:
                    stdout, stderr = await asyncio.wait_for(
                        last_process.communicate(),
                        timeout=timeout
                    )
                    
                    stdout_str = stdout.decode('utf-8', errors='ignore')
                    stderr_str = stderr.decode('utf-8', errors='ignore')
                    
                    return last_process.returncode, stdout_str, stderr_str
                    
                except asyncio.TimeoutError:
                    # Kill all processes
                    for p in processes:
                        try:
                            p.terminate()
                        except:
                            pass
                    
                    return -1, "", f"Pipeline timeout after {timeout} seconds"
            
            return -1, "", "No processes created"
            
        except Exception as e:
            self.log_error(f"Pipeline execution failed: {e}")
            return -1, "", str(e)